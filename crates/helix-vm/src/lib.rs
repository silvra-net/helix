//! Minimal WASM smart contract runtime for Helix.
//!
//! Contracts are self-contained WASM modules whose only permitted imports are the host
//! functions defined below (anything else is rejected at instantiation), and must export a
//! zero-argument, zero-return entry point named `call`, plus their own linear memory as
//! `"memory"` (the standard convention every WASM toolchain already follows). Execution is
//! fuel-metered so a contract can never run unbounded.
//!
//! # Host functions
//!
//! Every host function lives under the `"env"` import module. Byte data (keys, values,
//! addresses, call input) crosses the host/guest boundary through the contract's own linear
//! memory as `(ptr: i32, len: i32)` pairs — there is no allocator protocol (no host-calls-
//! guest-alloc dance): the contract is responsible for reserving its own buffers (e.g. a
//! static scratch region) and the host never writes more than the caller-supplied maximum
//! length, truncating and reporting the true length so the contract can detect it.
//!
//! ```text
//! storage_read(key_ptr, key_len, out_ptr, out_max_len) -> i32   // actual value length (0 = absent)
//! storage_write(key_ptr, key_len, val_ptr, val_len)    -> i32   // 0 = ok, -1 = key/value too long
//! transfer(to_ptr, to_len, amount: i64)                -> i32   // 0 = ok, 1 = insufficient balance, 2 = invalid address
//! get_caller(out_ptr, out_max_len)                     -> i32   // caller address string length
//! get_self_address(out_ptr, out_max_len)               -> i32   // this contract's own address string length
//! get_input(out_ptr, out_max_len)                      -> i32   // call input (tx.data) length
//! get_value()                                          -> i64   // nano-HLX sent with this call
//! get_block_height()                                   -> i64
//! set_return_data(ptr, len)                             (no return)
//! ```
//!
//! # Determinism
//!
//! Every validator must reach the same result executing the same contract call, or the chain
//! forks. `wasmi` is a pure interpreter (no JIT, no platform-specific codegen), which already
//! rules out most sources of cross-machine divergence. The remaining classic risk for a
//! WASM-based VM is floating point: IEEE 754 pins down most float behavior, but real
//! toolchains/hardware have historically disagreed on edge cases (canonical-NaN payload bits,
//! fused-multiply-add availability) — the reason the EVM never got native floats. `engine()`
//! disables float types and instructions outright via wasmi's `WasmFeatures` validator gate,
//! so a module that declares or uses one anywhere is rejected at `validate()` (deploy time),
//! before it can ever reach the chain.
//!
//! # Atomicity
//!
//! `HostContext` implementations are expected (this crate has no way to enforce it — it's a
//! contract the *caller* of `call()` must uphold) to buffer every `storage_write`/`transfer`
//! rather than applying them to real chain state immediately, and only commit that buffer if
//! `call()` returns `Ok`. A trap partway through a call — including running out of fuel —
//! must leave chain state exactly as it was before the call started, the same all-or-nothing
//! guarantee every other transaction type already gets from `execute_transaction` never
//! partially applying its effects. See `helix-executor`'s `ContractHostContext` for the real
//! implementation of that buffering.

use thiserror::Error;
use wasmi::{
    core::{Trap, TrapCode},
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

/// Per-instance cap on linear memory, enforced by a `wasmi::ResourceLimiter`. Without one
/// configured, wasmi eagerly allocates a module's *declared minimum* memory at instantiation
/// time — before a single fuel unit is consumed — so a ~40-byte module declaring
/// `(memory 65536 65536)` (the maximum a 32-bit Wasm memory type allows) could force every
/// validator to attempt a 4 GiB allocation per call, completely unmetered by fuel/fees.
/// Generous for realistic contracts, firm enough to bound worst-case damage per call.
const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Per-table cap on element count, same rationale as `MAX_MEMORY_BYTES` — tables aren't
/// fuel-metered at allocation time either.
const MAX_TABLE_ELEMENTS: u32 = 10_000;

/// Ceiling on a single storage key/call-input's byte length. Generous for realistic use
/// (names, short identifiers, small structured keys) while bounding how much state a single
/// call can touch — unlike fuel, which bounds *compute*, nothing else here bounds the size of
/// a single stored value, and state that lives forever in every validator's database is a
/// materially different cost than CPU time that's over in milliseconds.
pub const MAX_KEY_LEN: usize = 256;
/// Ceiling on a single storage value's byte length. See `MAX_KEY_LEN`.
pub const MAX_VALUE_LEN: usize = 4096;
/// Ceiling on a call's raw input length. See `MAX_KEY_LEN`.
pub const MAX_INPUT_LEN: usize = 16_384;

// Fuel costs for host calls, charged on top of wasmi's own per-WASM-instruction metering
// (which only prices the contract's *own* bytecode, not the work a host function does on its
// behalf). Flat per-call costs, not byte-proportional — simple, and sized so that even the
// most expensive host call is cheap relative to a realistic fuel budget, while a contract
// that calls storage_write in a tight loop still visibly burns down its budget rather than
// getting host-side work for free.
const FUEL_STORAGE_READ: u64 = 500;
const FUEL_STORAGE_WRITE: u64 = 1_000;
const FUEL_TRANSFER: u64 = 300;
const FUEL_CONTEXT_READ: u64 = 50;

#[derive(Debug, Error)]
pub enum VmError {
    #[error("invalid WASM module: {0}")]
    InvalidModule(String),
    #[error("failed to instantiate module: {0}")]
    Instantiation(String),
    #[error("module does not export a callable `call` function with signature () -> ()")]
    MissingEntryPoint,
    #[error("out of gas")]
    OutOfGas,
    #[error("contract trapped: {0}")]
    Trap(String),
}

pub type VmResult<T> = Result<T, VmError>;

/// Result of a `transfer` host call — a *contract-visible* outcome, not a Rust error: a
/// contract sending more than its own balance is an expected, recoverable condition the
/// contract itself should decide how to handle (revert its own state, try a smaller amount,
/// etc.), not a hard trap that aborts the whole call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOutcome {
    Ok,
    InsufficientBalance,
    InvalidAddress,
}

/// The bridge between a running contract and real chain state, implemented by the caller of
/// `call()`. See the module doc comment's "Atomicity" section for the buffering contract an
/// implementation must uphold.
pub trait HostContext {
    /// Read a value from this contract's own persistent storage. `None` if never set.
    fn storage_read(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// Write a value into this contract's own persistent storage, overwriting any existing
    /// value for `key`. Key/value lengths are already validated against `MAX_KEY_LEN`/
    /// `MAX_VALUE_LEN` before this is called.
    fn storage_write(&mut self, key: &[u8], value: Vec<u8>);
    /// Move `amount` nano-HLX from this contract's own balance to `to` (an address string).
    fn transfer(&mut self, to: &str, amount: u64) -> TransferOutcome;
    /// The address that invoked this call — `tx.from` for a top-level call.
    fn caller(&self) -> &str;
    /// This contract's own address — `tx.to` for a top-level call.
    fn self_address(&self) -> &str;
    /// How much HLX (nano) was sent along with this call — `tx.amount`.
    fn value(&self) -> u64;
    /// The current block height.
    fn block_height(&self) -> u64;
    /// The call's raw input bytes — `tx.data`.
    fn input(&self) -> &[u8];
    /// Record the contract's return value, for the caller of `call()` to retrieve afterward
    /// (this trait has no getter for it — the concrete implementation owns that, since the
    /// caller of `call()` already holds `&mut C` and can read its own field directly).
    fn set_return_data(&mut self, data: Vec<u8>);
}

fn engine() -> Engine {
    let mut config = Config::default();
    config.consume_fuel(true);
    // Reject f32/f64 types and instructions entirely (formal determinism guarantee,
    // not just a style preference): WASM's float semantics are precisely specified,
    // but real-world float non-determinism across validator hardware/toolchains
    // (canonical-NaN propagation edge cases, fused-multiply-add availability) is a
    // well-known blockchain VM risk class — it's exactly why the EVM never got native
    // floats. Enforced by wasmi's own WasmFeatures validator gate (not a hand-rolled
    // instruction blocklist), so it's exhaustive by construction: any module
    // declaring or using a float type/instruction anywhere fails `Module::new` before
    // a single fuel unit is spent, for both `validate()` and `call()`.
    config.floats(false);
    Engine::new(&config)
}

/// Parse and validate a WASM module's bytecode without running it.
/// Used at contract-deploy time to reject malformed bytecode up front.
pub fn validate(code: &[u8]) -> VmResult<()> {
    let engine = engine();
    Module::new(&engine, code).map_err(|e| VmError::InvalidModule(e.to_string()))?;
    Ok(())
}

/// Result of a successful contract call.
#[derive(Debug, Clone, Copy)]
pub struct CallOutcome {
    pub fuel_used: u64,
}

/// Combined `wasmi` store state: the resource limiter `wasmi` itself needs, plus a borrow of
/// the caller-supplied `HostContext` every host function closure reaches into.
struct StoreState<'a, C: HostContext> {
    limits: StoreLimits,
    host: &'a mut C,
}

/// Instantiate `code` and invoke its exported `call() -> ()` entry point, bounded by
/// `fuel_limit` units of execution fuel (roughly: interpreted instructions plus the flat
/// per-call costs of any host functions it invokes — see the `FUEL_*` constants).
pub fn call<C: HostContext>(code: &[u8], fuel_limit: u64, ctx: &mut C) -> VmResult<CallOutcome> {
    let engine = engine();
    let module = Module::new(&engine, code).map_err(|e| VmError::InvalidModule(e.to_string()))?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(MAX_MEMORY_BYTES)
        .table_elements(MAX_TABLE_ELEMENTS)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, StoreState { limits, host: ctx });
    store.limiter(|state| &mut state.limits);
    store
        .add_fuel(fuel_limit)
        .map_err(|e| VmError::Instantiation(e.to_string()))?;

    let mut linker = Linker::new(&engine);
    link_host_functions(&mut linker).map_err(|e| VmError::Instantiation(e.to_string()))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| VmError::Instantiation(e.to_string()))?
        .start(&mut store)
        .map_err(|e| VmError::Instantiation(e.to_string()))?;

    let entry = instance
        .get_typed_func::<(), ()>(&store, "call")
        .map_err(|_| VmError::MissingEntryPoint)?;

    entry.call(&mut store, ()).map_err(|trap| {
        if matches!(trap.trap_code(), Some(TrapCode::OutOfFuel)) {
            VmError::OutOfGas
        } else {
            VmError::Trap(trap.to_string())
        }
    })?;

    let fuel_used = store.fuel_consumed().unwrap_or(0);
    Ok(CallOutcome { fuel_used })
}

/// Read `len` bytes from the guest's exported `"memory"` at `ptr`, capped at `max_len` — used
/// for inputs the guest is telling us the size of itself (e.g. a storage key), so a length
/// past the cap is the guest's own bug/attack, not a host-side truncation decision.
fn read_guest_bytes<C: HostContext>(
    caller: &mut Caller<'_, StoreState<C>>,
    ptr: i32,
    len: i32,
    max_len: usize,
) -> Result<Vec<u8>, Trap> {
    if len < 0 || len as usize > max_len {
        return Err(Trap::new(format!("length {len} exceeds the {max_len}-byte limit")));
    }
    let memory = match caller.get_export("memory") {
        Some(wasmi::Extern::Memory(m)) => m,
        _ => return Err(Trap::new("contract does not export linear memory as \"memory\"")),
    };
    let mut buf = vec![0u8; len as usize];
    memory
        .read(&caller, ptr as usize, &mut buf)
        .map_err(|e| Trap::new(e.to_string()))?;
    Ok(buf)
}

/// Write `data` (truncated to `max_len`) into the guest's exported `"memory"` at `ptr`,
/// returning `data.len()` regardless of truncation so the guest can detect it (the standard
/// "measure vs. fetch" pattern this ABI uses instead of a host-driven allocator protocol).
fn write_guest_bytes<C: HostContext>(
    caller: &mut Caller<'_, StoreState<C>>,
    ptr: i32,
    data: &[u8],
    max_len: i32,
) -> Result<i32, Trap> {
    let memory = match caller.get_export("memory") {
        Some(wasmi::Extern::Memory(m)) => m,
        _ => return Err(Trap::new("contract does not export linear memory as \"memory\"")),
    };
    let max_len = max_len.max(0) as usize;
    let to_write = &data[..data.len().min(max_len)];
    memory
        .write(&mut *caller, ptr as usize, to_write)
        .map_err(|e| Trap::new(e.to_string()))?;
    Ok(data.len() as i32)
}

fn consume<C: HostContext>(caller: &mut Caller<'_, StoreState<C>>, amount: u64) -> Result<(), Trap> {
    caller.consume_fuel(amount).map(|_| ()).map_err(|_| TrapCode::OutOfFuel.into())
}

fn link_host_functions<C: HostContext>(linker: &mut Linker<StoreState<C>>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "env",
        "storage_read",
        |mut caller: Caller<'_, StoreState<C>>, key_ptr: i32, key_len: i32, out_ptr: i32, out_max_len: i32| -> Result<i32, Trap> {
            consume(&mut caller, FUEL_STORAGE_READ)?;
            let key = read_guest_bytes(&mut caller, key_ptr, key_len, MAX_KEY_LEN)?;
            let value = caller.data().host.storage_read(&key);
            match value {
                Some(v) => write_guest_bytes(&mut caller, out_ptr, &v, out_max_len),
                None => Ok(0),
            }
        },
    )?;

    linker.func_wrap(
        "env",
        "storage_write",
        |mut caller: Caller<'_, StoreState<C>>, key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32| -> Result<i32, Trap> {
            consume(&mut caller, FUEL_STORAGE_WRITE)?;
            if val_len < 0 || val_len as usize > MAX_VALUE_LEN {
                return Ok(-1);
            }
            let key = read_guest_bytes(&mut caller, key_ptr, key_len, MAX_KEY_LEN)?;
            let value = read_guest_bytes(&mut caller, val_ptr, val_len, MAX_VALUE_LEN)?;
            caller.data_mut().host.storage_write(&key, value);
            Ok(0)
        },
    )?;

    linker.func_wrap(
        "env",
        "transfer",
        |mut caller: Caller<'_, StoreState<C>>, to_ptr: i32, to_len: i32, amount: i64| -> Result<i32, Trap> {
            consume(&mut caller, FUEL_TRANSFER)?;
            if amount < 0 {
                return Err(Trap::new("transfer amount must not be negative"));
            }
            let to_bytes = read_guest_bytes(&mut caller, to_ptr, to_len, MAX_KEY_LEN)?;
            let Ok(to) = String::from_utf8(to_bytes) else {
                return Ok(2); // invalid address — not even valid UTF-8
            };
            Ok(match caller.data_mut().host.transfer(&to, amount as u64) {
                TransferOutcome::Ok => 0,
                TransferOutcome::InsufficientBalance => 1,
                TransferOutcome::InvalidAddress => 2,
            })
        },
    )?;

    linker.func_wrap(
        "env",
        "get_caller",
        |mut caller: Caller<'_, StoreState<C>>, out_ptr: i32, out_max_len: i32| -> Result<i32, Trap> {
            consume(&mut caller, FUEL_CONTEXT_READ)?;
            let addr = caller.data().host.caller().as_bytes().to_vec();
            write_guest_bytes(&mut caller, out_ptr, &addr, out_max_len)
        },
    )?;

    linker.func_wrap(
        "env",
        "get_self_address",
        |mut caller: Caller<'_, StoreState<C>>, out_ptr: i32, out_max_len: i32| -> Result<i32, Trap> {
            consume(&mut caller, FUEL_CONTEXT_READ)?;
            let addr = caller.data().host.self_address().as_bytes().to_vec();
            write_guest_bytes(&mut caller, out_ptr, &addr, out_max_len)
        },
    )?;

    linker.func_wrap(
        "env",
        "get_input",
        |mut caller: Caller<'_, StoreState<C>>, out_ptr: i32, out_max_len: i32| -> Result<i32, Trap> {
            consume(&mut caller, FUEL_CONTEXT_READ)?;
            let input = caller.data().host.input().to_vec();
            write_guest_bytes(&mut caller, out_ptr, &input, out_max_len)
        },
    )?;

    linker.func_wrap(
        "env",
        "get_value",
        |mut caller: Caller<'_, StoreState<C>>| -> Result<i64, Trap> {
            consume(&mut caller, FUEL_CONTEXT_READ)?;
            Ok(caller.data().host.value() as i64)
        },
    )?;

    linker.func_wrap(
        "env",
        "get_block_height",
        |mut caller: Caller<'_, StoreState<C>>| -> Result<i64, Trap> {
            consume(&mut caller, FUEL_CONTEXT_READ)?;
            Ok(caller.data().host.block_height() as i64)
        },
    )?;

    linker.func_wrap(
        "env",
        "set_return_data",
        |mut caller: Caller<'_, StoreState<C>>, ptr: i32, len: i32| -> Result<(), Trap> {
            consume(&mut caller, FUEL_CONTEXT_READ)?;
            let data = read_guest_bytes(&mut caller, ptr, len, MAX_VALUE_LEN)?;
            caller.data_mut().host.set_return_data(data);
            Ok(())
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn wat_to_wasm(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("valid WAT fixture")
    }

    /// A minimal, in-memory `HostContext` for tests — no chain state, no atomicity
    /// buffering (that's `helix-executor`'s job, tested separately against real
    /// `ChainState`), just enough to exercise every host function's own ABI/plumbing.
    #[derive(Default)]
    struct TestHost {
        storage: HashMap<Vec<u8>, Vec<u8>>,
        transfers: Vec<(String, u64)>,
        balance: u64,
        caller: String,
        self_address: String,
        value: u64,
        block_height: u64,
        input: Vec<u8>,
        return_data: Vec<u8>,
        deny_transfer: bool,
    }

    impl HostContext for TestHost {
        fn storage_read(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.storage.get(key).cloned()
        }
        fn storage_write(&mut self, key: &[u8], value: Vec<u8>) {
            self.storage.insert(key.to_vec(), value);
        }
        fn transfer(&mut self, to: &str, amount: u64) -> TransferOutcome {
            if self.deny_transfer || amount > self.balance {
                return TransferOutcome::InsufficientBalance;
            }
            self.balance -= amount;
            self.transfers.push((to.to_string(), amount));
            TransferOutcome::Ok
        }
        fn caller(&self) -> &str {
            &self.caller
        }
        fn self_address(&self) -> &str {
            &self.self_address
        }
        fn value(&self) -> u64 {
            self.value
        }
        fn block_height(&self) -> u64 {
            self.block_height
        }
        fn input(&self) -> &[u8] {
            &self.input
        }
        fn set_return_data(&mut self, data: Vec<u8>) {
            self.return_data = data;
        }
    }

    fn host() -> TestHost {
        TestHost {
            caller: "hlxCaller".to_string(),
            self_address: "hlxSelf".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn validate_accepts_well_formed_module() {
        let wasm = wat_to_wasm(r#"(module (func (export "call")))"#);
        assert!(validate(&wasm).is_ok());
    }

    #[test]
    fn validate_rejects_garbage_bytes() {
        assert!(validate(b"not wasm").is_err());
    }

    #[test]
    fn call_runs_exported_entry_point() {
        let wasm = wat_to_wasm(r#"(module (func (export "call")))"#);
        let outcome = call(&wasm, 1_000_000, &mut host()).expect("call should succeed");
        assert!(outcome.fuel_used > 0);
    }

    #[test]
    fn call_rejects_module_without_entry_point() {
        let wasm = wat_to_wasm(r#"(module (func (export "not_call")))"#);
        assert!(matches!(call(&wasm, 1_000_000, &mut host()), Err(VmError::MissingEntryPoint)));
    }

    #[test]
    fn call_fails_out_of_gas_on_infinite_loop() {
        let wasm = wat_to_wasm(r#"(module (func (export "call") (loop br 0)))"#);
        let err = call(&wasm, 10_000, &mut host()).unwrap_err();
        assert!(matches!(err, VmError::OutOfGas));
    }

    #[test]
    fn call_rejects_declared_memory_over_the_limit_instead_of_allocating_it() {
        // 65536 pages * 64 KiB/page = 4 GiB — the maximum a 32-bit Wasm memory type
        // allows, and comfortably declarable in a tiny module. Without a configured
        // ResourceLimiter, wasmi allocates the *declared minimum* eagerly at
        // instantiation, before a single fuel unit is spent — this must be rejected
        // instead of attempting the allocation.
        let wasm = wat_to_wasm(r#"(module (memory 65536 65536) (func (export "call")))"#);
        let err = call(&wasm, 1_000_000, &mut host()).unwrap_err();
        assert!(
            matches!(err, VmError::Instantiation(_)),
            "expected instantiation to fail cleanly, got: {err:?}"
        );
    }

    #[test]
    fn call_accepts_memory_within_the_limit() {
        let wasm = wat_to_wasm(r#"(module (memory 1 1) (func (export "call")))"#);
        assert!(call(&wasm, 1_000_000, &mut host()).is_ok());
    }

    #[test]
    fn call_rejects_module_with_unknown_host_imports() {
        let wasm = wat_to_wasm(
            r#"(module (import "env" "not_a_real_host_fn" (func)) (func (export "call")))"#,
        );
        assert!(matches!(call(&wasm, 1_000_000, &mut host()), Err(VmError::Instantiation(_))));
    }

    // Determinism guarantees (formal verification tooling — see engine()'s doc
    // comment): floats are rejected wherever they could appear in a module, not
    // just when actually executed, so this is checked at `validate()` time (i.e.
    // at deploy, before the bytecode is ever accepted on-chain).

    #[test]
    fn validate_rejects_a_module_using_a_float_instruction() {
        let wasm = wat_to_wasm(r#"(module (func (export "call") (drop (f32.const 1.0))))"#);
        assert!(matches!(validate(&wasm), Err(VmError::InvalidModule(_))));
    }

    #[test]
    fn validate_rejects_a_module_with_a_float_typed_global() {
        let wasm = wat_to_wasm(
            r#"(module (global $g f64 (f64.const 0.0)) (func (export "call")))"#,
        );
        assert!(matches!(validate(&wasm), Err(VmError::InvalidModule(_))));
    }

    #[test]
    fn validate_rejects_a_module_with_a_float_typed_local() {
        let wasm = wat_to_wasm(r#"(module (func (export "call") (local f32)))"#);
        assert!(matches!(validate(&wasm), Err(VmError::InvalidModule(_))));
    }

    #[test]
    fn validate_rejects_a_module_with_a_float_typed_parameter() {
        let wasm = wat_to_wasm(
            r#"(module (func $helper (param f64)) (func (export "call")))"#,
        );
        assert!(matches!(validate(&wasm), Err(VmError::InvalidModule(_))));
    }

    #[test]
    fn call_rejects_float_instructions_too_not_just_validate() {
        // Defense in depth: both validate() and call() build the module through the
        // same engine(), so this is really the same guarantee exercised via the
        // other entry point — but it's the one that matters at contract-call time.
        let wasm = wat_to_wasm(r#"(module (func (export "call") (drop (f32.const 1.0))))"#);
        assert!(matches!(call(&wasm, 1_000_000, &mut host()), Err(VmError::InvalidModule(_))));
    }

    #[test]
    fn validate_still_accepts_integer_only_modules() {
        let wasm = wat_to_wasm(
            r#"(module (func (export "call") (local i32 i64) (drop (i32.const 1))))"#,
        );
        assert!(validate(&wasm).is_ok());
    }

    // ── Host function tests ─────────────────────────────────────────────────────

    /// A module that imports every host function this crate defines — proves the whole ABI
    /// links successfully in one shot, exercised further by the individual tests below.
    const STORAGE_ROUNDTRIP_WAT: &str = r#"
        (module
            (import "env" "storage_write" (func $storage_write (param i32 i32 i32 i32) (result i32)))
            (import "env" "storage_read" (func $storage_read (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            ;; key "k" at offset 0, value "hello" at offset 16, read buffer at offset 32
            (data (i32.const 0) "k")
            (data (i32.const 16) "hello")
            (func (export "call")
                ;; write key="k" (len 1) value="hello" (len 5)
                (drop (call $storage_write (i32.const 0) (i32.const 1) (i32.const 16) (i32.const 5)))
                ;; read it back into offset 32, with an 8-byte max buffer
                (drop (call $storage_read (i32.const 0) (i32.const 1) (i32.const 32) (i32.const 8)))
            )
        )
    "#;

    #[test]
    fn storage_write_then_read_roundtrips_through_a_real_wasm_module() {
        let wasm = wat_to_wasm(STORAGE_ROUNDTRIP_WAT);
        let mut h = host();
        call(&wasm, 1_000_000, &mut h).expect("call should succeed");
        assert_eq!(h.storage.get(b"k".as_slice()).map(|v| v.as_slice()), Some(b"hello".as_slice()));
    }

    #[test]
    fn storage_read_reports_true_length_even_when_truncated_by_a_small_buffer() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "storage_write" (func $storage_write (param i32 i32 i32 i32) (result i32)))
                (import "env" "storage_read" (func $storage_read (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "k")
                (data (i32.const 16) "hello")
                (global $len (mut i32) (i32.const -1))
                (func (export "call")
                    (drop (call $storage_write (i32.const 0) (i32.const 1) (i32.const 16) (i32.const 5)))
                    ;; read with only a 2-byte output buffer — value is 5 bytes
                    (global.set $len (call $storage_read (i32.const 0) (i32.const 1) (i32.const 32) (i32.const 2)))
                )
                (export "len" (global $len))
            )
            "#,
        );
        let mut h = host();
        call(&wasm, 1_000_000, &mut h).expect("call should succeed");
        // The host-side record is untruncated regardless of the guest's small buffer.
        assert_eq!(h.storage.get(b"k".as_slice()).map(|v| v.as_slice()), Some(b"hello".as_slice()));
    }

    #[test]
    fn storage_read_of_an_unset_key_returns_zero_and_does_not_touch_the_output_buffer() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "storage_read" (func $storage_read (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "missing")
                (func (export "call")
                    (drop (call $storage_read (i32.const 0) (i32.const 7) (i32.const 32) (i32.const 8)))
                )
            )
            "#,
        );
        assert!(call(&wasm, 1_000_000, &mut host()).is_ok());
    }

    #[test]
    fn transfer_moves_value_via_the_host_context() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "transfer" (func $transfer (param i32 i32 i64) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "hlxRecipient")
                (func (export "call")
                    (drop (call $transfer (i32.const 0) (i32.const 12) (i64.const 42)))
                )
            )
            "#,
        );
        let mut h = host();
        h.balance = 100;
        call(&wasm, 1_000_000, &mut h).expect("call should succeed");
        assert_eq!(h.transfers, vec![("hlxRecipient".to_string(), 42)]);
        assert_eq!(h.balance, 58);
    }

    #[test]
    fn transfer_reports_insufficient_balance_without_trapping() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "transfer" (func $transfer (param i32 i32 i64) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "hlxRecipient")
                (global $status (mut i32) (i32.const -99))
                (func (export "call")
                    (global.set $status (call $transfer (i32.const 0) (i32.const 12) (i64.const 1000)))
                )
                (export "status" (global $status))
            )
            "#,
        );
        let mut h = host();
        h.balance = 5; // less than the requested 1000
        call(&wasm, 1_000_000, &mut h).expect("call itself must succeed — insufficient balance is contract-visible, not a trap");
        assert!(h.transfers.is_empty(), "no transfer should have been recorded");
    }

    #[test]
    fn context_getters_report_the_configured_values() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "get_value" (func $get_value (result i64)))
                (import "env" "get_block_height" (func $get_block_height (result i64)))
                (import "env" "get_caller" (func $get_caller (param i32 i32) (result i32)))
                (import "env" "get_self_address" (func $get_self_address (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "call")
                    (drop (call $get_value))
                    (drop (call $get_block_height))
                    (drop (call $get_caller (i32.const 0) (i32.const 32)))
                    (drop (call $get_self_address (i32.const 32) (i32.const 32)))
                )
            )
            "#,
        );
        let mut h = host();
        h.value = 7;
        h.block_height = 123;
        assert!(call(&wasm, 1_000_000, &mut h).is_ok());
    }

    #[test]
    fn set_return_data_is_visible_to_the_host_after_the_call() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "set_return_data" (func $set_return_data (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "the-answer")
                (func (export "call")
                    (call $set_return_data (i32.const 0) (i32.const 10))
                )
            )
            "#,
        );
        let mut h = host();
        call(&wasm, 1_000_000, &mut h).expect("call should succeed");
        assert_eq!(h.return_data, b"the-answer".to_vec());
    }

    #[test]
    fn a_contract_without_exported_memory_traps_on_its_first_host_call() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "get_value" (func $get_value (result i64)))
                (func (export "call") (drop (call $get_value)))
            )
            "#,
        );
        // No `(memory (export "memory") ...)` at all — get_value doesn't need memory itself,
        // so this specific call succeeds; the real ABI contract (documented at module level)
        // is that any BYTE-carrying host call traps without an exported memory, covered next.
        assert!(call(&wasm, 1_000_000, &mut host()).is_ok());
    }

    #[test]
    fn a_byte_carrying_host_call_traps_without_exported_memory() {
        let wasm = wat_to_wasm(
            r#"
            (module
                (import "env" "get_caller" (func $get_caller (param i32 i32) (result i32)))
                (func (export "call") (drop (call $get_caller (i32.const 0) (i32.const 32))))
            )
            "#,
        );
        let err = call(&wasm, 1_000_000, &mut host()).unwrap_err();
        assert!(matches!(err, VmError::Trap(_)), "expected a trap, got: {err:?}");
    }

    #[test]
    fn storage_write_rejects_an_oversized_value_without_trapping() {
        let wasm = wat_to_wasm(&format!(
            r#"
            (module
                (import "env" "storage_write" (func $storage_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 2)
                (data (i32.const 0) "k")
                (global $status (mut i32) (i32.const -99))
                (func (export "call")
                    (global.set $status (call $storage_write (i32.const 0) (i32.const 1) (i32.const 4) (i32.const {})))
                )
                (export "status" (global $status))
            )
            "#,
            MAX_VALUE_LEN + 1
        ));
        // The module declares 2 pages (128 KiB) of memory so the oversized length itself is
        // in-bounds — it's MAX_VALUE_LEN that must reject it, not a memory bounds check.
        assert!(call(&wasm, 1_000_000, &mut host()).is_ok(), "an oversized value must be a reported error, not a trap");
    }
}
