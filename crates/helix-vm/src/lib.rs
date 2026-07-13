//! Minimal WASM smart contract runtime for Helix.
//!
//! Contracts are self-contained WASM modules with no host imports (rejected at
//! instantiation) and must export a zero-argument, zero-return entry point named
//! `call`. Execution is fuel-metered so a contract can never run unbounded.
//!
//! # Determinism
//!
//! Every validator must reach the same result executing the same contract call,
//! or the chain forks. `wasmi` is a pure interpreter (no JIT, no platform-specific
//! codegen), which already rules out most sources of cross-machine divergence. The
//! remaining classic risk for a WASM-based VM is floating point: IEEE 754 pins down
//! most float behavior, but real toolchains/hardware have historically disagreed on
//! edge cases (canonical-NaN payload bits, fused-multiply-add availability) — the
//! reason the EVM never got native floats. `engine()` disables float types and
//! instructions outright via wasmi's `WasmFeatures` validator gate, so a module
//! that declares or uses one anywhere is rejected at `validate()` (deploy time),
//! before it can ever reach the chain.

use thiserror::Error;
use wasmi::{core::TrapCode, Config, Engine, Linker, Module, Store, StoreLimitsBuilder};

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

/// Instantiate `code` and invoke its exported `call() -> ()` entry point, bounded by
/// `fuel_limit` units of execution fuel (roughly: interpreted instructions).
pub fn call(code: &[u8], fuel_limit: u64) -> VmResult<CallOutcome> {
    let engine = engine();
    let module = Module::new(&engine, code).map_err(|e| VmError::InvalidModule(e.to_string()))?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(MAX_MEMORY_BYTES)
        .table_elements(MAX_TABLE_ELEMENTS)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, limits);
    store.limiter(|limits| limits);
    store
        .add_fuel(fuel_limit)
        .map_err(|e| VmError::Instantiation(e.to_string()))?;

    // No host functions are linked — a module that imports anything fails to
    // instantiate, which is exactly the sandboxing we want for now.
    let linker = Linker::new(&engine);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn wat_to_wasm(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("valid WAT fixture")
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
        let outcome = call(&wasm, 1_000_000).expect("call should succeed");
        assert!(outcome.fuel_used > 0);
    }

    #[test]
    fn call_rejects_module_without_entry_point() {
        let wasm = wat_to_wasm(r#"(module (func (export "not_call")))"#);
        assert!(matches!(call(&wasm, 1_000_000), Err(VmError::MissingEntryPoint)));
    }

    #[test]
    fn call_fails_out_of_gas_on_infinite_loop() {
        let wasm = wat_to_wasm(
            r#"(module (func (export "call") (loop br 0)))"#,
        );
        let err = call(&wasm, 10_000).unwrap_err();
        assert!(matches!(err, VmError::OutOfGas));
    }

    #[test]
    fn call_rejects_declared_memory_over_the_limit_instead_of_allocating_it() {
        // 65536 pages * 64 KiB/page = 4 GiB — the maximum a 32-bit Wasm memory type
        // allows, and comfortably declarable in a tiny module. Without a configured
        // ResourceLimiter, wasmi allocates the *declared minimum* eagerly at
        // instantiation, before a single fuel unit is spent — this must be rejected
        // instead of attempting the allocation.
        let wasm = wat_to_wasm(
            r#"(module (memory 65536 65536) (func (export "call")))"#,
        );
        let err = call(&wasm, 1_000_000).unwrap_err();
        assert!(
            matches!(err, VmError::Instantiation(_)),
            "expected instantiation to fail cleanly, got: {err:?}"
        );
    }

    #[test]
    fn call_accepts_memory_within_the_limit() {
        let wasm = wat_to_wasm(r#"(module (memory 1 1) (func (export "call")))"#);
        assert!(call(&wasm, 1_000_000).is_ok());
    }

    #[test]
    fn call_rejects_module_with_host_imports() {
        let wasm = wat_to_wasm(
            r#"(module (import "env" "host_fn" (func)) (func (export "call")))"#,
        );
        assert!(matches!(call(&wasm, 1_000_000), Err(VmError::Instantiation(_))));
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
        assert!(matches!(call(&wasm, 1_000_000), Err(VmError::InvalidModule(_))));
    }

    #[test]
    fn validate_still_accepts_integer_only_modules() {
        let wasm = wat_to_wasm(
            r#"(module (func (export "call") (local i32 i64) (drop (i32.const 1))))"#,
        );
        assert!(validate(&wasm).is_ok());
    }
}
