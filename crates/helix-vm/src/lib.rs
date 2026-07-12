//! Minimal WASM smart contract runtime for Helix.
//!
//! Contracts are self-contained WASM modules with no host imports (rejected at
//! instantiation) and must export a zero-argument, zero-return entry point named
//! `call`. Execution is fuel-metered so a contract can never run unbounded.

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
}
