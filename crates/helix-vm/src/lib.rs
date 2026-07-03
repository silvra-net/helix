//! Minimal WASM smart contract runtime for Helix.
//!
//! Contracts are self-contained WASM modules with no host imports (rejected at
//! instantiation) and must export a zero-argument, zero-return entry point named
//! `call`. Execution is fuel-metered so a contract can never run unbounded.

use thiserror::Error;
use wasmi::{core::TrapCode, Config, Engine, Linker, Module, Store};

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

    let mut store = Store::new(&engine, ());
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
    fn call_rejects_module_with_host_imports() {
        let wasm = wat_to_wasm(
            r#"(module (import "env" "host_fn" (func)) (func (export "call")))"#,
        );
        assert!(matches!(call(&wasm, 1_000_000), Err(VmError::Instantiation(_))));
    }
}
