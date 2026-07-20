//! Host-only tool: generates the Kotlin bindings from this crate's compiled library metadata
//! ("library mode" — no separate UDL file to keep in sync with `src/lib.rs`'s `#[uniffi::export]`
//! items). Run via `cargo run --features uniffi-cli --bin uniffi-bindgen -- generate --library
//! <path-to-cdylib> --language kotlin --out-dir <dir>`. Not part of the shipped Android library.
fn main() {
    uniffi::uniffi_bindgen_main()
}
