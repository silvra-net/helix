# helix-mobile

UniFFI bindings exposing Helix's *real* transaction signing to mobile apps — built to replace
Spark's hand-maintained TypeScript mirror of `helix_core::Transaction`/`TxPayload`
(`client/src/services/helixTx.ts` in the `silvra-net/spark` repo), which drifts silently
whenever `helix-core`'s signing format changes (it already did once, 2026-07-20). See this
crate's `src/lib.rs` doc comment for the full incident and design rationale.

Deliberately narrow: `derive_address(seed)` and `sign_transaction(seed, tx)` only — not a
general Helix SDK. `data` payloads for contract/governance/personhood transactions stay the
caller's responsibility (opaque bytes, never signature-critical structure), exactly as before.

Own Cargo workspace (see `Cargo.toml`), same reason as `gui/src-tauri`: uniffi's dependency tree
has no business in `cargo build/test --workspace` for the chain itself.

## Verify the Rust side

```bash
cd mobile
cargo test                                 # unit tests, including a real round-trip through
                                            # Transaction::verify_signature()
cargo run --example sign_demo -- <to> <amount_nano> <fee_nano> <nonce>   # prints signed JSON,
                                            # pipe into `curl -d @- <node>/transactions` against
                                            # a real (never prod) node for an end-to-end check
```

## Build for Android

Needs the Android NDK (`sdkmanager "ndk;27.1.12297006"`) and Rust's Android targets
(`rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
i686-linux-android`) and `cargo install cargo-ndk`.

```bash
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.1.12297006
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 -o target/android-libs build --release
```

Produces `target/android-libs/<abi>/libhelix_mobile.so` for each ABI.

## Generate the Kotlin bindings

"Library mode" — reads UniFFI metadata embedded in the compiled `.so`, no separate UDL file to
keep in sync with `src/lib.rs`'s `#[uniffi::export]` items.

```bash
cargo build --release --features uniffi-cli --bin uniffi-bindgen
./target/release/uniffi-bindgen generate \
  --library target/android-libs/arm64-v8a/libhelix_mobile.so \
  --language kotlin --out-dir target/kotlin-bindings
```

Produces `target/kotlin-bindings/uniffi/helix_mobile/helix_mobile.kt`.

## Wiring into Spark (silvra-net/spark, `client/android/`)

Both of the above are build artifacts, not committed here (see `.gitignore`) — copy them into
Spark's native project whenever this crate's signing surface changes:

```bash
cp target/android-libs/*/libhelix_mobile.so \
  ../../spark/client/android/app/src/main/jniLibs/<matching-abi>/
cp target/kotlin-bindings/uniffi/helix_mobile/helix_mobile.kt \
  ../../spark/client/android/app/src/main/java/uniffi/helix_mobile/
```

Spark's `HelixSignerModule.kt`/`HelixSignerPackage.kt` (React Native bridge, same
`ReactContextBaseJavaModule`/`ReactPackage` pattern as its existing `NetworkBindingModule.kt`)
and the `net.java.dev.jna:jna:5.13.0@aar` Gradle dependency it needs are Spark-repo concerns —
see that repo's `client/src/services/helixNative.ts`/`helixSign.ts` for the JS side. If
`sign_transaction`'s field names or `MobileError` variants change, the Kotlin module needs a
matching update (it is not generated, unlike `helix_mobile.kt`).

## Verified so far

- `cargo test`: 5/5, including a real `Transaction::verify_signature()` round-trip.
- Cross-compiled cleanly for all 4 Android ABIs.
- UniFFI Kotlin bindings generated successfully (`uniffi/helix_mobile/helix_mobile.kt`,
  `deriveAddress(seed: ByteArray): String` / `signTransaction(seed: ByteArray, tx: UnsignedTx):
  SignedTx`).
- **Live end-to-end proof**, not just unit tests: signed a real transaction with this crate,
  `POST`ed it to a real (isolated, non-prod) Helix devnet — accepted, applied, correct fee
  split and balances, nonce advanced. The signature and encoding are provably correct against
  the actual chain, not just internally self-consistent.
- Spark's `:app:compileDebugKotlin` succeeds with `HelixSignerModule.kt` + the generated
  bindings wired in and registered in `MainApplication.kt`.
- **Not yet verified:** an actual signed transaction from within the Spark app on a real
  device/emulator — no device was available in the authoring sandbox. The Rust-side signing is
  proven correct against a live node; the remaining risk is purely in the JNI/JNA plumbing
  (argument marshalling, library loading) between Kotlin and the `.so`, unverified by anything
  short of running the built app.
