//! Build script: emits the N-API link configuration when the `napi` feature is on.

fn main() {
    #[cfg(feature = "napi")]
    napi_build::setup();
}
