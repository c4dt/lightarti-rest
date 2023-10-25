// inspired by https://github.com/p2panda/meli/pull/21/files
// meli is licensed under GNU AFFERO GENERAL PUBLIC LICENSE

use std::env;

fn main() {
    // NDK > 25 does not link to `libgcc` anymore
    // see https://github.com/p2panda/meli/pull/21/files
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86_64"
        && env::var("CARGO_CFG_TARGET_OS").unwrap() == "android"
    {
        let home: String = env::var("HOME").unwrap();
        println!("cargo:rustc-link-search={home}/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/14.0.7/lib/linux/");
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64-android");
    }
}
