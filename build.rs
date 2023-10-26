// adapted version of meli's fix https://github.com/p2panda/meli/pull/21/files

use std::env;
use std::path;

fn main() {
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86_64"
        && env::var("CARGO_CFG_TARGET_OS").unwrap() == "android"
    {
        const VERSION: &str = "25.2.9519653";
        let mut android_ndk_home: String = env::var("ANDROID_NDK_HOME").unwrap();
        // check if default version is pinned version
        if !android_ndk_home.contains(VERSION) {
            let mut splits: Vec<&str> = android_ndk_home.as_str().split('/').collect();
            splits.pop(); // remove default version
            android_ndk_home = format!("{}/{}", &splits.join("/"), VERSION);
        }
        if !path::Path::new(&android_ndk_home).exists() {
            panic!(
                "build cannot succeed: '{}' does not exist",
                android_ndk_home
            );
        }
        println!("cargo:rustc-link-search={android_ndk_home}/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/14.0.7/lib/linux/");
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64-android");
    }
}
