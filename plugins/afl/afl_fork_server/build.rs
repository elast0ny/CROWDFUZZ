extern crate bindgen;

use std::env;

fn main() {
    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    let proj_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let dynamorio_lib_path;
    let dynamorio_ext_path;
    let extra_defines;
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            extra_defines = "-DX86_64";
            dynamorio_lib_path = "res\\DynamoRIO\\lib64\\release\\";
            dynamorio_ext_path = "res\\DynamoRIO\\ext\\lib64\\release";
        } else {
            extra_defines = "-DX86_32";
            dynamorio_lib_path = "res\\DynamoRIO\\lib32\\release\\";
            dynamorio_ext_path = "res\\DynamoRIO\\ext\\lib32\\release";
        }
    }
    
    // Core DynamoRIO lib
    println!("cargo:rustc-link-search={}\\{}", proj_dir, dynamorio_lib_path);
    println!("cargo:rustc-link-lib=static=dynamorio");

    // Extenstions
    println!("cargo:rustc-cdylib-link-arg=/FORCE:MULTIPLE");
    println!("cargo:rustc-link-search={}\\{}", proj_dir, dynamorio_ext_path);
    println!("cargo:rustc-link-lib=static=drmgr");
    println!("cargo:rustc-link-lib=static=drx");
    println!("cargo:rustc-link-lib=static=drreg");
    println!("cargo:rustc-link-lib=static=drwrap");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=res/wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("res/wrapper.h")
        //.header_contents("_extra.h", extra_defines)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .size_t_is_usize(true)
        .opaque_type("_IMAGE.*")
        .derive_debug(false)
        .clang_arg(extra_defines)
        .raw_line("#![allow(warnings)]")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    //tmp.push("src\\dynamorio.rs");
    bindings
        .write_to_file("src\\windows\\dynamorio.rs")
        .expect("Couldn't write bindings!");
}
