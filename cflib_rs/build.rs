fn main() {
    // Set the RUSTC_VERSION env variable
    let version = rustc_version::version().unwrap();
    println!("cargo:rustc-env=RUSTC_VERSION={}.{}.{}", version.major, version.minor, version.patch)
}