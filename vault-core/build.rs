fn main() {
    if cfg!(feature = "lunahsm") {
        println!("cargo:rustc-link-search=/usr/safenet/lunaclient/lib");
        println!("cargo:rustc-link-arg=-Wl,-rpath=/usr/safenet/lunaclient/lib");
        println!("cargo:rustc-link-lib=ethsm");
    } else if cfg!(feature = "softhsm") {
        println!("cargo:rustc-link-arg=-Wl,-rpath=/usr/lib/softhsm");
    } else {
        println!("cargo:warning=no cryptoki specified.");
    }
}
