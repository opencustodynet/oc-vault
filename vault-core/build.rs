fn main() {
    if cfg!(feature = "softhsm") {
        println!("cargo:rustc-link-search=/usr/lib/softhsm");
        println!("cargo:rustc-link-arg=-Wl,-rpath=/usr/lib/softhsm");
        println!("cargo:rustc-link-lib=softhsm2");
    } else if cfg!(feature = "lunahsm") {
        println!("cargo:rustc-link-search=/usr/safenet/lunaclient/lib");
        println!("cargo:rustc-link-arg=-Wl,-rpath=/usr/safenet/lunaclient/lib");
        println!("cargo:rustc-link-lib=Cryptoki2_64");
    } else if cfg!(feature = "lunahsm_fm") {
        println!("cargo:rustc-link-search=/usr/safenet/lunafmsdk/lib");
        println!("cargo:rustc-link-lib=static=fmsupt");
    } else {
        println!("cargo:warning=no cryptoki specified.");
    }
}
