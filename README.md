# OpenCustody Vault

## Softhsm (simulation)
Test with `softhsm` using this command:
```bash
cargo test --features softhsm
```

You can also build for `softhsm` (output: `target/debug/vault-proxy`) using this command:
```bash
cargo build --features softhsm
```

## Luna HSM
If your development machine is connected to a Luna HSM, you can use this command to directly test with `lunahsm`:
```bash
cargo test --features lunahsm
```

However, if your machine is not connected to a Luna HSM, you can use this command to build a test binrary, and run it on a machine that is connected to a Luna HSM:
```bash
cargo test --features lunahsm --no-run
```

build for `lunahsm` (output: `target/debug/vault-proxy`):
```bash
cargo build --features lunahsm
```

## Luna HSM Firmware (FM)
Then, you can build `vault-core` as a FM module for Luna HSM using `build_fm.sh` script (output: `target/powerpc-unknown-linux-gnu/release/vault-core.bin`). This script compiles `vault-core` as a static library for powerpc, links it to the basic FM C library and builds it, and finally checks the final binary size to be sure that it is less than the Luna FM max size (8 MB).
```bash
sh build_fm.sh
```

To test with a Luna HSM, build a test binary for `vault-proxy` to run it on a test machine that has Luna PCIe HSM:
```bash
cargo test -p vault-proxy --no-run --features lunahsm_fm
...
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 10s
  Executable unittests src/main.rs (target/debug/deps/vault_proxy-c09aef4c34f69215)
```
In this case, the output test binary is `vault_proxy-c09aef4c34f69215`. Rename it to `vault_proxy_test`:
```bash
mv vault_proxy-c09aef4c34f69215 vault_proxy_test
```

Then, copy `test_lunahsm.sh`, `vault-core.bin` and `vault_proxy_test` to the test machine that has Luna PCIe HSM, and run this command:
```bash
sh test_lunahsm.sh
```

To build `vault-proxy` release for Luna HSM FM, you can use this command (output: `target/release/vault-proxy`):
```bash
cargo build -p vault-proxy --release --features lunahsm_fm
```