# OpenCustody Vault

Vault is the core of the OpenCustody project, providing essential functionalities for secure cryptocurrency custody using [Thales Luna HSM](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms). Luna HSM is widely adopted in various projects and cloud platforms such as Google Cloud and AWS due to its robust security features and native support for cryptocurrency operations like ECDSA and EDDSA signing, as well as BIP-32 and SLIP-10 key derivation.

## Configurations

Vault can be built in three different configurations:

1. `softhsm`: In this configuration, OpenCustody uses SoftHSM as its HSM. [SoftHSM](https://github.com/opendnssec/SoftHSMv2) is an open-source project designed for the development and testing of HSM applications in a software-simulated environment. This configuration is ideal for simulation purposes, speeding up the development and testing processes.

2. `lunahsm`: This configuration is used to build OpenCustody for actual Luna HSM deployment. OpenCustody connects to a Luna HSM to generate, store, and derive keys, and sign transactions. It supports both in-house and cloud-based HSMs (such as Google Cloud and AWS). In this setup, key generation and BIP-32/SLIP-10 derivations occur within the HSM, ensuring keys never leave the HSM in plain text. However, hash values (prehash) and policy verifications are performed outside the HSM.

3. `lunahsm_fm`: This special configuration provides the highest level of security. In this setup, the OpenCustody Vault is built as a Luna HSM firmware (FM) and loaded directly into a Luna HSM. All key operations, including key generation, BIP-32/SLIP-10 derivation, hash calculation, and policy verification, are executed entirely within the HSM.

## `softhsm`
Test with `softhsm` using this command:
```bash
cargo test --features softhsm
```

You can also build for `softhsm` (output: `target/debug/vault-proxy`) using this command:
```bash
cargo build --features softhsm
```

## `lunahsm`
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

## `lunahsm_fm`
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