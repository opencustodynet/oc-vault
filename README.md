<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/opencustodynet/opencustody-vault/blob/main/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/opencustodynet/opencustody-vault/blob/main/logo.png">
  <img src="https://github.com/opencustodynet/opencustody-vault/blob/main/logo.png" alt="Logo" width="200"/>
</picture>

# OpenCustody Vault

## How to build, run, and test
### Build for softhsm
Build for `softhsm` (output: `target/debug/vault-proxy`):
```bash
cargo build --features softhsm
```
### Test with softhsm
To use `softhsm`, initialize `softhsm` for one time:
```bash
sh init_softhsm.sh
```

Test with `softhsm`:
```bash
cargo test --features softhsm
```

Run `vault-proxy` for `softhsm`:
```bash
cargo run --features softhsm
```

Test with `vault-proxy`:
```bash
curl -X POST http://localhost:8000/get_random -H "Content-Type: application/json" -d '{"size": 10}'
```

### Build for lunahsm
Build `vault-proxy` for Luna HSM (output: `target/release/vault-proxy`):
```bash
cargo build -p vault-proxy --release --features lunahsm
```

Build `vault-core` as a FM module for Luna HSM (output: `target/powerpc-unknown-linux-gnu/release/vault-core.bin`):
```bash
sh build_fm.sh
```

### Test with lunahsm
Build a test binary for `vault-proxy` to run it on a test machine that has Luna PCIe HSM:
```bash
cargo test -p vault-proxy --no-run --features lunahsm
...
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 10s
  Executable unittests src/main.rs (target/debug/deps/vault_proxy-c09aef4c34f69215)
```
In this case, the output test binary is `vault_proxy-c09aef4c34f69215`. Rename it to `vault_proxy_test`:
```bash
mv vault_proxy-c09aef4c34f69215 vault_proxy_test
```

Then, copy `test_lunahsm.sh`, `vault-core.bin` and `vault_proxy_test` to the test machine that has Luna PCIe HSM, and run:
```bash
sh test_lunahsm.sh
```
