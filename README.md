# OpenCustody Vault

## How to build, run, and test
To run with `softhsm`, initialize `softhsm` for one time:
```bash
sh init_softhsm.sh
```
and run `vault-proxy` for `softhsm`:
```bash
cargo run
```

Build for `softhsm` (output: `target/debug/vault-proxy`):
```bash
cargo build
```

Build `vault-proxy` for Luna HSM (output: `target/release/vault-proxy`):
```bash
cargo build -p vault-proxy --release --features lunahsm
```

Build `vault-core` as a FM module for Luna HSM (output: `target/powerpc-unknown-linux-gnu/release/vault-core.bin`):
```bash
sh build_fm.sh
```

Test with `vault-proxy`:
```bash
curl -X POST http://localhost:8000/get_random -H "Content-Type: application/json" -d '{"size": 10}'
```
