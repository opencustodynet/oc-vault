# OpenCustody Vault

## How to build, run, and test
Run with `softhsm`:
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
curl -X POST http://localhost:8000/RemoveVault \
     -H "Content-Type: application/json" \
     -d '{"label": "Secondary Vault", "reasons": [{"name": "Obsolete", "code": 200}, {"name": "Damaged", "code": 300}], "code": 1234}'
```
