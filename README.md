# OpenCustody Vault

## How to build, run, and test
Run with `softhsm`:
```bash
cargo run
```

Build for `softhsm`:
```bash
cargo build
```
output: `target/debug/vault-proxy`

Build `vault-proxy` for Luna HSM:
```bash
cargo build -p vault-proxy --release --features lunahsm
```
output: `target/release/vault-proxy`

Build `vault-core` as FM module for Luna HSM:
```bash
sh build_fm.sh
```

Test with `vault-proxy`:
```bash
curl -X POST http://localhost:8000/RemoveVault \
     -H "Content-Type: application/json" \
     -d '{"label": "Secondary Vault", "reasons": [{"name": "Obsolete", "code": 200}, {"name": "Damaged", "code": 300}], "code": 1234}'
```
