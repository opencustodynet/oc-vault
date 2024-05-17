# opencustody-vault

## how to run for softhsm
run this:
```bash
curl -X POST http://localhost:8000/RemoveVault \
     -H "Content-Type: application/json" \
     -d '{"label": "Secondary Vault", "reasons": [{"name": "Obsolete", "code": 200}, {"name": "Damaged", "code": 300}], "code": 1234}'
```
