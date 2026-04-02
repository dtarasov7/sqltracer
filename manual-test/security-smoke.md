# Security Smoke Checklist

Run from repository root:

```bash
bash manual-test/security-smoke.sh
```

The smoke suite validates:

1. Non-loopback bind is rejected unless `--allow-remote-listen` is explicitly enabled.
2. Vault over `http://` is rejected by default.
3. Event save files are created with `0600` permissions.
4. Per-connection pending queue overflow is blocked.
