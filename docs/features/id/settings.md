# Pengaturan dan file

Pengaturan, dan tempat komando menyimpan datanya. [Semua fitur](README.md)

```bash
komando config show
komando config set parallel 20
komando config set default_timeout 10m
komando config set host_key_policy strict    # accept-new (default) | strict | off (off butuh --yes)
komando config set audit_sql hash            # full (default) | hash | off: teks SQL tidak disimpan di riwayat
```

Semuanya disimpan di `~/.komando/` (ganti dengan `KOMANDO_HOME`):

| File | Isinya |
|------|--------|
| `state.json` | server, conn, key, pengaturan |
| `vault.json`, `vault.key` | secret terenkripsi dan kuncinya |
| `keys/` | SSH key yang dibuat oleh `komando key gen` |
| `known_hosts` | fingerprint server yang diingat |
| `audit.jsonl` | riwayat semua tindakan |

Backup folder ini dan jaga kerahasiaannya. Set `KOMANDO_VAULT_PASS` sebelum
secret pertama jika Anda lebih suka passphrase daripada file `vault.key`.
