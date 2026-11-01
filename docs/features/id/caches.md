# Cache

Membaca dan mengubah Redis dan Valkey dengan aman. [Semua fitur](README.md)

`komando cache` bekerja dengan Redis dan cache yang kompatibel (Valkey, KeyDB,
Dragonfly) yang ditambahkan dengan `komando conn add`.

```bash
komando cache info cache                      # versi, memori, client
komando cache keys cache 'session:*'          # daftar key (aman untuk cache besar)
komando cache get cache session:42            # tipe apa pun: nilai, tipe, sisa umur
komando cache set cache maintenance on --ttl 30m
komando cache rm cache session:42 --allow-dangerous   # menghapus butuh --allow-dangerous
```

Selain itu, pakai `cache run`. **Perintah ini hanya membaca kecuali Anda
menambahkan `--write`:**

```bash
komando cache run cache -- HGETALL user:42
komando cache run cache --write -- EXPIRE session:42 3600
```

Perintah yang menghapus, mengosongkan, memblokir, menjalankan skrip, atau
mengubah konfigurasi server (`DEL`, `FLUSHALL`, `KEYS`, `EVAL`, `CONFIG SET`,
`SHUTDOWN`, ...) juga butuh `--allow-dangerous`. Conn yang protected butuh
`--yes` untuk setiap perubahan. Redis tidak bisa membatalkan, jadi
`--dry-run` hanya menunjukkan bahwa perubahan akan diizinkan; tidak ada yang
dikirim.
