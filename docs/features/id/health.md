# Cek kesehatan dan jaringan

Cari tahu server ini apa dan apakah sehat. [Semua fitur](README.md)

## Cek kesehatan server

```bash
komando facts web1               # OS, CPU, memori, disk, IP, tool yang terpasang
komando recipe list                 # 39 pemeriksaan siap pakai
komando recipe run health @web
komando recipe run disk all
komando recipe run top-mem web1
komando recipe run cert-expiry web1 --var name=example.com
komando recipe run updates all
```

## Cek jaringan

Dijalankan *dari* server Anda:

```bash
komando net check @web db.internal:5432 redis.internal:6379
komando net http web1 https://example.com
komando net ports web1 --sudo
komando net dns web1 api.example.com
```
