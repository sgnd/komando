# Hasil dan error

Cara komando menjawab, exit code, dan memperbaiki error yang sering muncul. [Semua fitur](README.md)

## Membaca hasilnya

Di terminal Anda mendapat teks yang mudah dibaca. Saat program lain (seperti
AI agent) menjalankan komando, program itu mendapat satu objek JSON. Paksa
salah satunya dengan `-o text` atau `-o json`.

```json
{
  "ok": false,
  "command": "exec",
  "data": { "results": [ { "host": "web1", "ok": false, "exit_code": 3, "stdout": "", "stderr": "…" } ] },
  "error": { "code": "FAILED", "message": "host web1 failed", "hint": "…" },
  "meta": { "version": "0.1.0", "duration_ms": 211 }
}
```

`error.hint` selalu memberi tahu apa yang perlu dicoba berikutnya. Saat
target memilih hal-hal yang tidak bisa dikerjakan perintah itu,
`meta.skipped` mendaftarnya beserta alasannya (juga saat perintahnya
kemudian gagal).

| Exit code | Artinya |
|-----------|---------|
| 0 | sukses |
| 1 | error umum |
| 2 | perintah atau flag salah |
| 3 | tidak ditemukan (server, file, key…) |
| 4 | tidak bisa terhubung atau login |
| 5 | perintahnya gagal di server |
| 6 | diblokir demi keamanan |
| 7 | waktu habis |
| 8 | syarat edit tidak terpenuhi (teks tidak ditemukan / tidak unik) |

Referensi lengkap yang bisa dibaca program ada di `komando schema`.

## Apakah skrip saya tetap jalan?

Setiap jawaban JSON punya `meta.contract` (sekarang `1`). Di dalam satu
kontrak, komando hanya menambah field, kode error, dan perintah; tidak
pernah mengganti nama atau menghapusnya, dan perintah serta flag yang
diganti namanya tetap jalan sebagai alias. Kalau suatu saat harus berubah,
`meta.contract` naik dan changelog menjelaskan apa yang berubah.

## Mengatasi masalah

| Error | Biasanya berarti | Coba |
|-------|------------------|------|
| `AUTH_FAILED` | user, key, atau password salah | `komando host show NAME`, `komando key deploy` |
| `CONNECTION_REFUSED` / `CONNECT_TIMEOUT` | server mati, port salah, firewall | cek alamat dan port, `--connect-timeout 30s` |
| `HOSTKEY_MISMATCH` | server dibangun ulang — atau ada yang menyadap | pastikan ke penyedia hosting Anda, lalu `komando host trust NAME --reset` |
| `SECRET_UNRESOLVED` | password tersimpan atau env var tidak ada | `komando secret list` |
| `sudo: a password is required` | sudo butuh password | `komando host edit NAME --sudo-ref secret:NAME` |
| `POLICY_BLOCKED` | kelihatannya merusak | periksa lagi; manusia boleh menambahkan `--allow-dangerous` |
| `PROTECTED_HOST` / `PROTECTED_TARGET` | perubahan pada sesuatu yang ditandai protected | manusia boleh menambahkan `--yes` |
| `SAFETY_SETTING` | perubahan yang mematikan sabuk pengaman | manusia boleh menambahkan `--yes` |
| `NO_MATCHING_TARGETS` | target hanya memilih hal-hal yang tidak bisa dipakai perintah ini | ikuti hint-nya (mis. pakai `komando db` untuk database) |
| `TARGET_NOT_FOUND` / `TARGET_EMPTY` | salah ketik di nama, grup, atau tag | hint-nya menyarankan yang paling mirip; `komando list` |
| `TIMEOUT` | terlalu lama | `--timeout 30m` atau pakai `komando job start` |

`komando doctor` mengecek setup di komputer Anda.
