# Keamanan

Sabuk pengaman, dan apa yang harus dilakukan saat salah satunya menghentikan Anda. [Semua fitur](README.md)

| Sabuk pengaman | Fungsinya |
|----------------|-----------|
| Filter perintah berbahaya | Memblokir `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh` *di server Anda*, menghapus semua aturan firewall, mematikan SSH, dan lainnya. Lihat `komando policy list`. |
| Server dan conn protected | Perubahan butuh `--yes`. Perintah yang hanya melihat (tidak mengubah) bisa menyatakannya dengan `--read-only` dan jalan tanpa `--yes`. Menghapus yang protected, menggantinya, atau mematikan perlindungannya juga butuh `--yes`. Apa pun di alamat yang sama (target `user@address`, nama kedua, conn kedua ke server database yang sama) ikut terlindungi. |
| Pengaturan keamanan | Mematikan log audit atau pengecekan identitas server, atau menghapus aturan deny, butuh `--yes`. |
| Bertanya ke manusia | Saat Anda sendiri mengetik perintah di terminal, komando bertanya alih-alih gagal: `[y/N]` untuk target protected, dan mengetik nama target untuk perintah berbahaya. Agent dan skrip tidak pernah melihat pertanyaan ini; mereka butuh flag-nya. |
| Dry run | `--dry-run` menampilkan apa yang akan dijalankan dan apakah akan diblokir. |
| Edit yang aman | Penulisan atomik, ganti hanya jika teksnya cocok persis, backup `.bak` opsional. |
| Vault terenkripsi | Password dienkripsi dengan AES-256-GCM. Yang pernah ditampilkan hanya namanya. |
| Identitas server | Fingerprint server yang berubah menghentikan koneksi (`HOSTKEY_MISMATCH`). |
| Riwayat | Semua tindakan tercatat di `komando audit`. |

Menembus blokir butuh `--allow-dangerous` — itu keputusan manusia.
Secret tidak pernah diterima sebagai argumen perintah (nanti tersimpan di
riwayat shell Anda): `komando secret set NAME` menanyakan nilainya, atau pakai
`--from-env VAR` atau pipe.
Tambahkan aturan Anda sendiri dengan `komando policy deny 'REGEX'`.

> Filter ini menangkap kecelakaan yang umum; ini bukan batas keamanan yang
> lengkap. Beri otomasi user SSH yang hanya punya izin yang dibutuhkannya.
