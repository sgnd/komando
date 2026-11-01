# Storage: bucket dan file server

Melihat, mengunduh, dan mengunggah file di bucket yang kompatibel dengan S3
dan di server FTPS, SFTP, dan FTP, dengan perintah yang sama. [Semua fitur](README.md)

`komando storage` bekerja dengan S3 dan setiap layanan yang kompatibel
dengan S3 (MinIO, Cloudflare R2, Wasabi, DigitalOcean Spaces, Backblaze B2,
Garage). Tambahkan bucket sebagai conn; folder di URL membatasi conn itu ke
folder tersebut.

```bash
komando secret set backups-secret               # secret access key
komando conn add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref secret:backups-secret

komando storage ls backups                      # satu tingkat; --recursive untuk semuanya
komando download backups 2026/app.sql.gz            # ke folder saat ini
komando upload backups ./app.sql.gz 2026/app.sql.gz
komando storage link backups 2026/app.sql.gz --expires 24h   # link unduhan sementara
komando storage rm backups 2026/old.sql.gz --allow-dangerous
```

- Unduhan tidak pernah menimpa file; file-nya hanya bisa dibaca oleh Anda.
- `upload` mengganti objek dengan key yang sama (hasilnya menyebut
  `"replaced": true`). `rm` hanya menerima key yang persis, tidak folder atau
  pola, dan butuh `--allow-dangerous` karena objek yang dihapus hilang
  selamanya.
- Conn yang protected butuh `--yes` untuk `upload`, `rm`, dan `link`.
  `--dry-run` menunjukkan bahwa perubahan akan diizinkan dan tidak mengirim
  apa pun.
- Key tidak bisa keluar dari folder conn (`../` ditolak).
- Link bisa dipakai siapa saja yang memilikinya sampai kedaluwarsa.
  Bagikan seperti password. Link tidak ditulis ke riwayat.
- Setup paling aman: beri komando access key yang hanya bisa melakukan yang
  Anda butuhkan (hanya-baca untuk laporan, satu bucket saja). Layanannya
  sendiri yang kemudian menegakkannya.

## File server (FTPS, SFTP, FTP)

Web hosting dan sistem lama sering hanya memberi akses file. Tambahkan
server-nya sebagai conn; folder di URL adalah tempat komando mulai, dan key
tidak bisa keluar dari folder itu.

| Jenis | Contoh URL | Catatan |
|-------|------------|---------|
| FTPS | `ftps://deploy@files.example.com/public_html` | FTP dengan TLS. Tambahkan `?tls=skip-verify` hanya untuk sertifikat self-signed yang Anda percaya. |
| SFTP | `sftp://deploy@files.example.com/uploads` | Akses file lewat SSH, untuk akun tanpa shell. Path dihitung dari root server (di hosting sering berupa folder home Anda). |
| FTP  | `ftp://deploy@files.example.com/www?insecure=1` | Tanpa enkripsi: password dan file dikirim terbuka. komando menolaknya tanpa `?insecure=1`. Lebih baik pakai FTPS atau SFTP. |

```bash
komando secret set hosting-pass
komando conn add site 'ftps://deploy@files.example.com/public_html' --password-ref secret:hosting-pass

komando storage ls site --recursive
komando upload site ./index.html index.html
komando download site logs/error.log
komando storage rm site old/index.html --allow-dangerous
```

- Unggahan dikirim dulu ke nama sementara lalu diganti namanya ke tempat
  aslinya, jadi unggahan yang gagal tidak pernah meninggalkan file setengah
  jadi dengan nama aslinya. Folder yang belum ada akan dibuat.
- SFTP mengecek identitas server seperti host SSH lainnya (diingat pada
  koneksi pertama, dan perubahan ditolak dengan `HOSTKEY_MISMATCH`), dan bisa
  memakai SSH key Anda selain password.
- `--via` bekerja sama seperti untuk conn lain: lewat bastion atau VPN.
- File server tidak punya link sementara: `storage link` hanya untuk S3.
