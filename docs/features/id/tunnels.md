# Server privat dan tunnel

Menjangkau server dan layanan yang tidak ada di internet. [Semua fitur](README.md)

## Lewat bastion

Banyak server privat hanya bisa dijangkau lewat satu server "gerbang"
publik, yang sering disebut **bastion** atau jump host. Beri tahu komando
sekali, dan setiap perintah akan lewat situ dengan sendirinya:

```bash
komando host add bastion ubuntu@203.0.113.10
komando host add db1 admin@10.0.0.5 --via bastion          # server di belakang bastion
komando host add deep admin@10.1.0.7 --via bastion,db1     # rantai: bastion, lalu db1
komando conn add app-db postgres://app@10.0.0.9/app --via bastion   # database di belakangnya
```

komando membuka koneksi lewat bastion di dalam prosesnya sendiri. Tidak ada
port yang terbuka di komputer Anda dan pengaturan jaringan Anda tidak
berubah.

`--via` bekerja sama untuk server dan conn, dan sebuah rantai mendaftar
langkah-langkahnya dari komputer Anda sampai ke target. Dokumen lama mungkin
menyebut `--jump`; itu masih berfungsi.

## Pakai aplikasi Anda sendiri (TablePlus, psql, DBeaver)

Untuk membuka database di belakang bastion dengan aplikasi di komputer Anda,
jalankan tunnel dengan nama conn-nya. komando memilih port lokal yang kosong
dan menampilkannya:

```bash
komando tunnel start app-db                 # → listen: 127.0.0.1:53412
komando tunnel start app-db --port 15432    # pilih port sendiri
```

Arahkan aplikasi ke alamat itu dengan user dan password database. Tunnel
tetap hidup di latar belakang sampai `komando tunnel stop`.

## Tunnel untuk aplikasi lain

Tunnel membuat layanan di server muncul di komputer Anda sendiri. Tunnel
berjalan di latar belakang sampai Anda menghentikannya.

`-L 15432:localhost:5432` artinya: "port 15432 di komputer *saya* mengarah ke
port 5432 (PostgreSQL) di server". Lalu arahkan aplikasi database Anda ke
`localhost:15432`.

```bash
komando tunnel start db1 -L 15432:localhost:5432
komando tunnel start bastion -D 1080   # proxy SOCKS: set browser Anda ke localhost:1080 untuk browsing "dari" server
komando tunnel list
komando tunnel stop --all
```
