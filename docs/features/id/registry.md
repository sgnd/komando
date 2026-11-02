# Container registry

Lihat image apa saja yang ada di registry, salin image antar-registry, dan
bersihkan yang lama: Docker Hub, GHCR, GitLab, Harbor, ECR, atau `registry:2` milik Anda sendiri. [Semua fitur](README.md)

## Menambahkan registry

```bash
komando import docker                         # registry tempat Anda sudah login (~/.docker/config.json)
komando secret set ghcr-token                 # atau tambahkan satu secara manual
komando conn add ghcr registry://myuser@ghcr.io --password-ref secret:ghcr-token
komando conn add local 'registry://me@registry.lan:5000?tls=false' --via bastion   # tanpa TLS, di belakang bastion
```

Password-nya biasanya access token dengan hak baca (hak tulis untuk menyalin
ke registry itu, hak hapus untuk menghapus).

Login Amazon ECR berlaku 12 jam, jadi komando mengambil yang baru dari aws
CLI setiap kali (`aws ecr get-login-password`); jangan isi `--password-ref`:

```bash
komando conn add ecr registry://AWS@123456789012.dkr.ecr.eu-west-1.amazonaws.com --option aws_profile=prod
```

## Memakainya

```bash
komando registry ls harbor                    # repository (Docker Hub dan GHCR tidak mengizinkan ini)
komando registry ls ghcr myorg/api            # tag dari satu repository
komando registry inspect ghcr myorg/api:1.4.2 # digest, ukuran, platform, tanggal dibuat, label
komando registry copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2   # antar-registry
komando registry copy ghcr:myorg/api:1.4.2 harbor:                  # nama dan tag sama
komando registry rm harbor myorg/api:old --allow-dangerous
```

- `copy` menerima `CONN:IMAGE` di kedua sisi, seperti `komando cp`. Perintah
  ini menyalin setiap platform dari image multi-platform dan mempertahankan
  digest-nya, jadi tanda tangan (signature) dan deployment yang mengunci
  digest tetap berlaku. Layer yang sudah ada di tujuan dilewati; di dalam
  satu registry, layer ditautkan alih-alih disalin jika registry-nya
  mengizinkan (kalau tidak, disalin). Hanya tujuan yang berubah, jadi hanya
  tujuan yang protected yang butuh `--yes`. Hasilnya menyebut
  `"replaced": true` jika tag tujuan sebelumnya menunjuk ke image lain.

- `rm` menghapus image yang ditunjuk tag itu, jadi semua tag lain pada image
  yang sama ikut hilang. Ruang disk baru kembali setelah garbage collection
  registry berjalan.
- Conn registry yang protected juga butuh `--yes` untuk menghapus.
