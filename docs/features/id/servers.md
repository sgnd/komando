# Server

Menambahkan server, login dengan key atau password, dan menjaga daftarnya tetap rapi. [Semua fitur](README.md)

## Menambahkan server

```bash
komando host add web1 ubuntu@203.0.113.10                 # nama + user@alamat
komando host add web2 ubuntu@203.0.113.11 --group web --tag prod
komando host add db1 admin@10.0.0.5 --via bastion         # dijangkau lewat "bastion"
komando host import --ssh-config ~/.ssh/config             # impor yang sudah Anda punya
komando list                                          # lihat semuanya
komando test all                                      # bisa login ke semuanya?
```

Mengubah atau menghapus nanti:

```bash
komando host edit web1 --add-tag canary --port 2222
komando host edit web1 --protected        # produksi: perubahan butuh --yes
komando host rm web2
```

## Login tanpa mengetik password

Jika Anda sudah bisa login dengan `ssh` dari komputer ini, komando biasanya
langsung bisa: komando memakai key yang sama (file seperti
`~/.ssh/id_ed25519`, dan program ssh-agent yang menyimpan key yang sudah
dibuka). Kalau tidak, komando memakai password yang tersimpan.

**Simpan password dengan aman.** Anda mengetiknya, tidak ada yang tampil di layar, dan disimpan terenkripsi:

```bash
komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

**Lebih baik: pakai key.** Buat satu dan pasang di server Anda:

```bash
komando key gen deploy
komando key deploy deploy @web --set-default
```

Saat seseorang keluar, atau sebuah key diganti, hapus di semua server
sekaligus. Bisa memakai key dari keychain, file `.pub`, atau baris key-nya:

```bash
komando key revoke ~/keys/budi.pub @prod --dry-run   # berapa baris per server
komando key revoke ~/keys/budi.pub @prod
komando key revoke old-deploy @web --user deploy     # file milik user lain (sudo)
```

Mencabut key yang dipakai komando sendiri untuk login butuh `--allow-dangerous`.

**sudo butuh password?**

```bash
komando secret set web1-sudo
komando host edit web1 --sudo-ref secret:web1-sudo
```

Referensi juga bisa menunjuk ke environment variable (`env:MY_VAR`) atau
file (`file:/path`).

## Password dari password manager Anda

Setiap `--password-ref` (server, conn, VPN) bisa menunjuk ke password
manager yang sudah dipakai tim Anda, bukan ke vault milik komando sendiri:

| Referensi | Dibaca dengan |
|-----------|---------------|
| `secret:NAME` | vault komando (`komando secret set NAME`) |
| `env:VAR` | environment variable |
| `file:PATH` | sebuah file |
| `op://Vault/Item/field` | 1Password CLI (`op`) |
| `vault:secret/shop#db_password` | HashiCorp Vault CLI (`vault kv get`) |
| `aws-sm:shop/db#password` | AWS Secrets Manager (`aws`); `#key` memilih field JSON |
| `gcp-sm:db-pass@my-project` | Google Secret Manager (`gcloud`) |

```bash
komando conn add shop-db postgres://app@db.lan/shop --password-ref op://Shop/shop-db/password
```

komando menjalankan alat itu saat butuh password dan tidak pernah menyimpan
nilainya. Alat itu harus terpasang dan sudah login; login-nya (dan MFA
apa pun) tetap di tangan Anda.
