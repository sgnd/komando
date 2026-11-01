# Rancangan: jaringan — bastion, forwarding, dan banyak VPN sekaligus

Status: **rancangan, 2026-11-02.** Belum dibangun. Tujuan besarnya ada di
[vision.md](vision.md), aturan perintah di [ux.md](ux.md).

## Masalah

Satu laptop sering perlu menjangkau banyak project sekaligus:

- Project A: server di belakang bastion SSH.
- Project B: database di jaringan privat, hanya lewat WireGuard kantor.
- Project C: cluster di Tailscale milik klien.
- Project D: VPN perusahaan (OpenVPN, Cisco AnyConnect, FortiClient, GlobalProtect).

Dengan VPN biasa, VPN dipasang di level **sistem operasi**. Akibatnya:

1. Biasanya hanya satu VPN yang bisa aktif. Kita harus pindah-pindah VPN.
2. Dua VPN sering memakai subnet yang sama (`10.0.0.0/8`), jadi rutenya bentrok.
3. Semua lalu lintas laptop ikut berubah, bukan hanya yang untuk project itu.
4. Butuh hak admin, dan AI agent tidak bisa (dan tidak boleh) mengurusnya.

## Ide utama: jaringan per koneksi, di dalam proses komando

komando sudah melakukan ini untuk bastion: `--via web1` membuka SSH ke
`web1`, lalu menyambung ke database **dari dalam proses komando**. Tidak ada
port lokal yang terbuka dan tidak ada rute sistem yang berubah.

Ide yang sama diperluas ke VPN: komando menjalankan VPN **di dalam prosesnya
sendiri** (userspace), hanya untuk koneksi yang membutuhkannya, lalu
menutupnya saat perintah selesai.

```
komando db query app-db ...
   └─ app-db --via office-vpn,bastion
        ├─ WireGuard "office-vpn" (di dalam proses, tanpa mengubah rute laptop)
        └─ SSH ke "bastion" lewat VPN itu
             └─ TCP ke database dari bastion
```

Hasilnya:

- **Banyak VPN aktif sekaligus**, satu per target. Tidak perlu pindah-pindah.
- **Subnet yang bentrok tidak masalah**, karena tiap target punya jalurnya sendiri.
- **Tanpa hak admin**, tanpa mengubah jaringan laptop. Lalu lintas lain tidak terpengaruh.
- AI agent bisa memakainya dengan aman, karena kuncinya ada di vault.

## Satu konsep: `--via`

Hari ini ada dua flag untuk hal yang sama: `host --jump` dan `conn --via`.
Sesuai aturan "tidak ada fitur yang tumpang tindih", keduanya disatukan
menjadi **`--via`** untuk semua target. `--jump` tetap diterima sebagai
alias selama satu rilis.

`--via` berisi rantai jalur, dari laptop ke tujuan, dipisah koma:

```bash
komando host add db1 admin@10.0.0.5 --via bastion            # SSH bastion (sudah ada)
komando host add db1 admin@10.0.0.5 --via office-vpn         # lewat VPN
komando conn add app-db postgres://app@10.0.0.9/app --via office-vpn,bastion   # VPN, lalu bastion
```

Setiap langkah di rantai adalah sebuah host (bastion SSH) atau sebuah VPN.

## Perintah `komando vpn`

Kata benda baru dengan bahasa manusia: `vpn`. Bentuknya sama dengan `host`
dan `conn`, dan namanya berbagi ruang nama dengan keduanya. Semua selector,
`komando list`, dan `komando test` ikut bekerja dengannya.

```bash
komando vpn add office wireguard --config ~/Downloads/office.conf   # kunci privat masuk vault
komando vpn add client-x tailscale --auth-key-ref secret:client-x-ts
komando vpn add corp system --check 10.20.0.1:443                   # VPN yang dipasang di OS
komando vpn add lab socks --address 127.0.0.1:1080                  # proxy SOCKS5 yang sudah ada

komando vpn list
komando vpn test office            # bisa tersambung? alamat apa yang terjangkau?
komando vpn rm office
```

| Kind | Cara kerja | Butuh admin? | Banyak sekaligus? |
|---|---|---|---|
| `wireguard` | wireguard-go + netstack userspace, di dalam proses | tidak | ya |
| `tailscale` | `tsnet` (Tailscale/Headscale) userspace, di dalam proses | tidak | ya |
| `socks` | proxy SOCKS5/HTTP yang sudah berjalan | tidak | ya |
| `system` | VPN di OS (OpenVPN, AnyConnect, FortiClient, GlobalProtect, IPsec) | sesuai klien VPN-nya | sesuai OS |

### Kenapa `system` tidak dijalankan oleh komando

OpenVPN, AnyConnect, FortiClient, dan GlobalProtect tidak punya klien Go
murni yang matang, dan menjalankannya butuh hak admin serta mengubah rute
laptop. Itu bertentangan dengan "aman sebagai default" dan "satu biner pure
Go". Jadi untuk kind `system`, komando:

- mengecek apakah VPN itu sudah tersambung (`--check host:port`) sebelum
  memakai target yang membutuhkannya;
- kalau belum, gagal dengan `VPN_DOWN` dan hint yang jelas ("sambungkan VPN
  `corp` dulu"), bukan timeout yang membingungkan.

Kalau ada bastion yang bisa dijangkau lewat VPN itu, sarankan memakai
WireGuard/Tailscale atau bastion SSH, supaya tidak perlu pindah-pindah lagi.

## Forwarding untuk aplikasi di laptop

`--via` hanya untuk koneksi komando sendiri. Untuk aplikasi lain (TablePlus,
DBeaver, browser, `psql`), `komando tunnel` membuka port di laptop. Ini
diperluas supaya bisa memakai **nama target**, bukan alamat:

```bash
komando tunnel start app-db                 # localhost:<port> → app-db, lewat --via-nya
komando tunnel start app-db --local 15432   # pilih port lokal
komando tunnel start web1 -L 8080:localhost:80   # bentuk lama tetap jalan
komando tunnel start office -D 1080         # SOCKS lewat VPN: browser "di dalam" jaringan kantor
```

Tunnel berjalan di latar dan memegang jalurnya (VPN dan bastion) selama hidup.
`komando tunnel list` menunjukkan target, port lokal, dan jalurnya.

## Keamanan

- Kunci VPN (WireGuard private key, Tailscale auth key) **hanya di vault**.
  `vpn add --config` membaca file, memindahkan kuncinya ke vault, dan
  menyimpan sisanya tanpa kunci. File asli tidak diubah.
- Tunnel dan proxy hanya mendengarkan di `127.0.0.1`, kecuali diberi
  `--bind` (butuh `--yes`).
- Protected mengikuti alamat di dalam jaringan VPN yang sama (lihat
  `protectedHost`). Alamat yang sama di VPN yang berbeda adalah server yang
  berbeda.
- Audit mencatat jalur (`via`) setiap perintah.
- komando tidak pernah mengubah rute, DNS, atau firewall laptop.

## Edge case

- Dua VPN memakai subnet yang sama: aman, karena tiap target punya jalurnya sendiri.
- DNS di dalam VPN (`db.internal`): resolver userspace memakai DNS dari konfigurasi VPN.
- VPN putus di tengah perintah: error `VPN_DOWN` atau `TIMEOUT` dengan nama VPN-nya.
- Handshake WireGuard lambat di koneksi pertama: `--connect-timeout` berlaku untuk seluruh rantai.
- Rantai melingkar (`a --via b`, `b --via a`): ditolak saat `add`/`edit`.
- Menghapus VPN yang masih dipakai `--via`: ditolak (`IN_USE`), sama seperti host.
- MTU kecil di VPN bertumpuk: pakai MTU dari konfigurasi; bisa diubah per VPN.
- Ukuran biner: `tsnet` cukup besar. Kalau anggaran 40 MB terlewati, Tailscale
  ditunda atau diganti dengan `socks` lewat `tailscale serve`.

## Rencana bertahap

| Fase | Isi |
|---|---|
| 1 | `--via` untuk host (`--jump` jadi alias); `tunnel start TARGET` untuk conn; rantai melingkar dan `IN_USE` |
| 2 | `komando vpn` dengan kind `wireguard` dan `socks`; `vpn test`; masuk `list`/`test`/selector |
| 3 | kind `system` (`--check`, `VPN_DOWN`) |
| 4 | kind `tailscale` (kalau anggaran biner cukup) |
