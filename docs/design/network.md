# Rancangan: jaringan — bastion, forwarding, dan banyak VPN sekaligus

Status: **dibangun, 2026-11-02** (lihat [Rencana bertahap](#rencana-bertahap)). Sudah ada: `--via` untuk semua
target, `tunnel start TARGET`, dan `komando vpn` dengan kind `wireguard`,
`socks`, `system` (lihat [docs/features/vpn.md](../features/vpn.md)). Sisanya
rancangan. Tujuan besarnya ada di [vision.md](vision.md), aturan perintah di
[ux.md](ux.md).

**Klarifikasi pemilik (2026-11-02):** komando juga **pengelola klien VPN**.
VPN A bisa OpenVPN, B GlobalProtect, C Pritunl, D Fortinet, E L2TP, dan
seterusnya. Kredensialnya disimpan di komando (vault). Saat sebuah perintah
butuh target di balik VPN, komando **menyambungkan VPN itu sendiri**, lalu
menjangkau resource-nya. Contoh: `komando exec app -- uptime` → `app` butuh
`vpn-a` (OpenVPN) → sambungkan → SSH ke bastion → SSH ke app, dalam satu
perintah. Beberapa VPN bisa dibutuhkan bersamaan (app lewat VPN A, database
lewat VPN B).

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

`vpn` berbagi ruang nama dengan `host` dan `conn`; semua selector,
`komando list`, dan `komando test` ikut bekerja dengannya.

```bash
komando vpn add vpn-a openvpn --config kantor.ovpn --user budi --password-ref secret:vpn-a
komando vpn add vpn-b globalprotect --portal vpn.klien.com --user budi --password-ref secret:vpn-b
komando vpn add office wireguard --config ~/Downloads/office.conf     # sudah ada
komando vpn add lab socks --address 127.0.0.1:1080                    # sudah ada

komando host edit app --via vpn-a,bastion
komando conn edit app-db --via vpn-b
komando exec app -- uptime          # vpn-a tersambung sendiri, lalu bastion, lalu app

komando vpn up vpn-b                # sambungkan manual (mis. untuk login MFA)
komando vpn status                  # mana yang tersambung, sejak kapan, dipakai siapa
komando vpn down vpn-b
komando test kind:vpn
```

## Dua mode

| Mode | Kind | Cara kerja | Admin? | Banyak sekaligus? |
|---|---|---|---|---|
| **Userspace** | `wireguard` ✅ | wireguard-go + netstack di dalam proses | tidak | ya, subnet bentrok aman |
| | `socks` ✅ | proxy SOCKS5 yang sudah ada | tidak | ya |
| | `tailscale` | `tsnet` (Tailscale/Headscale) di dalam proses | tidak | ya |
| | `globalprotect`, `fortinet`, `anyconnect`, `pulse`, `f5` | `openconnect --protocol=… --script-tun` + `ocproxy`/`tunsocks`: klien berjalan di samping komando dan menyediakan SOCKS lokal, tanpa membuat interface jaringan | tidak | ya |
| **Mode OS** | `openvpn` (termasuk profil Pritunl) | evaluasi dulu klien Go userspace (`ooni/minivpn`, eksperimental); kalau tidak cukup, `openvpn` dijalankan oleh helper kecil | sekali (helper dipasang dengan sudo) | terbatas |
| | `l2tp` / IPsec | strongSwan + xl2tpd (Linux), VPN bawaan (macOS/Windows) | sekali | terbatas |
| | `system` ✅ | VPN yang sudah tersambung di komputer; komando hanya mengecek | sesuai kliennya | sesuai OS |

- Mode OS bisa bentrok kalau dua VPN memakai subnet yang sama. komando harus
  **mendeteksi dan memperingatkan** sebelum menyambung, bukan diam-diam
  merusak rute.
- Klien VPN (`openconnect`, `openvpn`, strongSwan) harus terpasang, kecuali
  WireGuard dan Tailscale yang ada di dalam komando. `komando doctor`
  mengecek klien yang dibutuhkan VPN yang terdaftar dan memberi cara
  memasangnya.

## Sesi VPN

- **Sambung otomatis.** Perintah yang `--via`-nya dimulai dengan VPN
  menyambungkannya kalau belum tersambung.
- **Satu sesi di latar per VPN** (seperti `tunnel`), dipakai bersama oleh
  perintah-perintah berikutnya supaya tidak login ulang setiap kali. Sesi
  diputus sendiri setelah tidak dipakai (default 30 menit, bisa diatur).
  WireGuard tetap bisa di dalam proses per perintah karena tidak ada login.
- `vpn up`, `vpn down`, `vpn status` untuk kendali manual.
- Audit mencatat kapan VPN tersambung dan diputus, oleh siapa, dan untuk
  perintah apa.

## MFA

Keputusan pemilik (2026-11-02): **MFA selalu dilakukan manusia.**

- komando **tidak** menyimpan secret TOTP dan **tidak** membuat kode MFA.
- Manusia menjalankan `komando vpn up NAME` (password + MFA, atau login SSO
  lewat browser). Agent dan perintah berikutnya memakai sesi itu.
- Kalau sesi habis, perintah agent gagal dengan `VPN_LOGIN_REQUIRED` dan hint
  "minta manusia menjalankan `komando vpn up NAME`". Agent tidak pernah
  menjawab MFA.
- VPN tanpa MFA (kunci WireGuard, OpenVPN yang hanya pakai password) tetap
  boleh tersambung otomatis saat dibutuhkan.

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

| Fase | Isi | Status |
|---|---|---|
| 0 | `--via` untuk semua target, `tunnel start TARGET`, `vpn add/show/rm`, kind `wireguard`/`socks`/`system`, VPN di `list`/`test`/selector | ✅ dites end-to-end |
| 1 | `vpn up/down/status`, sesi di latar per VPN dengan putus otomatis; kind `tailscale` | ✅ (tailscale belum dites dengan tailnet sungguhan) |
| 2 | Keluarga openconnect (GlobalProtect, Fortinet, AnyConnect, Pulse, F5) lewat `ocproxy`; `doctor` mengecek kliennya; `VPN_LOGIN_REQUIRED` untuk VPN dengan MFA | ✅ (belum dites dengan server VPN sungguhan) |
| 3 | OpenVPN/Pritunl di container Docker, tanpa mengubah jaringan laptop; `--os-mode` opsional | ✅ dites dengan server OpenVPN sungguhan (`make e2e-openvpn`) |
| 4 | L2TP/IPsec dan VPN bawaan OS lewat `system --service` (scutil/nmcli); peringatan subnet bentrok untuk OpenVPN mode OS | ✅ sebagian: deteksi bentrok yang lebih lengkap (membaca rute) belum |

## Keputusan pemilik

1. **Mode OS boleh** (2026-11-02): OpenVPN/Pritunl dan L2TP/IPsec boleh
   memakai helper kecil yang dipasang sekali dengan sudo.
2. **MFA selalu oleh manusia** (2026-11-02): tidak ada secret TOTP di vault;
   lihat bagian [MFA](#mfa).
