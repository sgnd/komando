# VPN

Menjangkau server dan database yang hanya bisa dijangkau lewat VPN, beberapa
VPN sekaligus, tanpa pindah-pindah. [Semua fitur](README.md)

## Tambahkan VPN sekali saja

```bash
komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
komando vpn add lab socks --address 127.0.0.1:1080
komando vpn add corp system --check 10.20.0.1:443
```

| Jenis | Apa itu | Butuh hak admin? | Bisa beberapa sekaligus? |
|-------|---------|------------------|--------------------------|
| `wireguard` | WireGuard, dijalankan di dalam komando | tidak | ya |
| `socks` | proxy SOCKS5 yang sudah berjalan (`komando tunnel start bastion -D 1080`, proxy kantor) | tidak | ya |
| `system` | VPN yang dijalankan komputer Anda sendiri; komando mengecek bahwa VPN itu tersambung sebelum memakainya | tergantung VPN-nya | tergantung VPN-nya |

- Private key WireGuard masuk ke vault. File `.conf` masih menyimpannya,
  jadi hapus file itu jika sudah tidak diperlukan.
- `--check host:port` adalah alamat yang hanya menjawab lewat VPN.
  `komando test office` memakainya.

## Memakainya

Taruh VPN di urutan pertama `--via`:

```bash
komando host add db1 admin@10.0.0.5 --via office              # server di dalam VPN
komando conn add app-db postgres://app@10.0.0.9/app --via office,bastion   # VPN, lalu bastion
komando exec db1 -- uptime                                    # menyambungkan VPN dengan sendirinya
komando tunnel start app-db                                   # untuk TablePlus, psql, ...
komando tunnel start office -D 1080                           # browsing "di dalam" VPN
```

VPN dibuka di dalam komando hanya untuk perintah itu. Jaringan, route, dan
DNS komputer Anda tidak berubah, dan dua VPN yang memakai alamat yang sama
(keduanya `10.0.0.0/8`) tidak saling mengganggu.

```bash
komando list kind:vpn
komando test kind:vpn
komando vpn show office          # apa saja yang memakainya
komando vpn rm office            # ditolak selama masih ada yang memakainya
```

Jika VPN `system` tidak tersambung, perintah yang membutuhkannya berhenti
dengan `VPN_DOWN` dan memberi tahu VPN mana yang harus disambungkan.

## Jenis lainnya

```bash
komando vpn add kantor openvpn --config kantor.ovpn --user budi --password-ref secret:kantor --check 10.8.0.1:22
komando vpn add client-x globalprotect --portal vpn.client.com --user budi --mfa
komando vpn add tailnet tailscale --password-ref secret:ts-authkey
komando vpn up client-x          # seseorang login (MFA); perintah berikutnya memakainya lagi
komando vpn status
komando vpn down --all
```

| Jenis | Cara jalannya | Jaringan komputer Anda berubah? |
|-------|---------------|---------------------------------|
| `openvpn` (dan `pritunl`) | di dalam container Docker kecil; komando menjangkaunya lewat port lokal | tidak |
| `openvpn --os-mode` | di komputer Anda, dengan sudo | ya |
| `globalprotect`, `fortinet`, `anyconnect`, `pulse`, `f5` | `openconnect` dengan `ocproxy` (`brew install openconnect ocproxy`) | tidak |
| `tailscale` | `tailscaled` dalam mode user-space | tidak |

VPN dengan `--mfa` butuh manusia: `komando vpn up NAME` meminta login, dan
perintah berikutnya (juga agent) memakai koneksi itu lagi. komando tidak
pernah menjawab MFA sendiri. Koneksi yang tidak dipakai selama 30 menit
ditutup (`komando config set vpn_idle 1h` untuk mengubahnya).
