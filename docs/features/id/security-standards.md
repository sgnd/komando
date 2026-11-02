# Standar keamanan

Seberapa jauh komando memenuhi standar keamanan internasional yang cocok untuk
alat DevOps yang menyimpan kredensial dan dijalankan oleh AI agent.
[Semua fitur](README.md) · [Keamanan](safety.md)

Ini penilaian sendiri, dicek ke kode dan tes, bukan sertifikat. Sertifikat
(ISO 27001, SOC 2) diberikan ke organisasi dan cara kerjanya; komando hanya
bisa memberi Anda kontrol untuk dipakai di dalamnya.

**Status:** ✅ terpenuhi · 🟡 sebagian (kekurangannya disebut) · 👤 tugas Anda

## OWASP ASVS 4.0.3

| Persyaratan | Cara komando memenuhinya | Status |
|---|---|---|
| 2.10, 6.4 Secret tidak ada di kode, argumen, atau riwayat | Vault, referensi `secret:NAME`, pengelola eksternal (1Password, HashiCorp Vault, AWS dan GCP Secret Manager); nilai secret di baris perintah ditolak | ✅ |
| 6.2 Algoritma yang diakui, bukan kripto buatan sendiri | AES-256-GCM (tiap nilai terikat ke namanya), scrypt N=2^17 r=8 p=1, `crypto/rand`, key Ed25519, SSH dan TLS dari Go | ✅ |
| 6.4.2 Material kunci dilindungi | File kunci dan vault mode 0600 di folder 0700; mode passphrase tidak menyimpan kunci di disk | 🟡 file kunci default ada di samping vault: pakai passphrase (`doctor` memperingatkan) |
| 7.1 Log mencatat siapa, apa, di mana, hasilnya, tanpa secret | Setiap tindakan: waktu, aktor, AI agent, persetujuan, host, perintah; dites tidak berisi password | ✅ |
| 7.3 Log dilindungi dari perubahan | 0600, dan rantai hash yang dicek `komando audit verify` | 🟡 user yang sama bisa membangun ulang rantainya atau memotong ujungnya: salin log ke luar komputer kalau itu penting |
| 8.3 Data sensitif tidak terlihat oleh yang tidak berhak | Nilai vault disembunyikan untuk semua; password, key dan token disembunyikan untuk AI agent | ✅ usaha terbaik: nama yang tidak biasa bisa lolos |
| 9.1, 9.2 Koneksi dienkripsi dan servernya dicek | Host key SSH (berhenti kalau beda), TLS 1.2+ untuk Redis, Kubernetes, FTPS; FTP polos butuh `?insecure=1` | 🟡 database mengikuti URL conn; `doctor` memperingatkan conn tanpa TLS yang diverifikasi |
| 12.3 File: tidak ada path traversal | Unduhan folder menolak path dari server yang keluar dari tujuan | ✅ |
| 14.2 Dependensi dikenal dan diperbarui | Modul Go, `govulncheck` di CI, Dependabot | ✅ |

## OWASP Top 10 untuk Aplikasi LLM (2025)

| Risiko | Cara komando memenuhinya | Status |
|---|---|---|
| LLM01 Prompt injection | Aturan agent: output server itu data, bukan perintah; tindakan berisiko butuh klik manusia, yang tidak bisa diberikan teks sisipan | 🟡 tidak ada alat yang bisa menghentikan injection itu sendiri, hanya membatasi jangkauannya |
| LLM02 Kebocoran informasi sensitif | Penyamaran untuk agent, `SENSITIVE_FILE`, penjaga Claude Code, `secret get --reveal` hanya untuk manusia | ✅ |
| LLM05 Penanganan output yang salah | Teks tersamar tidak pernah ditulis balik (`HIDDEN_VALUE`); setiap perintah dari agent melewati filter policy | ✅ |
| LLM06 Wewenang berlebihan | Default hanya membaca (`--read-only`, `--write`), target protected, manusia mengizinkan `--yes`, `--allow-dangerous` dan `--reveal`, log audit mencatat agent-nya | ✅ |
| LLM10 Konsumsi tak terbatas | Timeout, batas output per host, batas paralel, pekerjaan panjang sebagai job | ✅ |

## NIST

| Kontrol | Cara komando memenuhinya | Status |
|---|---|---|
| SP 800-63B Panjang passphrase | `doctor` memperingatkan di bawah 15 karakter | 🟡 diperingatkan, tidak dipaksa |
| SP 800-132 Penurunan kunci | scrypt dengan biaya yang disimpan; vault lama naik saat diubah berikutnya | ✅ |
| SP 800-53 AC-6 Hak minimum | AI agent default hanya membaca dan butuh manusia untuk lebih | ✅ · 👤 beri komando user SSH yang hanya punya izin yang dibutuhkan |
| SP 800-53 AU-2, AU-3, AU-9 Peristiwa, isi, dan perlindungan audit | Lihat ASVS 7 | 🟡 |
| SP 800-53 SC-8 Kerahasiaan transmisi | Lihat ASVS 9 | 🟡 |
| SP 800-53 SI-7 Integritas software | Checksum rilis dan provenance build yang ditandatangani | ✅ |
| SP 800-218 (SSDF) PS.3, PW.7, PW.8, RV.1 | Provenance, analisis statis (staticcheck, vet), tes unit, end-to-end dan fuzz, pemindaian kerentanan | ✅ |

## ISO/IEC 27001:2022 Annex A dan CIS Controls v8

komando memberi Anda kontrol untuk ini; sertifikatnya tentang organisasi Anda.

| Kontrol | Bagian komando |
|---|---|
| A.5.17 Informasi autentikasi · CIS 3.11 | Vault terenkripsi, referensi alih-alih nilai |
| A.8.2 Akses istimewa · CIS 5.4 | Target protected, jendela persetujuan, filter policy |
| A.8.5 Autentikasi yang aman | Key dan agent SSH, cek host key |
| A.8.15 Logging · CIS 8 | Log audit dengan rantai hash |
| A.8.24 Penggunaan kriptografi · CIS 3.10 | AES-256-GCM, scrypt, SSH, TLS 1.2+ |
| A.8.28 Secure coding · CIS 16 | Analisis statis, fuzzing, alat build yang dikunci versinya |

## Rantai pasok: OpenSSF Scorecard dan SLSA

| Cek | Status |
|---|---|
| Security-Policy (SECURITY.md, laporan privat) | ✅ |
| Token-Permissions (CI hanya membaca; rilis hanya menulis yang perlu) | ✅ |
| Pinned-Dependencies (action dikunci ke commit, alat ke versi) | ✅ |
| Dependency-Update-Tool (Dependabot) | ✅ |
| SAST dan Vulnerabilities (staticcheck, govulncheck) | ✅ |
| Fuzzing (penyamaran, filter policy, penjaga) | ✅ |
| Signed-Releases: provenance SLSA Build Level 2 | ✅ cek unduhan dengan `gh attestation verify komando_*.tar.gz --repo sgnd/komando` |
| Branch-Protection, Code-Review | 👤 nyalakan di GitHub: lindungi `main`, wajibkan review dan CI |

## Yang belum tercakup

- **AI agent adalah user Anda sendiri.** komando menghentikan kesalahan dan
  perintah sisipan; tidak bisa menghentikan program yang berjalan sebagai Anda
  dan berniat jahat. Isolasi sungguhan butuh sandbox OS atau akun user terpisah
  untuk agent.
- **Log audit tetap di komputer Anda.** Pengiriman ke server log belum ada.
- **Kunci vault belum di keychain OS atau kunci hardware.**
- **Jendela persetujuan cukup satu klik**, bukan faktor kedua.
- **Penjaga di komputer Anda khusus Claude Code.** Codex, Cursor dan Gemini
  CLI mendapat jendela persetujuan dan penyamaran, tapi tidak penjaganya.

## Cek sendiri

```bash
komando doctor          # keamanan: izin file, vault, rantai audit, conn tanpa enkripsi
komando audit verify    # tidak ada yang mengubah log audit
make security           # govulncheck + staticcheck (di source)
make fuzz               # fuzz parser yang membaca teks dari luar
```
