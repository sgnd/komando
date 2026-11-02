# Gap analysis: object storage, file server, dan container registry

Dasar: commit `4784fc9` (branch `feat/v0.3`), biner `bin/komando`, kode
`internal/cli/storage.go`, `transfer.go`, `cp.go`, `registry.go`,
`registrycopy.go`, `internal/storex/{storex,ftp,sftp}.go`,
`internal/registry/{registry,copy}.go`, `internal/driver/driver.go`,
`internal/cli/importer.go`, docs `docs/features/{storage,registry,files}.md`,
`docs/design/{vision,ux}.md`. Tidak ada server yang dihubungi.

## Ringkasan perintah yang ada sekarang

| Area | Perintah | Catatan |
|---|---|---|
| storage | `storage ls CONN [PREFIX] [-r] [-n]`, `storage download CONN KEY [--to]` (= `download`), `storage upload CONN FILE [KEY]` (= `upload`), `storage rm CONN KEY... --allow-dangerous`, `storage link CONN KEY [--expires ≤168h]` (alias `presign`, `share`) | Kind: `s3` (minio-go v7, URL opsi hanya `endpoint`, `region`), `ftp` (`?insecure=1`), `ftps` (explicit TLS, `?tls=skip-verify`), `sftp` (lewat sshx, host key dicek). Satu conn = satu bucket + prefix; key tidak boleh keluar folder (`..` ditolak). |
| host files | `cp`, `upload`/`download` ke host (SFTP, `-r`, `--sudo`, `-p`, `--mode`, fan-out `@group`, sha256 untuk 1 file), `fs ls/stat --sha256/cat/write/replace/rm/mkdir/mv/chmod` | `cp` remote-ke-remote ditolak ("download then upload"). `cp` ke conn storage ditolak (`NO_MATCHING_TARGETS`, hint ke `storage`). |
| registry | `registry ls CONN [REPO] [-n]`, `registry inspect CONN REPO[:TAG\|@DIGEST]`, `registry copy SRC:IMG DST:[IMG]` (alias `cp`), `registry rm CONN IMG --allow-dangerous` | OCI Distribution API langsung, basic + bearer token, `?tls=false`, `--via`/VPN. Import `docker` (config.json + credential helper). |
| host docker | `docker pull`, `docker images`, `docker raw ...` (push/tag/login/save/load/buildx lewat raw di host) | Jalur mentah di host SSH. |

Legenda status: **ADA**, **SEBAGIAN**, **TIDAK ADA**, **NON-GOAL** (dengan kutipan
`vision.md`). Prioritas: **P1** kebutuhan harian / keamanan / penghambat agent,
**P2** berguna dan sering, **P3** jarang atau niche.

Kutipan non-goal yang dipakai (vision.md, "Bukan tujuan"):
- NG-a: "Mengganti alat lengkap (`psql`, `kubectl`, `terraform`, `helm`). komando menangani 80% pekerjaan harian dengan aman."
- NG-b: "Infrastructure as Code, provisioning cloud, atau GitOps."
- NG-c: "GUI, TUI, sistem plugin, atau daemon/server. komando tetap CLI murni."
- NG-d: "Monitoring atau alerting yang berjalan terus-menerus."
- Aturan teknis: "Tanpa pool dan tanpa daemon", "Pure Go, tanpa cgo". (Batas ukuran biner 40 MB sudah dihapus pemilik.)

---

## A. Storage: transfer dasar objek / file

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| List satu level (folder sebagai prefix) | `aws s3 ls`, `mc ls`, `rclone lsf`, `s3cmd ls`, `gsutil ls`, `lftp ls` | ADA | `storage ls CONN [PREFIX]`, DIR untuk prefix | - |
| List rekursif | `aws s3 ls --recursive`, `mc ls -r`, `rclone ls` | ADA | `storage ls -r`, `--limit` (default 1000) + `more:true` | - |
| Pagination / lanjut dari token (`--starting-token`, `--start-after`) | `aws s3api list-objects-v2`, `mc ls` | TIDAK ADA | Hanya `--limit`; daftar >limit tidak bisa dilanjutkan, hanya "narrow the prefix". Bucket besar tidak bisa dibaca habis oleh agent | P2 — agent tidak bisa iterasi bucket besar |
| Ringkasan total ukuran/jumlah (`--summarize`, `du`, `size`) | `aws s3 ls --summarize --human-readable`, `mc du`, `rclone size`, `gsutil du -s` | TIDAK ADA | `ls` hanya `count`; tidak ada total byte. Workaround: `ls -r -o json` + jumlahkan sendiri | P2 — cek kapasitas backup sering |
| Tree | `mc tree`, `rclone tree` | TIDAK ADA | | P3 |
| Download satu objek | `aws s3 cp s3://.. .`, `mc cp`, `rclone copy`, `s3cmd get`, `gsutil cp`, `azcopy copy`, `lftp get`, `curl ftp://` | ADA | `download CONN KEY [--to]` (alias `storage download`), atomik, tidak menimpa file (`FILE_EXISTS`), mode 0600 | - |
| Download folder/prefix rekursif | `aws s3 cp --recursive`, `mc cp -r`, `rclone copy`, `lftp mirror`, `s3cmd get -r`, `azcopy --recursive` | TIDAK ADA | `download -r` ke storage ditolak: "-r is for servers; storage downloads one object" (`transfer.go`) | **P1** — restore backup/folder situs harian; agent harus loop per key |
| Upload satu file | `aws s3 cp`, `mc cp`, `rclone copyto`, `s3cmd put`, `lftp put`, `curl -T` | ADA | `upload CONN FILE [KEY]`, `replaced:true`, content-type dari ekstensi; FTP/SFTP lewat nama sementara lalu rename | - |
| Upload folder rekursif | `aws s3 cp --recursive`, `mc cp -r`, `rclone copy`, `lftp mirror -R`, `azcopy`, `s3cmd put -r` | TIDAK ADA | `upload` ke storage menolak `-r`: "storage takes one file"; `storageUpload` menolak direktori | **P1** — deploy situs ke FTPS/S3 static hosting, upload folder backup |
| Upload dari stdin / download ke stdout (stream, pipe) | `aws s3 cp - s3://..`, `aws s3 cp s3://.. -`, `mc pipe`, `mc cat`, `rclone rcat`/`cat`, `gsutil cat` | TIDAK ADA | `upload` butuh file reguler (`os.Stat` + `!IsDir`); `--to -` akan membuat file bernama `-` | P2 — `db dump \| upload` tanpa file sementara |
| Baca isi objek di terminal (`cat` dengan head/tail/limit) | `mc cat`, `mc head`, `rclone cat --head/--tail`, `gsutil cat -r`, `aws s3 cp .. -` | TIDAK ADA | Ada `fs cat --head/--tail` untuk host, tidak ada `storage cat`. Agent harus download ke file lalu baca | **P1** — pola agent (baca log/konfig di bucket/FTP) sama seperti `fs cat` |
| Stat/head satu objek (ukuran, ETag, content-type, metadata, version-id, storage class) | `aws s3api head-object`, `mc stat`, `rclone lsjson --stat`, `gsutil stat`, `s3cmd info` | TIDAK ADA | Hanya `Exists()` internal; `ls` memberi size+modified | P2 — verifikasi upload/backup |
| Verifikasi checksum (MD5/ETag/sha256) | `rclone check`, `rclone md5sum/hashsum`, `aws s3api --checksum-algorithm`, `gsutil hash`, `fs stat --sha256` | SEBAGIAN | Host: `cp` laporkan sha256 (1 file), `fs stat --sha256`. Storage: tidak ada hash di hasil `upload`/`download` | P2 — integritas backup |
| Multipart upload untuk file besar | `aws s3 cp` (otomatis), `aws s3api create-multipart-upload`, `mc cp`, `rclone --s3-chunk-size` | ADA (implisit) | minio-go `PutObject` otomatis multipart bila ukuran diketahui (>16 MiB). Tidak ada pengaturan part size/concurrency; tidak ada `abort`/list upload yatim | P3 (pengaturan) |
| Bersihkan multipart upload yatim | `aws s3api list-multipart-uploads/abort-multipart-upload`, `mc rm --incomplete` | TIDAK ADA | | P3 |
| Resume transfer terputus | `rclone` (retry), `lftp get -c`, `curl -C -`, `rsync --partial`, `azcopy jobs resume` | TIDAK ADA | Gagal = ulang dari awal; S3 `MaxRetry = 2` | P2 — file besar lewat VPN/bastion |
| Progress bar / laju transfer di stderr | `aws s3 cp` (progress), `mc`, `rclone -P`, `azcopy` | TIDAK ADA | ux.md edge case: "file sangat besar (progress di stderr)" belum dibuat | P2 — manusia menunggu tanpa umpan balik |
| Transfer paralel (banyak file sekaligus) | `aws s3 --max-concurrent-requests`, `rclone --transfers`, `lftp mirror -P`, `azcopy` | TIDAK ADA (storage) | Host `upload @group` paralel per host; storage hanya 1 objek per perintah | P2 (bergantung pada recursive/sync) |
| Bandwidth limit | `rclone --bwlimit`, `aws s3 --max-bandwidth`, `lftp net:limit-rate`, `rsync --bwlimit` | TIDAK ADA | | P3 |
| Transfer lama di latar belakang | `azcopy jobs`, `rclone rc`/`--daemon` | TIDAK ADA | `job start` hanya di host remote; storage jalan di laptop dan perintah harus menunggu sampai selesai (batas waktu hanya bila `--timeout` diberi, tanpa default untuk storage). Workaround: `job start` di host yang punya `aws`/`rclone` | P2 |
| Hapus objek tepat | `aws s3 rm`, `mc rm`, `rclone deletefile`, `s3cmd del`, `lftp rm` | ADA | `storage rm CONN KEY... --allow-dangerous`; protected butuh `--yes`; sebagian gagal melaporkan `already deleted` | - |
| Hapus prefix/folder rekursif, pola, atau berdasarkan umur (`--older-than`) | `aws s3 rm --recursive --exclude/--include`, `mc rm -r --older-than`, `rclone delete --min-age`, `rclone purge`, `s3cmd del -r`, `lftp rm -r` | TIDAK ADA (sengaja) | `rm` menolak `/` di akhir dan `*?`: "rm takes exact keys". Pembersihan backup lama harus `ls` + daftar key manual | **P1** — retensi backup harian; perlu versi aman: preview jumlah/daftar di `--dry-run`, `--allow-dangerous`, batas maksimum |
| Dry-run untuk perubahan | `aws s3 --dryrun`, `rclone --dry-run`, `mc mirror --dry-run`, `rsync -n` | SEBAGIAN | `--dry-run` di `upload`/`rm`/`link` hanya "nothing sent: the change would be allowed"; tidak cek apakah key ada / akan ditimpa / berapa byte | P2 — dry-run jujur untuk sync/rm massal |
| Include/exclude/glob filter | `aws s3 --include/--exclude`, `rclone --include/--exclude/--filter`, `mc --exclude`, `rsync --exclude`, `lftp mirror -x` | TIDAK ADA | Hanya prefix | P2 (wajib saat sync/recursive dibuat) |
| Cari objek (nama, umur, ukuran) | `mc find --name --older-than --larger`, `rclone lsf --min-age`, `gsutil ls` wildcard | TIDAK ADA | Workaround: `ls -r -o json` + filter di sisi agent | P2 |
| Rename/move objek | `aws s3 mv`, `mc mv`, `rclone moveto`, `s3cmd mv`, `lftp mv`, `sftp rename` | TIDAK ADA | Host punya `fs mv`; storage tidak | P2 — hosting FTP sering perlu rename |
| Copy server-side di dalam/antar bucket | `aws s3 cp s3://a s3://b`, `mc cp`, `rclone copy` (server-side), `gsutil cp gs://..` | TIDAK ADA | | P2 |
| Copy antar conn/area (bucket↔bucket, host↔bucket, FTP→S3) tanpa lewat disk laptop | `rclone copy a: b:`, `mc mirror`, `aws s3 cp` di server | TIDAK ADA | `cp` menolak remote-ke-remote; `registry copy` punya pola `CONN:PATH` tapi storage tidak. Workaround: download lalu upload, atau `exec` `aws`/`rclone` di host | P2 — backup server ke S3 tanpa kredensial di server |
| Buat folder kosong | `mc mb` (folder), `rclone mkdir`, `lftp mkdir`, `sftp mkdir` | SEBAGIAN | Folder dibuat otomatis saat upload (FTP/SFTP); tidak ada `storage mkdir` | P3 |
| chmod/chown di file server (hosting) | `lftp chmod`, `sftp chmod`, `curl -Q "SITE CHMOD"` | TIDAK ADA | `fs chmod` hanya host SSH; conn sftp/ftp tanpa shell tidak bisa | P2 — izin 644/755 di hosting umum |
| Symlink, info owner/permission di listing | `lftp ls -l`, `sftp ls -l`, `rclone --links` | TIDAK ADA | `Object` hanya key/size/modified/dir | P3 |

## B. Storage: sinkronisasi dan perbandingan

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Sync satu arah folder lokal ↔ bucket/FTP (`--delete` opsional) | `aws s3 sync [--delete]`, `mc mirror [--remove]`, `rclone sync`, `rclone copy`, `s3cmd sync`, `gsutil rsync`, `azcopy sync`, `lftp mirror [-R] [--delete]`, `rsync -a --delete` | TIDAK ADA | vision.md menjanjikan verb `sync` untuk storage ("`ls/get/put/rm/sync`") dan tabel verb `dump/restore/sync`; belum dibuat | **P1** — deploy situs, backup folder, mirror; inti "80% harian" |
| Sync folder ke host SSH (rsync-like, delta) | `rsync -az --delete`, `lftp mirror` di sftp | SEBAGIAN | `upload -r` menyalin semua file tiap kali (tanpa delta/hapus); `fs write --if-changed` hanya 1 file. Workaround: `exec` rsync antar server | P2 (P1 bila sync storage dibuat, satu verb untuk keduanya) |
| Sync dua arah | `rclone bisync`, `unison` | TIDAK ADA | | P3 — rawan konflik, bukan pola devops harian |
| Mirror bucket ke bucket (antar provider) | `mc mirror`, `rclone sync a: b:`, `aws s3 sync s3:// s3://` | TIDAK ADA | | P2 |
| Watch/continuous mirror | `mc mirror --watch`, `mc watch`, `rclone` + cron | NON-GOAL | NG-c "daemon/server" dan NG-d "berjalan terus-menerus". Workaround: `cron set` di host | - |
| Bandingkan isi (diff/check) | `rclone check`, `mc diff`, `rclone cryptcheck`, `rsync -n -i` | TIDAK ADA | | P2 — verifikasi backup/deploy |
| Dedupe | `rclone dedupe` | TIDAK ADA | Khusus Google Drive (nama ganda) | P3 |
| Mode `--size-only`/`--checksum`/`--update` | `rclone`, `aws s3 sync --size-only --exact-timestamps`, `rsync -c/-u` | TIDAK ADA | Bagian dari desain sync | P2 (ikut sync) |

## C. Storage: berbagi dan akses

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Presigned download URL | `aws s3 presign`, `mc share download`, `rclone link`, `gsutil signurl`, `az storage blob generate-sas` | ADA | `storage link --expires` (maks 168h), risk write, protected butuh `--yes`, URL tidak masuk audit, `content-disposition: attachment` | - |
| Presigned upload URL (PUT/POST) | `mc share upload`, `aws s3api` presign put, SAS write | TIDAK ADA | | P3 |
| Link publik permanen (objek publik) | `aws s3api put-object-acl --acl public-read`, `mc anonymous set` | TIDAK ADA | Juga lihat ACL/policy (NON-GOAL di bawah) | P3 |
| Link untuk FTP/SFTP | (tidak lazim) | TIDAK ADA (tidak relevan) | Bukan non-goal di vision.md (tidak ada di "Bukan tujuan"); protokol FTP/SFTP memang tidak punya link sementara. `noLinks` menolak dengan jujur: "FTP/SFTP servers have no temporary download links" | P3 |
| Batasi conn ke prefix | IAM policy, `rclone` remote dengan path | ADA | Folder di URL conn, `keyIn` menolak `..` | - |

## D. Storage: fitur S3 lanjutan (objek)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Content-Type saat upload | `aws s3 cp --content-type`, `mc cp --attr` | SEBAGIAN | Otomatis dari ekstensi (`mime.TypeByExtension`); tidak bisa diatur | P3 |
| Cache-Control, Content-Encoding, metadata kustom | `aws s3 cp --cache-control --metadata`, `mc cp --attr`, `rclone --header-upload`, `gsutil setmeta` | TIDAK ADA | | P3 (P2 untuk situs statis) |
| Storage class (STANDARD_IA, GLACIER, ...) | `aws s3 cp --storage-class`, `mc cp --storage-class`, `rclone --s3-storage-class` | TIDAK ADA | | P3 |
| Restore dari Glacier/arsip | `aws s3api restore-object`, `rclone backend restore` | TIDAK ADA | | P3 |
| Enkripsi server-side SSE-KMS / SSE-C per objek | `aws s3 cp --sse aws:kms --sse-kms-key-id`, `--sse-c`, `mc --enc-kms` | TIDAK ADA | SSE-S3 default bucket tetap berlaku di sisi server | P3 |
| Enkripsi sisi klien | `rclone crypt` | TIDAK ADA | | P3 |
| Object tagging | `aws s3api put-object-tagging`, `mc tag` | TIDAK ADA | | P3 |
| ACL objek | `aws s3api put-object-acl`, `s3cmd setacl`, `gsutil acl` | TIDAK ADA | | P3 |
| Versioning: daftar versi, unduh versi lama, undelete (hapus delete marker) | `aws s3api list-object-versions`, `mc ls --versions`, `mc undo`, `mc cp --version-id`, `rclone --s3-versions` | TIDAK ADA | ux.md edge case menyebut "bucket dengan versioning (delete marker)"; `rm` tidak memberi tahu bahwa objek masih bisa dipulihkan | P2 — pemulihan setelah salah hapus/timpa (keamanan) |
| Object lock: retention, legal hold | `mc retention`, `mc legalhold`, `aws s3api put-object-retention` | TIDAK ADA | | P3 |
| Requester pays, transfer acceleration, dual-stack | `aws s3 --request-payer`, `s3-accelerate` | TIDAK ADA | | P3 |
| S3 Select / query objek | `aws s3api select-object-content`, `mc sql` | TIDAK ADA | | P3 |

## E. Storage: bucket dan administrasi

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Daftar bucket di akun/endpoint | `aws s3 ls`, `mc ls alias`, `rclone lsd remote:`, `gsutil ls` | TIDAK ADA | Conn wajib bucket ("s3 URL needs a bucket"). Untuk penemuan: satu conn per bucket | P2 — orientasi awal ("bucket apa saja?") |
| Buat/hapus bucket (`mb`/`rb`) | `aws s3 mb/rb`, `mc mb/rb`, `s3cmd mb`, `gsutil mb`, `rclone mkdir/rmdir` | NON-GOAL (sebagian) | NG-b "provisioning cloud". `mb` di MinIO lokal kadang harian; bisa P3 bila diminta | P3 |
| Bucket policy, CORS, lifecycle, replication, notification, website, encryption default, ownership | `aws s3api put-bucket-*`, `mc ilm`, `mc anonymous`, `mc replicate`, `mc event`, `gsutil cors/lifecycle` | NON-GOAL (ubah) / TIDAK ADA (baca) | NG-b "Infrastructure as Code, provisioning cloud" — konfigurasi bucket milik terraform. Membaca (mis. `storage info` menampilkan versioning/lifecycle/policy) belum ada | P3 (baca saja) |
| Versioning on/off di bucket | `aws s3api put-bucket-versioning`, `mc version enable` | NON-GOAL | NG-b | - |
| Info bucket (region, versioning aktif, object lock, ukuran) | `mc stat alias/bucket`, `aws s3api get-bucket-*`, `gsutil ls -L -b` | TIDAK ADA | `komando test` hanya cek bisa dihubungi | P3 |
| Admin MinIO (user, policy, heal, info server, quota) | `mc admin ...` | NON-GOAL (sebagian) | NG-a (mengganti alat lengkap). `mc admin info` (health) bisa P3 | P3 |
| Mount sebagai filesystem | `rclone mount`, `s3fs`, `mc` (tidak) | NON-GOAL | NG-c "daemon/server"; FUSE juga butuh komponen OS/cgo | - |
| Serve (HTTP/WebDAV/SFTP/S3 dari remote) | `rclone serve`, `mc` | NON-GOAL | NG-c "daemon/server" | - |
| Analisis pemakaian interaktif | `rclone ncdu` | NON-GOAL | NG-c "TUI" (keputusan #5: "Tidak. CLI murni"); versi non-interaktif = `du` (bagian A) | - |

## F. Storage: backend / protokol

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| AWS S3 | `aws s3`, `mc`, `rclone`, `s3cmd` | ADA | `s3://KEY@bucket/prefix?region=` (endpoint default AWS) | - |
| S3-kompatibel: MinIO, R2, Wasabi, Spaces, Backblaze B2 (S3 API), Garage, Ceph RGW | `mc`, `rclone`, `aws --endpoint-url` | ADA | `?endpoint=https://...`; dites e2e dengan Garage (`test/e2e/run.sh`, `test/e2e/garage/`), bukan MinIO | - |
| Path-style vs virtual-host diatur eksplisit | `aws configure set s3.addressing_style`, `mc --path`, `rclone force_path_style` | SEBAGIAN | minio-go BucketLookupAuto; tidak ada opsi URL (`path_style` ditolak: "known: endpoint, region") | P3 |
| Self-signed TLS untuk endpoint S3 (MinIO internal) | `mc --insecure`, `aws --no-verify-ssl`, `rclone --no-check-certificate` | TIDAK ADA | Tidak ada `tls=skip-verify`/CA kustom untuk s3 (ada untuk ftps). Workaround: endpoint `http://` lewat `--via` | P2 — MinIO on-prem dengan CA internal umum |
| Google Cloud Storage native (service account, OAuth) | `gsutil`, `gcloud storage`, `rclone gcs` | SEBAGIAN | Lewat S3 interop (HMAC key, endpoint `https://storage.googleapis.com`) kemungkinan jalan; tanpa service-account JSON. vision: "nanti: gcs" | P2 |
| Azure Blob Storage | `az storage blob`, `azcopy`, `rclone azureblob` | TIDAK ADA | vision: "nanti: ... azblob"; perlu client REST ringan (SharedKey/SAS), bukan SDK penuh (ukuran biner tidak lagi dibatasi, tapi client ringan tetap lebih sederhana) | P2 |
| WebDAV (Nextcloud, ownCloud, hosting) | `rclone webdav`, `curl`, `cadaver` | TIDAK ADA | vision: "nanti: webdav" | P2 |
| SFTP (akun tanpa shell) | `sftp`, `lftp sftp://`, `rclone sftp` | ADA | `sftp://` sebagai conn storage, host key dicek, key/agent/password, `--via` | - |
| FTPS explicit (AUTH TLS) | `lftp`, `curl --ssl-reqd`, `ncftp` | ADA | `ftps://`, TLS 1.2+, session resume, `?tls=skip-verify` | - |
| FTPS implicit (port 990) | `lftp ftps://`, `curl ftps://` | TIDAK ADA | Hanya `DialWithExplicitTLS` | P3 — masih dipakai hosting lama |
| FTP polos | `lftp`, `ncftp`, `curl ftp://` | ADA | Ditolak tanpa `?insecure=1` (aman default) | - |
| FTP active mode / opsi passive (EPSV off) | `lftp set ftp:passive-mode`, `curl --ftp-port` | TIDAK ADA | Hanya passive bawaan library | P3 |
| SMB/CIFS | `smbclient`, `rclone smb` | TIDAK ADA | | P3 |
| Google Drive, Dropbox, OneDrive, Box | `rclone` | TIDAK ADA | Butuh OAuth interaktif; bukan devops harian | P3 |
| OpenStack Swift, HDFS, HTTP index, dll. (70+ backend rclone) | `rclone` | TIDAK ADA | Workaround: `exec` rclone di host | P3 |

## G. Storage: kredensial, import, keamanan

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Access key statis + secret di vault | `aws configure`, `mc alias set`, `rclone config` | ADA | User = access key ID di URL, secret lewat `--password-ref` (vault/env/file/op/vault/aws-sm/gcp-sm) | - |
| Kredensial sementara: session token, AWS profile/SSO, AssumeRole, credential_process, IMDS | `aws sso login`, `aws --profile`, `AWS_SESSION_TOKEN`, `rclone env_auth` | TIDAK ADA | `credentials.NewStaticV4(t.User, secret, "")` — token selalu kosong | **P1** — banyak organisasi AWS melarang key permanen; tanpa ini storage tidak bisa dipakai di sana |
| Import `~/.aws/config` + `credentials` | `aws` | TIDAK ADA | Direncanakan di vision.md tabel migrasi (`aws`), tidak ada di `importSources` | P2 |
| Import rclone remote S3/FTP/WebDAV | `rclone.conf` | SEBAGIAN | `importRclone` hanya `sftp`; tipe lain dicatat "is not imported" (kunci S3 di rclone tidak di-obscure, jadi bisa diimpor) | P2 |
| Import FileZilla FTP/FTPS | `sitemanager.xml` | SEBAGIAN | `importFileZilla` hanya Protocol 1 (SFTP); FTP/FTPS dilewati | P2 — FileZilla paling umum untuk FTP hosting |
| Import `mc` alias (`~/.mc/config.json`), `.s3cfg` | `mc`, `s3cmd` | TIDAK ADA | | P3 |
| Import S3 URL dari `.env` | `.env` | ADA | `import env` mengenali `s3://` | - |
| Lewat bastion / VPN | `aws` + proxy, `rclone` + ssh tunnel | ADA | `--via` untuk s3 (Transport.DialContext), ftp (data conn juga), sftp (sshx) | - |
| Protected conn, `--yes`, `--allow-dangerous`, audit | (tidak ada di alat lain) | ADA | `withStorage` → `guardConns`, audit tanpa secret untuk semua perintah storage (termasuk `ls`/`download`) | - |
| Read-only ditegakkan server | IAM key read-only | SEBAGIAN | Dianjurkan di docs ("access key that can only do what you need"); komando sendiri tidak membedakan key read/write per conn | P3 |
| Unduhan tidak menimpa, atomik, mode 0600 | `aws s3 cp` (menimpa), `rclone` (menimpa) | ADA | Lebih aman dari pembanding | - |
| Upload tidak sengaja menimpa (`--no-clobber`/`--if-none-match`) | `rclone --ignore-existing`, `aws s3api put-object --if-none-match`, `mc cp --disable-multipart` | SEBAGIAN | `replaced:true` dilaporkan sesudahnya; tidak ada opsi menolak bila sudah ada | P2 — agent menimpa backup tanpa sadar |

---

## H. Registry: membaca

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Daftar repository (catalog) | `crane catalog`, `regctl repo ls`, `skopeo` (tidak), Harbor API | SEBAGIAN | `registry ls CONN`; **`Catalog()` tidak mengikuti header `Link`** (hanya `n=limit` satu halaman), sedangkan `Tags()` mengikutinya. Registry yang membatasi `n` (Harbor/GitLab/registry:2 dengan batas) mengembalikan daftar terpotong tanpa `more` | **P1** — hasil diam-diam tidak lengkap (agent salah menyimpulkan) |
| Daftar tag | `crane ls`, `skopeo list-tags`, `regctl tag ls`, `docker` (tidak) | ADA | `registry ls CONN REPO` dengan pagination `Link`, `--limit` | - |
| Daftar tag dengan digest/tanggal, urut/semver, filter | `regctl tag ls` + `--include`, Harbor/ECR `describe-images`, `crane ls --full-ref` | TIDAK ADA | Hanya nama tag; perlu `inspect` per tag | P2 — dasar untuk pembersihan |
| Inspect image: digest, ukuran, platform, created, label | `skopeo inspect`, `crane manifest`/`config`, `regctl image inspect`, `docker buildx imagetools inspect`, `docker manifest inspect` | ADA | `registry inspect CONN REPO[:TAG\|@DIGEST]` | - |
| Digest saja | `crane digest`, `regctl image digest`, `skopeo inspect --format {{.Digest}}` | ADA | Field `digest` di `inspect` | - |
| Config lengkap (Env, Entrypoint, Cmd, ExposedPorts, User, WorkingDir) | `crane config`, `skopeo inspect --config`, `regctl image config` | TIDAK ADA | `Inspect` hanya ambil `created`, `os/arch`, `Labels` | P2 — agent perlu port/env untuk deploy |
| Manifest mentah (JSON) | `crane manifest`, `regctl manifest get --format raw`, `skopeo inspect --raw` | TIDAK ADA | | P2 — debugging dan jalur "fitur CLI asli" |
| Inspect per platform (`--platform linux/arm64`) | `crane --platform`, `skopeo --override-arch`, `regctl --platform` | TIDAK ADA | Untuk index hanya daftar platform; ukuran/label tidak per platform | P2 |
| Layer & history (perintah tiap layer, ukuran per layer) | `dive`, `crane config` (history), `regctl image config` | TIDAK ADA | Hanya jumlah layer + total ukuran | P3 (dive interaktif = NON-GOAL, NG-c "TUI") |
| Ambil blob/file dari image tanpa pull (`crane export`, `regctl blob get`, `crane blob`) | `crane export`, `regctl blob get`, `regctl image get-file` | TIDAK ADA | | P3 |
| Daftar manifest tanpa tag (untagged) | Harbor/ECR API, `regctl` (tidak langsung) | TIDAK ADA | Distribution API tidak punya endpoint standar | P3 |
| Referrers (signature, SBOM, attestation terlampir) | `oras discover`, `regctl artifact tree`, `cosign tree` | TIDAK ADA | Atestasi di index dilewati (`platform.os == "unknown"`) | P3 |
| Cek rate limit Docker Hub | `curl` header `ratelimit-remaining`, `regctl` | TIDAK ADA | ux.md edge case menyebut "rate limit Docker Hub" | P3 |
| Cek login/akses | `docker login`, `crane auth`, `skopeo login` | SEBAGIAN | `komando test CONN` / `conn test` hanya membuka koneksi TCP ke registry (`testConn`, `Check = "tcp"`), tidak login. Password/token yang salah baru ketahuan saat `registry ls`/`inspect` | P2 — agent mengira conn sehat padahal token kedaluwarsa (lihat juga ECR 12 jam) |

## I. Registry: menulis dan menyalin

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Copy image antar registry (semua platform, digest tetap) | `crane copy`, `skopeo copy --all`, `regctl image copy`, `oras copy` | ADA | `registry copy SRC:IMG DST:[IMG]`; layer yang ada dilewati, mount di registry sama, `replaced:true`, protected tujuan butuh `--yes`, `--dry-run` | - |
| Retag di registry yang sama | `crane tag`, `regctl image copy`, `docker buildx imagetools create -t` | ADA | `registry copy reg:app:latest reg:app:stable` (manifest saja; blob di-mount) | - |
| Copy hanya platform tertentu | `skopeo copy --override-arch`, `crane copy --platform` | TIDAK ADA | Selalu semua platform | P3 |
| Copy semua tag / sync repo atau daftar image | `skopeo sync`, `regctl image copy` loop, `crane copy --all-tags` | TIDAK ADA | Satu image per perintah | P2 — migrasi registry, mirror ke registry internal |
| Copy ikut signature/SBOM (referrers, tag `sha256-*.sig`) | `cosign copy`, `oras copy -r`, `regctl image copy --referrers` | TIDAK ADA | Digest tetap sehingga signature tetap valid, tetapi artefak signature tidak ikut disalin | P2 — verifikasi gagal di registry tujuan |
| Push image dari laptop (tarball/OCI layout/daemon lokal) | `docker push`, `crane push`, `skopeo copy docker-archive:/oci:`, `oras push` | TIDAK ADA | Di host: `docker raw push` (jalur mentah). Dari laptop tidak ada | P3 — build/push milik CI |
| Pull/export ke tarball atau OCI layout | `crane pull --format`, `skopeo copy ... docker-archive:`, `docker save` | TIDAK ADA | Di host: `docker pull`, `docker raw save` | P3 |
| Pull image di server (deploy) | `docker pull` | ADA | `komando docker pull TARGET IMAGE` (host) | - |
| Login registry di server agar `docker pull` privat jalan, tanpa membuka password ke agent | `docker login --password-stdin`, `crane auth login` | TIDAK ADA | Workaround `docker raw login` di host akan membuat agent melihat/menulis secret; tidak ada cara memakai `--password-ref` registry conn ke host (atau ke k8s `imagePullSecret`) | P2 — keamanan secret saat deploy |
| Mutasi image (label, env, entrypoint, append layer, flatten, rebase) | `crane mutate/append/flatten/rebase`, `regctl image mod` | NON-GOAL | NG-a "Mengganti alat lengkap"; ini pekerjaan build/CI, bukan operasi harian | - |
| Buat index multi-arch dari image yang ada | `docker buildx imagetools create`, `docker manifest create/push`, `regctl index create` | TIDAK ADA | | P3 |
| Artefak OCI (push/pull file, attach) | `oras push/pull/attach`, `regctl artifact put/get` | TIDAK ADA | `copy` menyalin manifest apa adanya, jadi artefak bertag kemungkinan ikut tersalin; tidak ada push/pull file | P3 |
| Buat repository sebelum push (ECR wajib) | `aws ecr create-repository`, Harbor project API | TIDAK ADA | `copy` ke ECR repo yang belum ada akan gagal | P2 — untuk ECR, terkait klaim dukungan ECR |

## J. Registry: menghapus dan membersihkan

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Hapus image (manifest by digest) | `crane delete`, `skopeo delete`, `regctl manifest rm`, `regctl image delete` | ADA | `registry rm --allow-dangerous`, resolve tag → digest, protected `--yes`, catatan GC | - |
| Peringatan tag lain yang ikut hilang | (regctl `tag rm` membedakan) | SEBAGIAN | Help/docs bilang "every tag that points at it goes too", tetapi hasil `rm` dan `--dry-run` hanya `would_delete: repo@digest` — **tidak menyebut tag mana saja yang ikut terhapus** (mis. `latest`, `stable`) | **P1** — keamanan: agent menghapus `old` dan ikut menghapus `prod` |
| Hapus tag saja (untag) tanpa menghapus manifest | `regctl tag rm` (OCI 1.1 tag delete / dummy manifest), Harbor/ECR `batch-delete-image --image-ids imageTag=` | TIDAK ADA | `rm` selalu menghapus manifest | P2 — cara aman membersihkan tag |
| Pembersihan massal: simpan N tag terbaru / hapus lebih tua dari X, dengan pratinjau | `regctl` + skrip, Harbor tag retention, ECR lifecycle policy, `crane` + jq | TIDAK ADA | Docs: "clean up old ones", tetapi hanya satu image per `rm`; tidak ada tanggal di `ls` | **P1** — registry penuh adalah keluhan harian; agent harus `inspect` + `rm` satu-satu |
| Garbage collection registry | `registry garbage-collect` (registry:2), Harbor GC API, GitLab cleanup | TIDAK ADA | Workaround: `exec`/`docker exec` di host registry:2 (`registry garbage-collect /etc/docker/registry/config.yml`) | P3 |
| Retention policy / immutable tags / tag protection (Harbor, ECR, GHCR) | Harbor API, `aws ecr put-lifecycle-policy`, `put-image-tag-mutability` | NON-GOAL | NG-b "provisioning cloud / IaC" — konfigurasi registry dikelola terraform/konsol | - |

## K. Registry: auth dan provider khusus

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Basic auth + bearer token (Docker Hub, GHCR, GitLab, Harbor, registry:2, Quay) | `docker login`, `crane auth`, `skopeo login`, `regctl registry login` | ADA | `registry.New`, token per scope, realm non-https ditolak | - |
| Registry tanpa TLS / self-signed | `--insecure-registry`, `skopeo --tls-verify=false`, `regctl registry set --tls disabled` | SEBAGIAN | `?tls=false` (HTTP polos). Tidak ada `skip-verify`/CA kustom untuk HTTPS self-signed | P2 — Harbor internal dengan CA sendiri umum |
| AWS ECR (token `get-login-password` 12 jam) | `aws ecr get-login-password`, `docker-credential-ecr-login`, `crane` (ecr helper) | SEBAGIAN | Docs mengklaim ECR, tetapi tidak ada pembuat token SigV4; token harus disalin manual ke vault dan kedaluwarsa 12 jam. `import docker` bisa membaca dari `ecr-login` helper sekali saja | **P1** — klaim dukungan tidak bisa dipakai stabil; agent terhenti tiap 12 jam |
| Google Artifact Registry / GCR | `gcloud auth configure-docker`, `docker-credential-gcr` | SEBAGIAN | Bisa dengan user `_json_key` + JSON service account sebagai secret (basic). Token `oauth2accesstoken` (1 jam) tanpa refresh | P2 |
| Azure ACR (token AAD) | `az acr login`, `az acr repository list` | SEBAGIAN | Admin user / service principal (basic) jalan; pertukaran token AAD tidak ada | P3 |
| Credential helper saat runtime (bukan hanya saat import) | `docker-credential-*`, `credHelpers` | SEBAGIAN | `credHelper()` hanya dipanggil di `import docker`; password disalin ke vault (tidak ikut refresh) | P2 (menyelesaikan ECR/GCR sekaligus) |
| Fitur khusus Harbor (project, robot account, hasil scan, replikasi) | Harbor API/UI | TIDAK ADA | NG-a / NG-b sebagian | P3 |
| Repository listing GHCR/Docker Hub (tanpa catalog) | `gh api /orgs/x/packages`, Hub API | TIDAK ADA | Error `REGISTRY_UNSUPPORTED` "Docker Hub and GHCR have no catalog" — jujur, tapi tanpa alternatif | P3 |

## L. Registry: keamanan rantai pasok

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Verifikasi signature (cosign/notation) | `cosign verify`, `notation verify` | TIDAK ADA | Sigstore SDK berat (ukuran biner tidak lagi dibatasi); workaround `exec cosign` di host | P2 — verifikasi sebelum deploy (cek "apakah image ini ditandatangani" via referrers bisa ringan) |
| Tanda tangan image | `cosign sign`, `notation sign` | NON-GOAL | NG-a; pekerjaan CI, kunci penandatangan bukan untuk agent harian | - |
| Lihat SBOM / attestation | `cosign download sbom/attestation`, `oras discover`, `docker buildx imagetools inspect --format '{{json .SBOM}}'` | TIDAK ADA | | P3 |
| Scan kerentanan image | `trivy image`, `grype`, Harbor/ECR scan | TIDAK ADA | DB kerentanan besar + scanner berat (perlu unduh DB terus-menerus); workaround `exec trivy` di host. Membaca hasil scan Harbor/ECR (API) bisa P3 | P3 (scan sendiri mendekati NON-GOAL NG-a) |
| Analisis layer interaktif | `dive` | NON-GOAL | NG-c "TUI" | - |

---

## Catatan tambahan yang ditemukan saat verifikasi

1. `registry.Catalog` tidak mem-paginasi (lihat H) — bug kebenaran, bukan sekadar fitur.
2. `registry rm --dry-run` tidak menyebut tag lain yang ikut terhapus (lihat J).
3. S3 tidak mendukung session token sama sekali (`NewStaticV4(..., "")`), jadi kredensial AWS SSO/STS tidak bisa dipakai (lihat G).
4. `fileTarget`/`cp`: storage dan host punya verb sama (`upload`/`download`) tetapi flag `-r` hanya untuk host; desain sync/recursive sebaiknya menyatukan keduanya.
5. `bin/komando` 51 MB adalah build dev tanpa strip; build rilis (`-s -w -trimpath`, CGO_ENABLED=0) **34,7 MB**. Ukuran biner tidak lagi dibatasi, jadi Azure/GCS/cosign tidak terhalang ukuran.
6. Import FileZilla dan rclone hanya SFTP, padahal storage sudah mendukung FTP/FTPS/S3 (lihat G).
7. `komando test` / `conn test` untuk conn registry dan storage hanya membuka koneksi TCP (`testConn`, `internal/cli/conn.go`); login tidak dicoba. Kredensial yang salah atau token yang kedaluwarsa baru ketahuan saat perintah sungguhan (lihat H, "Cek login/akses").

## Hitungan status

Sudah dikoreksi setelah verifikasi per baris (lihat bagian terakhir).

| Status | Jumlah baris |
|---|---|
| ADA | 26 |
| SEBAGIAN | 19 |
| TIDAK ADA | 81 |
| NON-GOAL | 12 |
| **Total** | **138** |

Baris berstatus ganda dihitung menurut status pertamanya: "ADA (implisit)" sebagai ADA, "TIDAK ADA (storage/sengaja/tidak relevan)" sebagai TIDAK ADA, "NON-GOAL (sebagian)" dan "NON-GOAL (ubah) / TIDAK ADA (baca)" sebagai NON-GOAL.

Prioritas untuk gap (SEBAGIAN + TIDAK ADA, 100 baris): P1 = 10, P2 = 44, P3 = 46. Di luar itu 4 baris lain juga diberi P3 (multipart "ADA (implisit)" untuk pengaturannya, dan 3 baris NON-GOAL yang sebagian kecilnya masih masuk akal).

## 10 gap P1 teratas

| # | Gap | Alasan (visi) |
|---|---|---|
| 1 | `storage sync` folder ↔ bucket/FTP (dengan `--dry-run` jujur, `--delete` dijaga `--allow-dangerous`, include/exclude) | Verb `sync` dijanjikan di vision.md; deploy/backup harian |
| 2 | `upload -r` folder ke storage | 80% kerja harian (situs FTPS, S3 static) |
| 3 | `download -r` prefix dari storage | Restore backup; agent tidak perlu loop |
| 4 | `storage cat` (stdout, `--head/--tail/--max-bytes`) | Pola agent yang sudah ada di `fs cat` |
| 5 | `storage rm` berdasarkan prefix/umur dengan pratinjau dan batas | Retensi backup, aman default |
| 6 | Kredensial S3 sementara (session token, profile/SSO, AssumeRole) | Penghambat di organisasi AWS; secure by default (tanpa key permanen) |
| 7 | Token ECR otomatis (atau credential helper saat runtime) | Docs mengklaim ECR; token 12 jam memutus agent |
| 8 | `Catalog` mengikuti pagination `Link` | Hasil terpotong diam-diam = jawaban salah untuk agent |
| 9 | `registry rm` (dan `--dry-run`) menyebut semua tag yang ikut terhapus | Keamanan destructive |
| 10 | Pembersihan tag registry: simpan N terbaru / lebih tua dari X, dengan pratinjau | Docs menjanjikan "clean up old ones"; keluhan harian registry penuh |

## Verifikasi per baris

Setiap baris di bagian A–L dicek ulang terhadap kode di commit `4784fc9` (bukan dari teks "Bukti" lama). Singkatan path: `cli/` = `internal/cli/`, `storex/` = `internal/storex/`, `reg/` = `internal/registry/`, `driver.go` = `internal/driver/driver.go`. "grep X: 0 hasil" berarti pencarian di `internal/` (tanpa `_test.go`) tidak menemukan apa pun. Subperintah `storage` hanya `ls`, `download`, `upload`, `rm`, `link` (`cli/storage.go:42`); subperintah `registry` hanya `ls`, `inspect`, `copy`, `rm` (`cli/registry.go:33`); tidak ada recipe bawaan untuk storage/registry (`recipe list`: 39 recipe, grep rclone/aws s3/skopeo/crane/cosign/trivy: 0 hasil).

| # | Kemampuan (singkat) | Status akhir | Hasil cek | Bukti di kode |
|---|---|---|---|---|
| 1 | List satu level | ADA | Benar | `cli/storage.go:170` (`ls CONN [PREFIX]`), DIR di `cli/storage.go:157`; `storex/storex.go:111` |
| 2 | List rekursif | ADA | Benar | `cli/storage.go:195-196` (`-r`, `--limit` 1000), `more` `cli/storage.go:165` |
| 3 | Pagination / token lanjut | TIDAK ADA | Benar | `storex/storex.go:111` tanpa `StartAfter`; grep `StartAfter\|starting-token\|continuation`: 0 hasil |
| 4 | Total ukuran (`du`/`--summarize`) | TIDAK ADA | Benar | `objectList` hanya `Count` (`cli/storage.go:145-151`); grep `summarize`: 0 hasil di storage |
| 5 | Tree | TIDAK ADA | Benar | grep `"tree"`: 0 hasil |
| 6 | Download satu objek | ADA | Benar | `cli/storage.go:311-336` (`FILE_EXISTS` :316, `writeAtomic` :321); 0600 di `cli/dbdump.go:341` |
| 7 | Download prefix rekursif | TIDAK ADA | Benar | `cli/transfer.go:98` "-r is for servers; storage downloads one object" |
| 8 | Upload satu file | ADA | Benar | `cli/storage.go:339-365` (`replaced` :350, mime :359); temp+rename `storex/ftp.go:209`, `storex/sftp.go:150` |
| 9 | Upload folder rekursif | TIDAK ADA | Benar | `cli/transfer.go:64`; `fi.IsDir()` ditolak `cli/storage.go:345` |
| 10 | Stream stdin/stdout | TIDAK ADA | Benar | `os.Stat` + `IsDir` `cli/storage.go:344-345`; `--to` langsung dipakai sebagai nama file `cli/storage.go:312-321` |
| 11 | `storage cat` | TIDAK ADA | Benar | Tidak ada subperintah `cat` (`cli/storage.go:42`); `fs cat --head` hanya host `cli/fs.go:313` |
| 12 | Stat/head objek | TIDAK ADA | Benar | Hanya `Exists` internal `storex/storex.go:146`; tidak ada subperintah `stat` |
| 13 | Verifikasi checksum | SEBAGIAN | Benar | Host: `cli/cp.go:62`, `cli/fs.go:215`; storage: hasil upload/download tanpa hash `cli/storage.go:335,363` |
| 14 | Multipart file besar | ADA (implisit) | Benar | `storex/storex.go:167` `PutObject` dengan ukuran; grep `PartSize\|NumThreads`: 0 hasil |
| 15 | Bersihkan multipart yatim | TIDAK ADA | Benar | grep `ListIncompleteUploads\|RemoveIncompleteUpload\|AbortMultipart`: 0 hasil |
| 16 | Resume transfer | TIDAK ADA | Benar | `storex/storex.go:67` `MaxRetry = 2`; tidak ada offset/range di `Get` |
| 17 | Progress di stderr | TIDAK ADA | Benar | grep `progress` di `internal/`: 0 hasil; ux.md:321 |
| 18 | Transfer paralel (storage) | TIDAK ADA | Benar | Satu objek per perintah `cli/storage.go:339`; paralel hanya `runCp` host `cli/cp.go:88` |
| 19 | Bandwidth limit | TIDAK ADA | Benar | grep `bwlimit\|RateLimit\|rate.Limit`: 0 hasil |
| 20 | Transfer lama di latar | TIDAK ADA | Dikoreksi (bukti): "dibatasi `--timeout`" → batas hanya bila `--timeout` diberi | `cli/storage.go:73` (`if g.timeout > 0`); `cli/root.go:164` default 0 |
| 21 | Hapus objek tepat | ADA | Benar | `cli/storage.go:236-266`, `DataDelete` :250, `already deleted` :258 |
| 22 | Hapus prefix/pola/umur | TIDAK ADA (sengaja) | Benar | `cli/storage.go:246` "rm takes exact keys" |
| 23 | Dry-run perubahan | SEBAGIAN | Benar | `cli/storage.go:67-70` "nothing sent: the change would be allowed" (tanpa cek server) |
| 24 | Include/exclude | TIDAK ADA | Benar | Flag `ls` hanya `-r`,`-n` `cli/storage.go:195-196`; grep `exclude` di storage: 0 hasil |
| 25 | Cari objek | TIDAK ADA | Benar | Tidak ada subperintah `find`; tidak ada filter umur/ukuran di `List` `storex/storex.go:31` |
| 26 | Rename/move objek | TIDAK ADA | Benar | Interface `Bucket` tanpa Move `storex/storex.go:28-41`; `Rename` hanya untuk temp upload |
| 27 | Copy server-side | TIDAK ADA | Benar | grep `CopyObject\|ComposeObject`: 0 hasil |
| 28 | Copy antar conn/area | TIDAK ADA | Benar | `cli/cp.go:73` "remote-to-remote copy is not supported" |
| 29 | Buat folder kosong | SEBAGIAN | Benar | Otomatis saat upload `storex/ftp.go:206`, `storex/sftp.go:126`; tidak ada `storage mkdir` |
| 30 | chmod/chown file server | TIDAK ADA | Benar | `Chmod` hanya internal saat upload `storex/sftp.go:149`; `fs chmod` hanya host |
| 31 | Symlink/owner di listing | TIDAK ADA | Benar | `Object{Key,Size,Modified,Dir}` `storex/storex.go:97-102` |
| 32 | Sync lokal ↔ bucket/FTP | TIDAK ADA | Benar | Tidak ada subperintah `sync`; janji di vision.md:107 dan :130 |
| 33 | Sync ke host SSH (delta) | SEBAGIAN | Benar | `upload -r` lewat `runCp` `cli/cp.go:88` tanpa skip/delete (grep `skip\|unchanged` di cp.go: 0 hasil); `--if-changed` 1 file `cli/fs.go:550` |
| 34 | Sync dua arah | TIDAK ADA | Benar | grep `bisync`: 0 hasil |
| 35 | Mirror bucket ke bucket | TIDAK ADA | Benar | grep `mirror` di storage: 0 hasil; copy antar conn ditolak `cli/cp.go:73` |
| 36 | Watch/continuous mirror | NON-GOAL | Benar | vision.md:227 (daemon/server), :228 (berjalan terus-menerus) |
| 37 | Diff/check | TIDAK ADA | Benar | Tidak ada subperintah; grep `diff\|check` di storage: 0 hasil |
| 38 | Dedupe | TIDAK ADA | Benar | grep `dedupe`: 0 hasil |
| 39 | `--size-only`/`--checksum` | TIDAK ADA | Benar | grep `size-only`: 0 hasil |
| 40 | Presigned download URL | ADA | Benar | `cli/storage.go:270-295` (maks 168h :282, RiskWrite :286); `storex/storex.go:189-190` |
| 41 | Presigned upload URL | TIDAK ADA | Benar | grep `PresignedPut\|PresignedPost`: 0 hasil |
| 42 | Link publik permanen | TIDAK ADA | Benar | grep `acl\|anonymous` di storex: 0 hasil |
| 43 | Link FTP/SFTP | TIDAK ADA (tidak relevan) | Dikoreksi: NON-GOAL → TIDAK ADA (P3) | Tidak ada di vision.md "Bukan tujuan" (:221-228); `storex/ftp.go:244,249`, `storex/sftp.go:190` |
| 44 | Batasi conn ke prefix | ADA | Benar | `storex/storex.go:45-56` (`..` ditolak) |
| 45 | Content-Type saat upload | SEBAGIAN | Benar | `cli/storage.go:359` `mime.TypeByExtension`; tidak ada flag `upload` (`cli/storage.go:217-234`) |
| 46 | Cache-Control/metadata | TIDAK ADA | Benar | `PutObjectOptions{ContentType}` saja `storex/storex.go:167`; grep `CacheControl\|UserMetadata`: 0 hasil |
| 47 | Storage class | TIDAK ADA | Benar | grep `StorageClass\|storage-class`: 0 hasil |
| 48 | Restore Glacier | TIDAK ADA | Benar | grep `RestoreObject\|restore-object`: 0 hasil |
| 49 | SSE-KMS/SSE-C | TIDAK ADA | Benar | grep `ServerSideEncryption\|encrypt.` di storex: 0 hasil |
| 50 | Enkripsi sisi klien | TIDAK ADA | Benar | grep `crypt` di storex: 0 hasil selain `crypto/tls` |
| 51 | Object tagging | TIDAK ADA | Benar | grep `Tagging`: 0 hasil |
| 52 | ACL objek | TIDAK ADA | Benar | grep `ACL\|acl` di storex: 0 hasil |
| 53 | Versioning objek | TIDAK ADA | Benar | grep `VersionID\|WithVersions`: 0 hasil; ux.md:331 |
| 54 | Object lock | TIDAK ADA | Benar | grep `Retention\|LegalHold`: 0 hasil |
| 55 | Requester pays/accel | TIDAK ADA | Benar | Opsi URL s3 hanya `endpoint`,`region` `driver.go:293` |
| 56 | S3 Select | TIDAK ADA | Benar | grep `SelectObjectContent`: 0 hasil |
| 57 | Daftar bucket | TIDAK ADA | Benar | `driver.go:265` "s3 URL needs a bucket"; grep `ListBuckets`: 0 hasil |
| 58 | `mb`/`rb` | NON-GOAL (sebagian) | Benar | vision.md:226 (provisioning cloud); grep `MakeBucket\|RemoveBucket`: 0 hasil |
| 59 | Bucket policy/CORS/lifecycle | NON-GOAL (ubah) / TIDAK ADA (baca) | Benar | vision.md:226; grep `GetBucketPolicy\|Lifecycle`: 0 hasil |
| 60 | Versioning on/off bucket | NON-GOAL | Benar | vision.md:226 |
| 61 | Info bucket | TIDAK ADA | Benar | `testConn` hanya TCP `cli/conn.go:491,498` |
| 62 | Admin MinIO | NON-GOAL (sebagian) | Benar | vision.md:223 (mengganti alat lengkap) |
| 63 | Mount filesystem | NON-GOAL | Benar | vision.md:227 (daemon/server), :180 (tanpa cgo) |
| 64 | Serve | NON-GOAL | Benar | vision.md:227 |
| 65 | Analisis interaktif (ncdu) | NON-GOAL | Benar | vision.md:227 (TUI), keputusan #5 vision.md:238 |
| 66 | AWS S3 | ADA | Benar | `driver.go:276` endpoint default AWS |
| 67 | S3-kompatibel | ADA | Dikoreksi (bukti): e2e memakai Garage, bukan MinIO | `driver.go:274-293`; `test/e2e/run.sh:143` (`region=garage`), compose tanpa MinIO |
| 68 | Path-style eksplisit | SEBAGIAN | Benar | `storex/storex.go:78-83` tanpa `BucketLookup`; `driver.go:293` |
| 69 | Self-signed TLS S3 | TIDAK ADA | Benar | `storex/storex.go:71-84` tanpa `TLSClientConfig`; `InsecureSkipVerify` hanya di `storex/ftp.go:40` dan `internal/kube` |
| 70 | GCS native | SEBAGIAN | Benar | Hanya kind `s3` `driver.go:75`; grep `gcs\|googleapis`: 0 hasil; vision.md:94 |
| 71 | Azure Blob | TIDAK ADA | Benar | grep `azblob\|azure`: 0 hasil |
| 72 | WebDAV | TIDAK ADA | Benar | grep `webdav`: 0 hasil; kind storage hanya s3/ftps/ftp/sftp `driver.go:75-82` |
| 73 | SFTP tanpa shell | ADA | Benar | `cli/storage.go:98-115` (sshx.Dial, host key), `driver.go:81` |
| 74 | FTPS explicit | ADA | Benar | `storex/ftp.go:39-43,72`; `driver.go:251` |
| 75 | FTPS implicit | TIDAK ADA | Benar | Hanya `DialWithExplicitTLS` `storex/ftp.go:72`; grep `DialWithImplicitTLS`: 0 hasil |
| 76 | FTP polos | ADA | Benar | `driver.go:243` `INSECURE_PROTOCOL` tanpa `?insecure=1` |
| 77 | FTP active/EPSV off | TIDAK ADA | Benar | grep `DisableEPSV\|ActiveMode`: 0 hasil |
| 78 | SMB/CIFS | TIDAK ADA | Benar | grep `smb`: 0 hasil |
| 79 | Google Drive/Dropbox/… | TIDAK ADA | Benar | Tidak ada kind (`driver.go:62-82`) |
| 80 | Swift/HDFS/backend lain | TIDAK ADA | Benar | grep `swift\|hdfs`: 0 hasil |
| 81 | Access key + secret vault | ADA | Benar | `storex/storex.go:79`; `--password-ref` `cli/conn.go:66` |
| 82 | Kredensial sementara AWS | TIDAK ADA | Benar | `storex/storex.go:79` `NewStaticV4(t.User, secret, "")`; grep `SessionToken\|AssumeRole\|NewIAM\|AWS_PROFILE`: 0 hasil |
| 83 | Import `~/.aws` | TIDAK ADA | Benar | `importSources` `cli/importer.go:48-58` tanpa `aws`; direncanakan vision.md:166 |
| 84 | Import rclone S3/FTP | SEBAGIAN | Benar | `cli/importer.go:771` hanya `sftp`, lainnya "is not imported" :783 |
| 85 | Import FileZilla FTP/FTPS | SEBAGIAN | Benar | `cli/importer.go:711` `Protocol != 1` dilewati |
| 86 | Import `mc`/`.s3cfg` | TIDAK ADA | Benar | `cli/importer.go:48-58`; grep `mc/config\|s3cfg`: 0 hasil |
| 87 | Import S3 URL dari `.env` | ADA | Benar | `cli/importer.go:499,508` (semua skema kind, termasuk `s3`) |
| 88 | Lewat bastion/VPN | ADA | Benar | S3 `storex/storex.go:73-75`; FTP data conn `storex/ftp.go:50-69`; SFTP `cli/storage.go:103` |
| 89 | Protected/`--yes`/audit | ADA | Benar | `cli/storage.go:64` guardConns, audit :68 dan :87 (juga untuk ls/download) |
| 90 | Read-only di server | SEBAGIAN | Benar | Hanya anjuran `docs/features/storage.md:30`; tidak ada mode read-only per conn |
| 91 | Unduhan aman (0600, atomik) | ADA | Benar | `cli/storage.go:316,321`; `cli/dbdump.go:334-349` |
| 92 | Upload no-clobber | SEBAGIAN | Benar | `replaced` sesudahnya `cli/storage.go:350,363`; grep `no-clobber\|if-none-match\|ignore-existing`: 0 hasil |
| 93 | Daftar repository (catalog) | SEBAGIAN | Benar | `reg/registry.go:256-262` satu permintaan `n=limit`, tanpa `nextLink`; output tanpa `more` `cli/registry.go:137-141` |
| 94 | Daftar tag | ADA | Benar | `reg/registry.go:265-290` (`nextLink` :278) |
| 95 | Tag + digest/tanggal/filter | TIDAK ADA | Benar | `Tags` hanya nama `reg/registry.go:265`; `ls` hanya `-n` `cli/registry.go:151` |
| 96 | Inspect image | ADA | Benar | `cli/registry.go:155`, `reg/registry.go:319-372` |
| 97 | Digest saja | ADA | Benar | `reg/registry.go:340` `Docker-Content-Digest` |
| 98 | Config lengkap | TIDAK ADA | Benar | Hanya `Created`, `OS`, `Arch`, `Labels` `reg/registry.go:356-368` |
| 99 | Manifest mentah | TIDAK ADA | Benar | `inspect` tanpa flag `cli/registry.go:155-168`; grep `raw` di registry: 0 hasil |
| 100 | Inspect per platform | TIDAK ADA | Benar | Index hanya daftar platform `reg/registry.go:341-349`; grep `--platform`: 0 hasil |
| 101 | Layer & history | TIDAK ADA | Benar | Hanya jumlah + total ukuran `reg/registry.go:350-353` |
| 102 | Ambil blob/file | TIDAK ADA | Benar | Tidak ada subperintah (`cli/registry.go:33`); grep `export\|blob get`: 0 hasil |
| 103 | Manifest tanpa tag | TIDAK ADA | Benar | Tidak ada endpoint selain catalog/tags/manifests/blobs `reg/registry.go:155-175` |
| 104 | Referrers | TIDAK ADA | Benar | Atestasi dilewati `reg/registry.go:342`; grep `referrers`: 0 hasil di registry |
| 105 | Rate limit Docker Hub | TIDAK ADA | Benar | grep `ratelimit-remaining`: 0 hasil; ux.md:333 |
| 106 | Cek login/akses | SEBAGIAN | Dikoreksi: ADA → SEBAGIAN (P2) | `cli/conn.go:470-504`: `testConn` hanya `dial(tcp)` :491,498, tanpa permintaan `/v2/` |
| 107 | Copy antar registry | ADA | Benar | `cli/registrycopy.go:16-133`; skip `reg/copy.go:21`, mount :150, replaced :56; `--yes` :91, `--dry-run` :99 |
| 108 | Retag registry sama | ADA | Benar | Mount blob `reg/copy.go:146-158`; contoh `cli/registrycopy.go:30` |
| 109 | Copy platform tertentu | TIDAK ADA | Benar | `copy` tanpa flag `cli/registrycopy.go:16-36` |
| 110 | Copy semua tag / sync | TIDAK ADA | Benar | `cobra.ExactArgs(2)`, satu image `cli/registrycopy.go:31`; grep `all-tags`: 0 hasil |
| 111 | Copy ikut signature/SBOM | TIDAK ADA | Benar | grep `referrers\|\.sig`: 0 hasil di `reg/copy.go` |
| 112 | Push dari laptop | TIDAK ADA | Benar | Tidak ada subperintah push; host: `docker raw` `cli/modules.go:383` |
| 113 | Pull/export tarball | TIDAK ADA | Benar | grep `docker-archive\|oci-layout`: 0 hasil |
| 114 | Pull image di server | ADA | Benar | `docker pull` `cli/modules.go:304` |
| 115 | Login registry di server tanpa membuka secret | TIDAK ADA | Benar | grep `password-stdin\|imagePullSecret\|docker login`: 0 hasil |
| 116 | Mutasi image | NON-GOAL | Benar | vision.md:223 (mengganti alat lengkap) |
| 117 | Buat index multi-arch | TIDAK ADA | Benar | grep `index create\|imagetools`: 0 hasil |
| 118 | Artefak OCI | TIDAK ADA | Benar | Tidak ada push/pull file; `copy` menyalin manifest `reg/copy.go:77` |
| 119 | Buat repository (ECR) | TIDAK ADA | Benar | grep `CreateRepository\|create-repository`: 0 hasil |
| 120 | Hapus image | ADA | Benar | `cli/registry.go:171-199` (resolve via `Inspect`, catatan GC :195), `reg/registry.go:375` |
| 121 | Peringatan tag ikut hilang | SEBAGIAN | Benar | `cli/registry.go:189` `would_delete: repo@digest` saja; help `cli/registry.go:174` menyebut "every tag" |
| 122 | Untag saja | TIDAK ADA | Benar | `Delete` selalu manifest by digest `reg/registry.go:375-382` |
| 123 | Pembersihan massal tag | TIDAK ADA | Benar | `rm` `cobra.ExactArgs(2)` `cli/registry.go:176`; janji docs `docs/features/registry.md:3-4` |
| 124 | Garbage collection | TIDAK ADA | Benar | grep `garbage-collect`: 0 hasil (hanya catatan teks `cli/registry.go:195`) |
| 125 | Retention/immutable tags | NON-GOAL | Benar | vision.md:226 |
| 126 | Basic + bearer token | ADA | Benar | `reg/registry.go:63-130`, scope `:155`, realm non-https ditolak `:186` |
| 127 | Registry tanpa TLS / self-signed | SEBAGIAN | Benar | `?tls=false` `cli/registry.go:92`, `reg/registry.go:38`; transport tanpa `TLSClientConfig` `reg/registry.go:43` |
| 128 | AWS ECR token | SEBAGIAN | Benar | grep `GetAuthorizationToken\|SigV4\|ecr`: 0 hasil (hanya komentar `reg/registry.go:2`); klaim di `docs/features/registry.md:4` |
| 129 | Google AR/GCR | SEBAGIAN | Benar | Hanya basic/bearer `reg/registry.go:99,203`; grep `oauth2accesstoken\|_json_key`: 0 hasil |
| 130 | Azure ACR | SEBAGIAN | Benar | Hanya basic/bearer standar; grep `acr\|aad`: 0 hasil di registry |
| 131 | Credential helper runtime | SEBAGIAN | Benar | `credHelper` hanya dari `importDocker` `cli/registry.go:232,252` |
| 132 | Fitur khusus Harbor | TIDAK ADA | Benar | grep `harbor` di kode: hanya komentar/contoh |
| 133 | Listing GHCR/Docker Hub | TIDAK ADA | Benar | Hint 405 `cli/registry.go:105` |
| 134 | Verifikasi signature | TIDAK ADA | Benar | grep `cosign\|notation\|sigstore`: 0 hasil |
| 135 | Tanda tangan image | NON-GOAL | Benar | vision.md:223 |
| 136 | Lihat SBOM/attestation | TIDAK ADA | Benar | grep `sbom\|attestation`: 0 hasil (hanya komentar atestasi `reg/registry.go:342-343`) |
| 137 | Scan kerentanan | TIDAK ADA | Benar | grep `trivy\|grype`: 0 hasil |
| 138 | Analisis layer interaktif | NON-GOAL | Benar | vision.md:227 (TUI), :238 |

Ringkasan verifikasi: 138 baris dicek, 4 dikoreksi (2 status, 2 bukti). Status: #43 NON-GOAL → TIDAK ADA (P3), #106 ADA → SEBAGIAN (P2). Bukti: #20 (`--timeout` tanpa default untuk storage), #67 (e2e memakai Garage, bukan MinIO). Prioritas P1 tetap 10 baris.
