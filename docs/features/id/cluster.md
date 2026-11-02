# Cluster (Kubernetes dan Docker Swarm)

Lihat dan ubah apa yang berjalan di Kubernetes dan Docker Swarm dengan satu
set perintah. [Semua fitur](README.md)

## Menambahkan cluster

Cluster Kubernetes diambil dari kubeconfig Anda, satu conn per context:

```bash
komando import kubeconfig --dry-run        # lihat apa yang akan ditambahkan
komando import kubeconfig                  # ~/.kube/config
komando conn edit prod --via bastion       # API server privat? jangkau seperti yang lain
```

Kubeconfig untuk setiap context masuk ke vault. Plugin kredensial
(`aws eks get-token`, `gke-gcloud-auth-plugin`) tetap berfungsi: komando
menjalankannya saat dibutuhkan.

Docker Swarm tidak butuh apa-apa lagi: pakai server manager sebagai target.

## Melihat

```bash
komando cluster status prod                         # versi, node, dan setiap masalah yang ditemukan
komando cluster ls prod pods --namespace shop
komando cluster ls prod deploy --all-namespaces
komando cluster ls prod pods -l app=api             # hanya objek dengan label ini
komando cluster describe prod deployment api --namespace shop   # kondisi, pod, event terbaru
komando cluster events prod --namespace shop --warnings          # apa yang salah, terlama dulu
komando cluster get prod deploy api --namespace shop   # seluruh objek (nilai Secret disembunyikan)
komando cluster logs prod api-7d9f-x2 --namespace shop --since 10m -n 100

komando cluster status swarm1                       # manager Swarm
komando cluster ls swarm1 services
komando cluster logs swarm1 web -n 100
```

Log satu pod, semua pod sebuah workload, atau semua pod dengan label tertentu
(baris diawali `[pod]` kalau ada beberapa pod). `-f` terus membaca baris
baru sampai Ctrl-C atau `--timeout`:

```bash
komando cluster logs prod deploy/api --namespace shop -f
komando cluster logs prod -l app=api --namespace shop -n 50
komando cluster logs swarm1 web -f
```

## Di dalam pod

```bash
komando cluster exec prod deploy/api --namespace shop --read-only -- cat /app/config.yml
komando cluster exec prod api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear
komando cluster forward prod svc/api 8080:80 --namespace shop   # 127.0.0.1:8080 sampai Ctrl-C
```

`cluster exec` memeriksa perintah dengan filter perintah berbahaya, sama
seperti `exec` di server; `--read-only` menandakan perintah hanya melihat.
`cluster forward` membuat port pod atau service bisa dipakai dari komputer
ini saja. Keduanya butuh `kubectl`.

`cluster status` menyebut masalah satu per satu, misalnya
`pod/shop/api-7d9f-x2: api: CrashLoopBackOff`, `deployment/shop/api: 1 of 3
replicas ready`, atau node yang kena `MemoryPressure`. `healthy` bernilai true
kalau tidak ada masalah. `cluster ls` menampilkan kolom yang berguna per
kind: replika siap, restart, host ingress, volume claim, job selesai, jadwal
cron, dan target autoscaler.

## Mengubah

```bash
komando cluster apply prod --file app.yaml --dry-run   # server mengeceknya, tidak ada yang berubah
komando cluster apply prod --file app.yaml
komando cluster restart prod deployment/api --namespace shop
komando cluster scale prod deployment/api 3 --namespace shop
komando cluster rm prod pod api-7d9f-x2 --namespace shop --allow-dangerous

komando cluster apply swarm1 --file compose.yml --stack shop
komando cluster scale swarm1 service/web 4
```

## Deploy versi baru, dan kembali

```bash
komando cluster deploy prod deployment/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait
komando cluster status prod deployment/api --namespace shop --wait   # sudah selesai rollout?
komando cluster history prod deployment/api --namespace shop         # revisi dan image-nya
komando cluster rollback prod deployment/api --namespace shop --wait # kembali ke versi sebelumnya
komando cluster rollback prod deployment/api --to 3 --namespace shop

komando cluster deploy swarm1 service/web --image nginx:1.27 --wait
komando cluster rollback swarm1 service/web --wait
```

`--wait` menunggu sampai semua replika menjalankan versi baru. Ia berhenti
dengan `ROLLOUT_FAILED` kalau cluster menyerah, atau `ROLLOUT_TIMEOUT`
setelah `--timeout` (default 5 menit); lalu `cluster describe` menunjukkan
sebabnya dan `cluster rollback` mengembalikannya.

- Cluster yang protected meminta `--yes` sebelum perubahan apa pun.
- Scale ke 0 dan `rm` menghentikan sesuatu, jadi keduanya butuh `--allow-dangerous`.

## Apa pun yang bisa dilakukan kubectl atau docker

```bash
komando cluster run prod -- get pods -A -o wide
komando cluster run prod --write -- rollout undo deployment/api -n shop
komando cluster run swarm1 -- service ps web
```

`cluster run` meneruskan perintah ke kubectl di komputer ini (dengan
kubeconfig privat dan sementara, lewat jalur `--via` milik conn), atau ke
docker di manager Swarm. Perintah ini hanya membaca kecuali Anda menambahkan
`--write`; delete, drain, dan sejenisnya juga butuh `--allow-dangerous`.
kubectl harus terpasang untuk Kubernetes.

Namespace ditulis `--namespace` (komando memakai `-n` untuk "berapa banyak").
