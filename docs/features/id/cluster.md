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
komando cluster status prod                         # versi, node yang siap, pod yang tidak berjalan
komando cluster ls prod pods --namespace shop
komando cluster ls prod deploy --all-namespaces
komando cluster get prod deploy api --namespace shop   # seluruh objek (nilai Secret disembunyikan)
komando cluster logs prod api-7d9f-x2 --namespace shop --since 10m -n 100

komando cluster status swarm1                       # manager Swarm
komando cluster ls swarm1 services
komando cluster logs swarm1 web -n 100
```

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
