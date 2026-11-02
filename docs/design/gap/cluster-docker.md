# Analisis gap fitur: Kubernetes, Docker Swarm, Docker/Compose di host

Cakupan: `komando cluster` (Kubernetes + Swarm), `komando docker` (satu host /
fleet lewat SSH), `komando logs --container`, recipe `ops` terkait container.
Dibandingkan dengan kubectl, kubectx/kubens, k9s, stern/kail, helm, kustomize,
kubeseal, Lens, krew (neat, tree, who-can), popeye, kube-capacity, velero,
Docker CLI, docker compose, lazydocker, ctop, dive, Docker Swarm, Portainer,
Nomad, Podman.

Sumber bukti: `internal/cli/cluster.go`, `internal/kube/kube.go`,
`internal/cli/modules.go` (bagian docker), `internal/cli/ops.go` (recipe),
`internal/policy/policy.go`, `internal/cli/exec.go`/`common.go` (guard),
`docs/features/cluster.md`, `docs/features/system.md`, `docs/design/vision.md`,
`docs/design/ux.md`, dan `bin/komando --help`.

## Legenda

- **ADA**: ada perintah/flag first-class, terstruktur, dengan klasifikasi risk.
- **SEBAGIAN**: ada, tetapi kurang (flag hilang, output tidak terstruktur,
  hanya lewat jalan pintas, atau safety-nya tidak konsisten).
- **TIDAK ADA**: tidak ada perintah first-class. Kalau ada jalan pintas
  (`cluster run -- <kubectl>`, `cluster run -- <docker>` di manager Swarm,
  `docker raw`, `exec`), disebut di kolom catatan.
- **NON-GOAL**: sengaja tidak dibuat menurut `docs/design/vision.md`
  ("Bukan tujuan"). Satu pengecualian: "Impersonation `--as`" sengaja ditolak
  oleh kode demi safety (bukan dari vision.md), tetapi tetap dihitung di sini
  karena bukan gap.
- Prioritas: **P1** kebutuhan harian / safety / penghambat agent;
  **P2** sering dipakai tapi ada jalan pintas yang wajar; **P3** jarang/niche.

Kutipan non-goal yang dipakai (vision.md, "Bukan tujuan"):

- NG-1: "Mengganti alat lengkap (`psql`, `kubectl`, `terraform`, `helm`).
  komando menangani 80% pekerjaan harian dengan aman. Sisanya tetap bisa
  dikerjakan lewat `exec` di host atau alat aslinya."
- NG-2: "Infrastructure as Code, provisioning cloud, atau GitOps."
- NG-3: "GUI, TUI, sistem plugin, atau daemon/server. komando tetap CLI murni."
- NG-4: "Monitoring atau alerting yang berjalan terus-menerus."

Catatan penting tentang jalan pintas:

- `cluster run TARGET -- ARGS` menjalankan **kubectl lokal** (kubeconfig
  sementara dari vault, lewat `--via`) atau **docker di manager Swarm**.
  Read-only kecuali `--write`; verb berisiko (`delete`, `drain`, `exec`, `cp`,
  `port-forward`, `debug`, `patch`, `edit`, `taint`, `cordon`...) juga butuh
  `--allow-dangerous` (`classifyKubectl`/`classifyDocker`, cluster.go:843-895).
  Output JSON hanya `{stdout, stderr, exit_code}` (teks mentah), bukan data
  terstruktur. Flag `--context/--kubeconfig/--as/--token/--dry-run` ditolak (cluster.go:811-813).
  **Tidak ada jalan pintas untuk helm** (hanya kubectl).
- `docker raw TARGET -- ARGS` menjalankan docker apa pun di host, **selalu
  dianggap mutating** (modules.go:387) tanpa klasifikasi read/write/destructive;
  hanya pola policy global (`docker-prune-all`) yang memblokir.

---

## 1. Koneksi, konteks, dan target

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Impor kubeconfig, satu conn per context | kubectl config, Lens | ADA | `komando import kubeconfig [--dry-run]`; kubeconfig per context ke vault (`importKubeconfig`, cluster.go:1066) | - |
| Pindah cluster/context | kubectx, `kubectl config use-context` | ADA | Konsepnya diganti nama conn per perintah (`cluster ls prod ...`); tidak ada state "context aktif" yang bisa salah | - |
| Daftar context | `kubectl config get-contexts` | ADA | `komando list kind:conn` / `conn list`; `cluster run -- config get-contexts` diklasifikasi read | - |
| Namespace default per cluster (ganti) | kubens, `kubectl config set-context --namespace` | SEBAGIAN | Namespace default diambil dari context kubeconfig saat impor (`importKubeconfig` menyimpannya sebagai option `namespace`, cluster.go:1096-1097; fallback `default`, kube.go:240-243); `--namespace` per perintah. Default **bisa** diganti tanpa impor ulang: `conn edit prod --option namespace=shop` (conn.go:75/214), dipakai `kubeClient` (cluster.go:78). Kurangnya: `cluster run` (kubectl) mengabaikan option itu dan memakai namespace dari kubeconfig di vault (`runKubectl`, cluster.go:985); option ini juga tidak didokumentasikan di docs/features/cluster.md | P3 - jalan sudah ada; tinggal konsistensi `cluster run` dan dokumentasi |
| Exec auth plugin (EKS/GKE/AKS token) | kubectl | ADA | `bearer()` menjalankan plugin exec (kube.go:256); docs/features/cluster.md | - |
| API server privat lewat bastion/VPN | kubectl + ssh tunnel manual, Lens | ADA | `conn edit prod --via bastion`; kubectl di `cluster run` lewat tunnel lokal (`forwardLocal`) dengan TLS server name asli | - |
| Docker Swarm sebagai target | `docker context`, Portainer | ADA | Server manager dipakai langsung sebagai target (`resolveCluster`) | - |
| Docker host remote | `docker context`, `DOCKER_HOST=ssh://` | ADA | Semua `komando docker ... TARGET` lewat SSH; mendukung selector `@grup` (fleet paralel) | - |
| Satu perintah ke banyak cluster sekaligus | k9s (tidak), kubectl (tidak), Lens (catalog) | TIDAK ADA | `resolveCluster` menolak >1 cluster: "this command works on one" (cluster.go:59). Untuk `docker` fleet bisa | P2 - vision: selector `@prod` universal; `cluster status @prod` untuk ringkasan semua cluster |
| Cek koneksi cluster | `kubectl cluster-info`, `kubectl version` | ADA | `cluster status` (versi lewat `/version`, cluster.go:226, sekaligus menguji login); `komando test <conn>` hanya cek TCP ke API server (`testConn`, conn.go:490-501), bukan autentikasi | - |
| Podman sebagai engine | podman CLI, podman-remote | TIDAK ADA | Perintah `docker` di-hardcode (modules.go); hanya alias `podman-docker` di host atau `exec -- podman ...` | P3 - pasar kecil di server; bisa lewat `exec` |
| Nomad sebagai orkestrator | nomad CLI | TIDAK ADA | vision.md:95 "nanti: nomad" (direncanakan, belum ada) | P3 - pengguna sedikit, sudah direncanakan |
| k3s/kind/minikube lokal | kubectl | ADA | k8s conn generik (vision.md:95) | - |
| OpenShift (`oc`), Rancher | oc, rancher CLI | SEBAGIAN | API k8s generik jalan (discovery CRD); verb khusus (`oc login`, project, route) tidak | P3 - niche |

## 2. Melihat objek dan status (get/describe/insight)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| List objek tipe apa pun (termasuk CRD, shortname) | `kubectl get`, k9s | ADA | `cluster ls TARGET TYPE` dengan discovery + shortNames (kube.go:353-412); `--namespace`, `--all-namespaces`, `-n/--limit` | - |
| Kolom ringkas per kind (pods, deploy, sts, ds, svc, node, secret) | `kubectl get` | ADA | `summarize()` (cluster.go:273): status, ready, restarts, node, ports, versi | - |
| Kolom untuk kind lain (ingress, pvc, pv, job, cronjob, hpa, configmap, event, namespace) | `kubectl get` (printer columns server-side) | SEBAGIAN | Kind lain hanya `name/namespace/age`. Tidak memakai `Table` API (`Accept: application/json;as=Table`) yang memberi kolom kubectl untuk semua kind termasuk CRD | P1 - agent harus `get` satu per satu untuk tahu status PVC/Job/Ingress |
| `-o wide` (IP pod, node, nominated) | `kubectl get -o wide` | SEBAGIAN | Pod: node ada, IP pod tidak; workaround `cluster run -- get pods -o wide` (teks) | P3 |
| Filter label `-l app=api` | `kubectl get -l`, k9s filter | TIDAK ADA | `cluster ls` tidak punya `--selector`; hanya `cluster run -- get pods -l app=api` (teks mentah) | P1 - cara utama memilih pod dari deployment; penting untuk agent |
| Filter field (`status.phase!=Running`, `spec.nodeName=`) | `kubectl get --field-selector` | TIDAK ADA | Hanya dipakai internal di `cluster status`; jalan pintas `cluster run` | P2 |
| Paginasi / lanjut | `kubectl get --chunk-size` | SEBAGIAN | `--limit` + `truncated: true`, tapi tidak ada `--continue` untuk halaman berikut | P3 |
| Objek lengkap (YAML/JSON) | `kubectl get -o yaml` | ADA | `cluster get TARGET TYPE NAME`; `managedFields` dibuang; Secret di-redact | - |
| Objek "bersih" untuk di-apply ulang | kubectl-neat | SEBAGIAN | `managedFields` dibuang, tetapi `status`, `uid`, `resourceVersion`, `creationTimestamp`, anotasi `last-applied` tetap | P3 |
| Describe (objek + events terkait, ringkas manusia) | `kubectl describe`, k9s `d`, Lens | TIDAK ADA | `cluster get` tidak menyertakan events; workaround `cluster run -- describe pod X` (read, teks) | P1 - langkah debug pertama (ImagePullBackOff, FailedScheduling, OOMKilled) |
| Events cluster/namespace, urut waktu, hanya Warning | `kubectl events --types=Warning`, `get events --sort-by` | SEBAGIAN | `cluster ls prod events` jalan lewat discovery, tetapi hanya name/age (tanpa reason/message/object, tanpa sort, tanpa filter Warning) | P1 - inti diagnosis "apa yang salah" untuk agent |
| Ringkasan kesehatan cluster | Lens overview, k9s pulses, popeye | SEBAGIAN | `cluster status`: versi, node ready, pod "not running" berdasar **phase** saja (fieldSelector `status.phase!=Running,status.phase!=Succeeded`, cluster.go:235). Pod `CrashLoopBackOff` ber-phase `Running` → terlewat; `ImagePullBackOff` (phase `Pending`) memang terdaftar tetapi tanpa alasan; deployment `ready < desired`, node pressure (Memory/Disk/PID), PVC Pending, Job gagal, events Warning tidak dilaporkan | P1 - janji perintah "what is not healthy"; agent mengandalkannya |
| Ringkasan kesehatan Swarm | Portainer, `docker service ls` | SEBAGIAN | `cluster status swarm1` hanya mengembalikan JSON mentah `docker info/node ls/service ls`; tidak menghitung layanan dengan replicas `1/3`, node Down/Drain, task gagal | P2 |
| Lint/sanitasi konfigurasi (tanpa limit, latest tag, probe hilang) | popeye, kube-score, Polaris | TIDAK ADA | - | P3 - "nice to have", bukan 80% harian |
| Pohon kepemilikan (Deployment→RS→Pod) | kubectl-tree, Lens | TIDAK ADA | - | P3 |
| Penggunaan CPU/mem pod & node | `kubectl top`, k9s, Lens | TIDAK ADA | Workaround `cluster run -- top pods -A` (read, butuh metrics-server, teks) | P2 - pertanyaan harian "siapa yang makan memori" |
| Kapasitas: request/limit vs allocatable per node | kube-capacity, Lens | TIDAK ADA | Workaround `cluster run -- describe nodes` | P2 |
| Daftar tipe resource | `kubectl api-resources` | SEBAGIAN | Discovery ada di dalam (kube.go:353) tapi tidak diekspos; `cluster run -- api-resources` (read) | P3 |
| Dokumentasi field | `kubectl explain` | SEBAGIAN | Hanya `cluster run -- explain deploy.spec` (read) | P3 |
| Watch perubahan (`-w`) | `kubectl get -w`, k9s | TIDAK ADA | Bukan non-goal: vision.md tidak menyebut watch, dan streaming sesaat sudah ada di komando (`logs --follow`, ux.md:108 `-f`); NG-4 hanya soal monitoring/alerting terus-menerus. Jalan pintas `cluster run -- get pods -w` (read) hanya berguna di mode teks (mode JSON menahan output, cluster.go:1032-1036) | P3 - jarang dibutuhkan agent; `rollout status`/`wait` lebih penting |
| Dashboard interaktif | k9s, Lens, lazydocker, Portainer UI | NON-GOAL | NG-3: "GUI, TUI ... komando tetap CLI murni" | - |

## 3. Logs

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Log satu pod, tail N, since, timestamps | `kubectl logs --tail --since --timestamps` | ADA | `cluster logs TARGET POD -n --since` (timestamps selalu) | - |
| Pilih container, run sebelumnya | `kubectl logs -c`, `--previous` | ADA | `--container/-c`, `--previous` | - |
| Follow (`-f`) pod | `kubectl logs -f`, stern | TIDAK ADA | `cluster logs` tidak punya `--follow`, padahal ux.md:108 menjanjikan `-f` untuk follow dan `komando logs --follow` sudah ada untuk host. Workaround `cluster run -- logs -f POD` (mode teks saja; mode JSON menahan output sampai selesai) | P1 - kebutuhan harian saat deploy; konsistensi verb `logs` |
| Log by workload (`deploy/api`, `svc/x`) | `kubectl logs deploy/api` | TIDAK ADA | Path selalu `pods/<nama>` (cluster.go:507); harus cari nama pod dulu | P1 - nama pod acak berubah tiap rollout; agent butuh 2 langkah |
| Log banyak pod via selector / regex nama | stern, kail, `kubectl logs -l` | TIDAK ADA | Tidak ada `--selector`; `cluster run -- logs -l app=api --prefix` sebagai jalan pintas | P1 - layanan multi-replica: error bisa di replica mana saja |
| Semua container dalam pod | `kubectl logs --all-containers` | TIDAK ADA | Workaround `cluster run` | P2 - sidecar (istio, cloudsql-proxy) |
| Filter isi log (grep) | stern `--include/--exclude` | TIDAK ADA | `komando logs` (host) punya `--grep`, `cluster logs` tidak | P2 - konsistensi dengan `logs --grep` |
| `--until` / rentang waktu | journalctl, docker logs `--until` | TIDAK ADA | k8s API tidak mendukung until; bisa disaring sisi klien | P3 |
| Log Swarm service (tail, since) | `docker service logs` | ADA | `cluster logs swarm1 web -n --since` (`--no-trunc --timestamps`) | - |
| Follow log Swarm service | `docker service logs -f` | TIDAK ADA | Tidak ada `--follow`; `cluster run swarm1 -- service logs -f web` (buffer sampai timeout) | P2 |
| Log container di host (tail/since/until/grep/follow) | `docker logs`, lazydocker | ADA | `logs TARGET --container C` dengan `-f/--follow`, `--grep`, `--since`, `--until`, `-n` (modules.go:173-256; follow lewat `followLogs`, modules.go:272-273). Catatan: alias `docker logs TARGET C` menerima `-f` tetapi memanggil `runOne`, bukan `followLogs` (modules.go:320-323) → output ditahan sampai timeout; bug kecil, follow yang benar lewat `komando logs --container` | - |
| Log container di banyak host sekaligus | ctop (tidak), Portainer (per env) | ADA | `komando logs @web --container api` (fleet) | - |
| Log compose project (semua service) | `docker compose logs --tail -f` | SEBAGIAN | `docker compose TARGET -- logs --tail 50` (teks); `-f` lewat runOne di-buffer sampai timeout | P3 |

## 4. Akses dan debug ke workload

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Exec perintah di pod (non-interaktif) | `kubectl exec POD -- cmd` | SEBAGIAN | Hanya `cluster run --write --allow-dangerous -- exec POD -- cmd`. Tidak ada exec first-class dengan `--read-only` seperti `docker exec --read-only`; perintah baca (`cat /etc/app.conf`, `env`) pun harus `--allow-dangerous` | P1 - debug harian; memaksa agent memakai `--allow-dangerous` yang mestinya jarang (aturan 7 AGENTS.md) |
| Exec interaktif (`-it` shell) | `kubectl exec -it`, k9s `s`, Lens | SEBAGIAN | `cluster run ... -- exec -it POD -- sh` jalan di mode teks (stdin terhubung, cluster.go:1035); tidak ada perintah first-class | P2 - untuk manusia; agent tidak butuh |
| Copy file ke/dari pod | `kubectl cp` | SEBAGIAN | `cluster run --write --allow-dangerous -- cp`; tidak ada integrasi dengan `komando cp TARGET:PATH` | P2 |
| Port-forward ke pod/service | `kubectl port-forward`, k9s, Lens | SEBAGIAN | `cluster run --write --allow-dangerous -- port-forward svc/x 8080:80` memblok di foreground; tidak terintegrasi `komando tunnel start` (yang mendukung conn db/host, bukan service k8s) | P1 - akses DB/admin UI internal cluster; agent perlu background + alamat lokal seperti `tunnel start` |
| `kubectl proxy` | kubectl | SEBAGIAN | `cluster run ... -- proxy` (destructive); jarang perlu | P3 |
| Debug container ephemeral / debug node | `kubectl debug` | SEBAGIAN | Hanya lewat `cluster run --write --allow-dangerous`; tidak bisa `--dry-run` (cluster.go:1025-1026) | P3 |
| Pod sementara (busybox/netshoot) | `kubectl run --rm -it` | SEBAGIAN | `cluster run --write -- run tmp --image=busybox --rm -it` (teks) | P3 |
| Attach | `kubectl attach` | SEBAGIAN | `cluster run` (destructive) | P3 |
| Exec di container (host) | `docker exec` | ADA | `docker exec TARGET C -- cmd` dengan `--read-only`, policy dicek pada perintah dalam (modules.go:352) | - |
| Exec interaktif container (host, `-it`) | `docker exec -it`, lazydocker | SEBAGIAN | `docker exec` memakai `-i` tanpa TTY; tidak ada `--pty` (padahal `komando exec` punya `--pty`) | P2 - shell ke container untuk manusia |
| Copy file host<->container | `docker cp` | SEBAGIAN | `docker raw -- cp` (mutating, tidak dianggap destructive); tidak ada `cp TARGET:container:/path` | P3 |
| Exec di Swarm task / container di node lain | `docker exec` di node | TIDAK ADA | Harus cari node task lalu `docker exec` di node itu; tidak ada bantuan | P3 |

## 5. Deploy, rollout, dan perubahan objek (Kubernetes)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Apply YAML multi-dokumen, server-side apply | `kubectl apply --server-side` | ADA | `cluster apply TARGET --file F` (stdin `-`), field manager `komando` | - |
| Dry-run server | `kubectl apply --dry-run=server` | ADA | Global `--dry-run` → `dryRun=All` | - |
| Diff sebelum apply | `kubectl diff`, Argo/helm-diff | TIDAK ADA | ux.md:332 menulis "`apply` selalu dengan diff dan `--dry-run=server` dulu", tetapi `cluster apply --dry-run` hanya mengembalikan daftar nama objek (cluster.go:708-710), tanpa diff. Jalan pintas `cluster run -- diff -f app.yaml` (read) | P1 - safety: manusia/agent harus melihat apa yang berubah sebelum menulis |
| Konflik field manager | `kubectl apply --server-side` (tanpa force default) | SEBAGIAN | Selalu `force=true` (cluster.go:691): mengambil alih field milik manager lain (HPA, controller lain) tanpa peringatan | P2 - safety; sebaiknya tidak force kecuali diminta |
| Apply direktori / banyak file / URL | `kubectl apply -f dir/ -R` | TIDAK ADA | `--file` satu file; jalan pintas `cat *.yaml \| ... --file -` | P2 |
| Kustomize | `kubectl apply -k`, kustomize | TIDAK ADA | Jalan pintas `kustomize build \| komando cluster apply --file -` atau `cluster run --write -- apply -k` | P2 - umum di repo app; tetapi bisa di-pipe |
| Urutan CRD lalu CR dalam satu file | kubectl (re-discovery) | SEBAGIAN | Discovery di-cache sekali (kube.go:353); CR yang CRD-nya baru dibuat di file yang sama gagal "does not serve" | P3 |
| apiVersion non-preferred (mis. `autoscaling/v1`) | kubectl | SEBAGIAN | `ResourceFor` hanya mengenal versi preferred tiap grup (kube.go:395) → manifest dengan versi lama yang masih dilayani ditolak | P2 - error membingungkan untuk YAML lama |
| Prune objek yang tidak ada di file | `kubectl apply --prune`, ApplySet | NON-GOAL | NG-2 (GitOps); `--prune` diklasifikasi destructive di `cluster run` | - |
| Ganti image (deploy versi baru) | `kubectl set image`, k9s | TIDAK ADA | Jalan pintas `cluster run --write -- set image deploy/api api=repo:tag`; Swarm `cluster run --write -- service update --image` | P1 - aksi deploy paling umum; layak first-class dengan audit image lama→baru dan rollback hint |
| Status rollout / tunggu sampai selesai | `kubectl rollout status`, `kubectl wait` | TIDAK ADA | `cluster restart`/`scale`/`apply` langsung kembali tanpa menunggu; jalan pintas `cluster run -- rollout status deploy/api --timeout 5m` (read) | P1 - agent butuh tahu apakah perubahan berhasil sebelum lapor |
| Riwayat rollout | `kubectl rollout history` | SEBAGIAN | `cluster run -- rollout history` (read, teks); `cluster ls replicasets` tanpa revision/image | P2 |
| Rollback (undo) | `kubectl rollout undo`, helm rollback | TIDAK ADA | Hanya `cluster run --write -- rollout undo` (dicontohkan di docs); bukan first-class, tanpa ringkasan revisi tujuan | P1 - jalan pulang paling penting saat deploy gagal; AGENTS.md aturan 11 meminta cara rollback |
| Pause/resume rollout | `kubectl rollout pause/resume` | SEBAGIAN | `cluster run --write` | P3 |
| Restart rolling | `kubectl rollout restart` | ADA | `cluster restart TARGET deployment/api` (deploy/sts/ds), dry-run server | - |
| Scale | `kubectl scale` | ADA | `cluster scale TARGET TYPE/NAME N`; 0 → `--allow-dangerous` | - |
| Scale dengan syarat (`--current-replicas`) | `kubectl scale --current-replicas` | TIDAK ADA | Tidak ada pengecekan nilai awal; output tidak menyebut replicas sebelumnya (berguna untuk rollback) | P2 - safety/rollback |
| Autoscale (HPA) buat/lihat | `kubectl autoscale`, `get hpa` | SEBAGIAN | `cluster ls hpa` hanya name/age; buat lewat `cluster run --write -- autoscale` atau YAML | P3 |
| Patch | `kubectl patch` | SEBAGIAN | `cluster run --write --allow-dangerous -- patch` (patch dianggap destructive) | P3 |
| Edit di editor | `kubectl edit`, k9s `e` | SEBAGIAN | `cluster run` (destructive, mode teks); alur aman yang disarankan: `cluster get` → edit file → `cluster apply --dry-run` | P3 |
| Label/annotate | `kubectl label/annotate` | SEBAGIAN | `cluster run --write -- label ...` | P3 |
| Buat Secret/ConfigMap dari file/literal | `kubectl create secret generic --from-literal`, `create configmap` | SEBAGIAN | `cluster run --write -- create secret ... --from-literal=k=v`: audit aman (`redactArgs`, cluster.go:1110-1129, menyembunyikan nilai argumen yang mengandung literal/password/token/secret, bentuk `=` maupun spasi), tetapi nilai tetap lewat argv kubectl lokal; tidak ada integrasi `komando secret` (vault) → Secret k8s | P2 - vision mengelola secrets; jalur aman dari vault ke cluster |
| Hapus objek | `kubectl delete` | ADA | `cluster rm TARGET TYPE NAME --allow-dangerous`, dry-run server | - |
| Hapus banyak / by selector, `--cascade`, `--grace-period` | `kubectl delete -l`, `--force` | TIDAK ADA | `cluster rm` satu objek; sisanya `cluster run --allow-dangerous` | P3 |
| Replace | `kubectl replace` | SEBAGIAN | `cluster run` (destructive) | P3 |
| Jalankan Job dari CronJob sekarang | `kubectl create job --from=cronjob/x` | SEBAGIAN | `cluster run --write -- create job ...` | P2 - aksi ops umum (backup manual, migrasi) |
| Suspend/resume CronJob | `kubectl patch cronjob -p '{"spec":{"suspend":true}}'` | SEBAGIAN | `cluster run --allow-dangerous -- patch` | P3 |
| Tunggu kondisi (`wait --for=condition`) | `kubectl wait` | SEBAGIAN | `cluster run -- wait` (read) | P2 |
| Helm-style template/values | helm template, kustomize | NON-GOAL | NG-1 (bukan pengganti helm) dan NG-2 (IaC) | - |

## 6. Node dan kapasitas (Kubernetes)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| List node + status Ready + versi | `kubectl get nodes` | ADA | `cluster ls prod nodes` (status, kubelet version); `cluster status` node ready | - |
| Kondisi node (MemoryPressure, DiskPressure), taint, role, IP | `kubectl describe node`, k9s | SEBAGIAN | Hanya di `cluster get node X` (JSON penuh); tidak diringkas di ls/status | P2 |
| Cordon/uncordon | `kubectl cordon/uncordon` | SEBAGIAN | `cluster run --write --allow-dangerous -- cordon NODE` | P2 - maintenance node rutin |
| Drain | `kubectl drain --ignore-daemonsets --delete-emptydir-data` | SEBAGIAN | `cluster run --write --allow-dangerous -- drain`; tanpa ringkasan pod yang akan dipindah dan PDB yang memblok; `--dry-run` server didukung kubectl | P2 - maintenance; layak dibuat aman dan terstruktur |
| Taint | `kubectl taint` | SEBAGIAN | `cluster run --allow-dangerous` | P3 |
| Pod per node | `kubectl get pods --field-selector spec.nodeName=` | SEBAGIAN | `cluster ls pods -A` punya kolom node; tanpa filter | P3 |
| Shell ke node | `kubectl debug node/x`, ssh | SEBAGIAN | Kalau node terdaftar sebagai host komando: `komando exec/shell`; `kubectl debug node` lewat `cluster run` | P3 |

## 7. RBAC, keamanan, dan rahasia (Kubernetes)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Nilai Secret disembunyikan | Lens (sembunyi default) | SEBAGIAN | `cluster get` me-redact Secret (cluster.go:327), `cluster ls` hanya jumlah key. **Tetapi** `cluster run -- get secret X -o yaml` atau `-o jsonpath='{.data}'` diklasifikasi read dan mencetak nilai (base64) tanpa redaksi; `get pods -o yaml` juga menampilkan env inline | P1 - safety/aturan 9 AGENTS.md: agent bisa membocorkan rahasia lewat jalan pintas read-only |
| Lihat satu nilai Secret atas permintaan manusia | `kubectl get secret -o jsonpath \| base64 -d` | TIDAK ADA | Tidak ada padanan `secret get --reveal` untuk Secret k8s (selain jalan pintas yang bocor di atas) | P2 - konsisten dengan `komando secret get --reveal` |
| Cek izin (`can-i`, `whoami`) | `kubectl auth can-i --list`, `auth whoami` | SEBAGIAN | `cluster run -- auth can-i ...` (read); tidak ada pengecekan izin first-class sebelum aksi | P2 - agent bisa cek sebelum mencoba |
| Siapa bisa melakukan X | kubectl-who-can, rbac-lookup | TIDAK ADA | - | P3 |
| Sealed Secrets | kubeseal | TIDAK ADA | - | P3 - GitOps (NG-2) cenderung di luar cakupan |
| Approve CSR / sertifikat | `kubectl certificate approve` | SEBAGIAN | `cluster run --allow-dangerous` | P3 |
| Impersonation `--as` | kubectl | NON-GOAL (sengaja ditolak) | `kubectlForbidden` menolak `--as`, `--as-group`, `--as-uid`, `--token`, `--context` (cluster.go:811-813): identitas ditentukan conn. Tidak tercantum di "Bukan tujuan" vision.md; ini keputusan safety di kode, bukan gap | - |
| Audit setiap perubahan | kubectl (tidak), Lens (tidak) | ADA | `withKube`/`runKubectl` menulis audit untuk risk > read; `komando audit` | - |
| Cluster protected (konfirmasi) | - | ADA | Conn `--protected` → perubahan butuh `--yes` (docs/features/cluster.md) | - |

## 8. Helm dan ekosistem paket

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Daftar release (`helm list -A`) | helm, Lens | TIDAK ADA | Tidak ada jalan pintas helm (`cluster run` hanya kubectl); release terlihat sebagai Secret `sh.helm.release.v1.*` via `cluster ls secrets` | P2 - read-only, sering ditanya; bisa dibaca dari Secret tanpa biner helm |
| Status/riwayat release | `helm status`, `helm history` | TIDAK ADA | - | P2 - diagnosis "versi chart apa yang jalan" |
| Values yang dipakai release | `helm get values` | TIDAK ADA | - | P3 |
| Rollback release | `helm rollback` | TIDAK ADA | - | P2 - jalan pulang standar untuk cluster berbasis helm |
| Install/upgrade/uninstall chart | `helm upgrade --install` | NON-GOAL | NG-1: "Mengganti alat lengkap (... `helm`)" - pakai helm asli | - |
| Template, repo add/update, plugin | `helm template`, `helm repo` | NON-GOAL | NG-1 / NG-2 | - |
| Kustomize build | kustomize | NON-GOAL | NG-1 (mengganti alat lengkap; vision.md tidak menyebut kustomize secara eksplisit, tetapi merender manifest = pekerjaan alat aslinya); bisa di-pipe ke `cluster apply --file -`. Menerapkan hasilnya dicatat terpisah di bagian 5 ("Kustomize", TIDAK ADA) | - |
| Backup/restore cluster | velero | NON-GOAL | NG-1 (alat lengkap lain) / NG-2; `cluster get` per objek bisa jadi backup manual | - |
| Plugin krew | krew | NON-GOAL | NG-3: "sistem plugin" | - |

## 9. Docker Swarm

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Status swarm | `docker info`, `node ls`, `service ls` | SEBAGIAN | `cluster status swarm1` (JSON mentah, tanpa analisis "apa yang tidak sehat") | P2 |
| List service/node/stack/task | `docker service ls`, `node ls`, `stack ls`, `service ps` | ADA | `cluster ls swarm1 services\|nodes\|stacks\|tasks` | - |
| Task satu service / satu stack | `docker service ps web`, `docker stack ps shop` | SEBAGIAN | `tasks` = semua service (loop); tanpa filter per service/stack; jalan pintas `cluster run -- service ps web` (read) | P2 - diagnosis "kenapa task gagal" |
| Task gagal + pesan error (`--no-trunc`) | `docker service ps --no-trunc --filter desired-state=...` | SEBAGIAN | `tasks` mengembalikan kolom Error tapi terpotong (tanpa `--no-trunc`) | P2 |
| Inspect service/node/secret/config/network | `docker X inspect` | ADA | `cluster get swarm1 service web` (tipe apa pun diteruskan) | - |
| List secret/config/network/volume | `docker secret ls`, `config ls`, `network ls` | SEBAGIAN | `cluster ls` menolak tipe selain services/nodes/tasks/stacks (cluster.go:381); jalan pintas `cluster run -- secret ls` (read) | P2 |
| Log service | `docker service logs` | ADA | `cluster logs swarm1 web -n --since` (tanpa follow, lihat bagian 3) | - |
| Update image service | `docker service update --image` | TIDAK ADA | Jalan pintas `cluster run --write -- service update --image repo:tag web` | P1 - deploy harian di Swarm |
| Rollback service | `docker service rollback` / `update --rollback` | TIDAK ADA | Jalan pintas `cluster run --write -- service rollback web` | P1 - jalan pulang saat deploy gagal |
| Restart (force update) | `docker service update --force` | ADA | `cluster restart swarm1 service/web` (`--detach`) | - |
| Tunggu konvergensi update | `docker service update` (tanpa `--detach`) | TIDAK ADA | restart/scale/apply selalu `--detach`; tidak ada status konvergensi | P1 - agent tidak tahu apakah rollout berhasil (paralel dengan rollout status k8s) |
| Scale | `docker service scale` | ADA | `cluster scale swarm1 service/web 4`; 0 → `--allow-dangerous` | - |
| Deploy stack dari compose file | `docker stack deploy -c` | ADA | `cluster apply swarm1 --file compose.yml --stack shop` (dikirim lewat stdin) | - |
| Stack deploy dengan auth registry | `docker stack deploy --with-registry-auth` | TIDAK ADA | Flag tidak ada; image privat bisa gagal di worker. Integrasi conn `registry` juga belum | P2 - umum untuk image privat (GHCR/ECR) |
| File relatif dalam compose (env_file, configs, secrets file) | `docker stack deploy` dari direktori lokal | SEBAGIAN | File dikirim via stdin; path relatif di-resolve di manager, bukan di laptop → gagal kecuali file sudah ada di manager. Tidak didokumentasikan | P2 - kejutan saat deploy pertama |
| Diff / dry-run stack | Portainer (preview) | SEBAGIAN | `--dry-run` hanya menampilkan perintah yang akan jalan; Swarm tidak punya server-side dry-run | P3 |
| Hapus service/stack | `docker service rm`, `stack rm` | ADA | `cluster rm swarm1 service\|stack NAME --allow-dangerous` | - |
| Node drain/active/pause | `docker node update --availability drain` | SEBAGIAN | `cluster run --write --allow-dangerous -- node update --availability drain N` (destructive, classifyDocker) | P2 - maintenance node |
| Promote/demote, label node | `docker node promote/update --label-add` | SEBAGIAN | `cluster run --write`; demote destructive | P3 |
| Buat secret/config Swarm | `docker secret create`, `config create` | SEBAGIAN | `cluster run --write -- secret create NAME FILE` (FILE harus sudah ada di manager): `cluster run` Swarm tidak meneruskan stdin (`runOne` dengan stdin nil, cluster.go:953; exec.go:318-321), jadi `secret create NAME -` tidak bisa dipakai; tidak ada jalur dari vault `komando secret` | P2 - rahasia app di Swarm; nilai sebaiknya dari vault, bukan argumen |
| Init/join swarm, token join | `docker swarm init/join-token` | SEBAGIAN | `cluster run` (`swarm` selalu destructive); `swarm join-token` mencetak token tanpa redaksi | P3 |
| Network overlay buat/hapus | `docker network create -d overlay` | SEBAGIAN | `cluster run --write` | P3 |

## 10. Docker di host (Docker CLI, lazydocker, ctop, dive, Portainer)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| ps terstruktur (semua container) | `docker ps -a`, lazydocker, ctop | ADA | `docker ps TARGET` (JSON lines, fleet `@web`) | - |
| Filter ps (status, label, nama, health) | `docker ps --filter` | TIDAK ADA | `docker ps` selalu `ps -a` tanpa `--filter`; jalan pintas `docker raw -- ps --filter health=unhealthy` | P2 - "container mana yang unhealthy di semua host" |
| Container unhealthy / restart loop | lazydocker, Portainer, recipe | SEBAGIAN | recipe `docker-overview` (ops.go:134) teks; tidak ada field restart count/health terstruktur | P2 |
| Stats CPU/mem terstruktur | `docker stats --no-stream`, ctop | ADA | `docker stats TARGET` | - |
| Proses di container | `docker top` | SEBAGIAN | `docker raw -- top C` (dianggap mutating) | P3 |
| Inspect | `docker inspect` | SEBAGIAN | `docker inspect TARGET NAME` (JSON). Env berisi password tampil tanpa redaksi (berbeda dengan `cluster get` yang me-redact Secret) | P2 - safety: agent membaca inspect untuk debug dan membocorkan `DB_PASSWORD` |
| Start/stop/restart | `docker start/stop/restart` | ADA | `docker start\|stop\|restart TARGET NAME...` (mutating, protected host → `--yes`, `--dry-run`) | - |
| Hapus container | `docker rm` | SEBAGIAN | `docker rm TARGET NAME` hanya "mutating"; `-f`/`-v` (hapus volume anonim) lolos tanpa `--allow-dangerous`. Tidak konsisten dengan `cluster rm` yang butuh `--allow-dangerous` | P1 - safety; aturan "rm butuh --allow-dangerous" harus sama di semua family |
| Kill, pause/unpause, rename, update (limit) | `docker kill/pause/update` | SEBAGIAN | `docker raw` (mutating, tanpa klasifikasi) | P3 |
| Run/create container baru | `docker run -d` | SEBAGIAN | `docker raw -- run -d ...`; tidak ada guard untuk `--privileged`, `-v /:/host`, `--pid=host` (di `cluster run` k8s, `run --privileged` destructive) | P2 - safety: klasifikasi `docker raw` setara `classifyDocker` |
| Images terstruktur | `docker images` | ADA | `docker images TARGET` | - |
| Pull image | `docker pull` | ADA | `docker pull TARGET IMAGE` | - |
| Pull dengan kredensial registry dari vault | `docker login` + pull | TIDAK ADA | Conn `registry` (vault) tidak dipakai untuk login di host; harus `docker login` manual di host | P2 - vision: satu vault untuk semua; image privat umum |
| Tag/push image | `docker tag/push` | SEBAGIAN | `docker raw`; antar-registry tanpa host: `komando registry copy` (ADA) | P3 |
| Hapus image (rmi) | `docker rmi`, `image rm` | SEBAGIAN | `docker raw -- rmi` (mutating saja); registry: `registry rm --allow-dangerous` | P3 |
| Build image di host | `docker build`, buildx | SEBAGIAN | `docker raw -- build` (butuh konteks di host; tanpa upload konteks). Build lokal di luar cakupan | P3 - CI/CD, bukan ops harian |
| Analisis layer image | dive | TIDAK ADA | `registry inspect` memberi ukuran/platform, bukan isi layer | P3 |
| Network ls/inspect/create/rm | `docker network` | SEBAGIAN | `docker raw`; `network ls` pun dianggap mutating (protected host minta `--yes`) | P2 - `docker raw` harus membedakan read |
| Volume ls/inspect/rm | `docker volume` | SEBAGIAN | `docker raw`; `volume rm` tidak diblokir policy (hanya `volume prune --all`) → kehilangan data tanpa `--allow-dangerous` | P1 - safety: volume = data |
| Disk usage | `docker system df` | SEBAGIAN | recipe `docker-overview` (teks) / `docker raw -- system df` | P3 |
| Prune aman | `docker system prune` | ADA | recipe `docker-prune` (tanpa volume, mutating); `prune -a/--volumes` diblok policy `docker-prune-all` | - |
| Events | `docker events --since` | SEBAGIAN | `docker raw -- events --since 1h --until now` (perlu `--until` agar tidak menggantung) | P3 |
| Copy file container | `docker cp` | SEBAGIAN | lihat bagian 4 | P3 |
| Login registry | `docker login` | SEBAGIAN | `komando import docker` mengimpor `~/.docker/config.json` ke conn registry (lokal); login di host remote tidak ada | P3 |
| Docker context | `docker context` | ADA | Target/host komando menggantikan context | - |
| `docker raw` dengan klasifikasi risk | (konsep komando) | SEBAGIAN | `docker raw` selalu mutating (modules.go:387): read (`ps`, `network ls`) dianggap tulis, sedangkan `volume rm`, `rm -f`, `run --privileged` tidak dianggap destructive. `classifyDocker` (cluster.go:877) sudah ada tapi hanya dipakai di `cluster run` | P1 - safety & ergonomi agent; perbaikan murah (pakai ulang `classifyDocker`, flag `--write` seperti `cluster run`) |
| Fleet: aksi docker ke banyak host | Portainer (multi-env) | ADA | Semua subperintah `docker` menerima `@grup` (runFleet, paralel `-P`) | - |
| Dashboard TUI | lazydocker, ctop, Portainer UI | NON-GOAL | NG-3 | - |

## 11. Docker Compose di host

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Passthrough compose dengan file/dir | `docker compose -f -p` | ADA | `docker compose TARGET --dir D --file F -- ARGS` | - |
| up -d / pull / restart / exec | `docker compose up/pull/restart/exec` | ADA | Lewat passthrough; dianggap mutating (protected → `--yes`), `--dry-run` menampilkan perintah | - |
| ps terstruktur | `docker compose ps --format json` | SEBAGIAN | Output teks (`2>&1` digabung); bisa `-- ps --format json` tapi hasil tidak di-parse | P2 - agent butuh status service compose terstruktur |
| `ls` project di host | `docker compose ls` | ADA | passthrough `-- ls` (dianggap read) | - |
| Down | `docker compose down` | SEBAGIAN | Hanya mutating; `down -v` (hapus volume = data) dan `down --rmi all` tidak butuh `--allow-dangerous`; policy tidak punya pola compose | P1 - safety: `down -v` menghapus database |
| Config (render) | `docker compose config` | SEBAGIAN | Dianggap read, tapi mencetak env/secret hasil interpolasi `.env` tanpa redaksi | P2 - safety: kebocoran rahasia ke agent |
| Deteksi read-only | - | SEBAGIAN | `HasPrefix(sub,"ps"/"logs"/"config"/"ls")` (modules.go:376): `top`, `images`, `version`, `events` dianggap mutating | P3 |
| Logs follow | `docker compose logs -f` | SEBAGIAN | Lihat bagian 3 (buffer sampai timeout) | P3 |
| Edit compose file/env di host | editor + ssh | ADA | `komando fs replace ... --backup`, `cp` (bagian host) | - |
| Deploy alur: pull → up → cek health | Portainer stacks, watchtower | SEBAGIAN | Bisa dirangkai manual; tidak ada pengecekan health setelah `up` | P2 - verifikasi pasca-deploy untuk agent |
| Update otomatis image | watchtower | NON-GOAL | NG-3/NG-4 (daemon, berjalan terus) | - |

## 12. Lintas area: kontrak agent dan safety

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Output JSON terstruktur untuk perintah first-class | kubectl `-o json` | ADA | Kontrak `{ok, command, data, error, meta}`; `cluster ls/get/status`, `docker ps/stats/images` | - |
| Output terstruktur untuk jalan pintas | kubectl `-o json` | SEBAGIAN | `cluster run` mengembalikan stdout mentah; agent bisa menambah `-o json` sendiri, tapi `docker raw`/`compose` tidak di-parse | P3 |
| Streaming di mode JSON (follow, rollout status, port-forward) | - | SEBAGIAN | `runKubectl` menahan output sampai proses selesai di mode JSON (cluster.go:1032-1036); perintah panjang perlu `job start` | P2 |
| Perintah panjang di background | - | SEBAGIAN | `komando job start` ada untuk host (bisa dipakai untuk `docker ...` di manager Swarm); untuk Kubernetes tidak ada: `cluster run` menjalankan kubectl lokal di foreground (cluster.go:1031-1037) dan `job` hanya bekerja lewat SSH | P2 - rollout/drain bisa > 2 menit (AGENTS.md aturan 6) |
| Klasifikasi risk konsisten antar family | - | SEBAGIAN | k8s: rm/scale 0/drain/exec → `--allow-dangerous`. Docker host: `rm`, `volume rm`, `compose down -v`, `raw` → cukup mutating | P1 - prinsip "secure by default" harus seragam |
| Dry-run pada semua perubahan | kubectl `--dry-run=server` | SEBAGIAN | k8s: server dry-run; Swarm/docker: hanya menampilkan perintah. Swarm `cluster rm` tanpa `--allow-dangerous` memblok sebelum dry-run sempat menampilkan rencana (cluster.go:782) | P3 |
| Hint rollback setelah perubahan | - | TIDAK ADA | `cluster scale/apply/set image` tidak mengembalikan nilai sebelumnya (replicas lama, image lama, revisi) untuk rollback | P2 - AGENTS.md aturan 11 |
| Selector `@grup` untuk cluster | - | TIDAK ADA | Lihat bagian 1 | P2 |

---

## Ringkasan hitungan

Dihitung per baris kemampuan di semua tabel (183 baris):

| Status | Jumlah |
|---|---|
| ADA | 46 |
| SEBAGIAN | 83 |
| TIDAK ADA | 43 |
| NON-GOAL | 11 |

Prioritas gap (SEBAGIAN + TIDAK ADA): P1 = 23, P2 = 49, P3 = 54.
(Setelah verifikasi per baris: "Watch perubahan" pindah dari NON-GOAL ke
TIDAK ADA/P3, dan "Namespace default per cluster" turun dari P2 ke P3.)
(Baris "Impersonation `--as`" dihitung NON-GOAL karena sengaja ditolak demi safety.)

## 10 gap P1 teratas (urutan dampak)

1. **Klasifikasi risk docker di host tidak konsisten**: `docker rm -f/-v`,
   `docker raw -- volume rm`, `docker compose down -v`, `docker raw -- run
   --privileged` hanya "mutating"; `docker raw` tidak membedakan read. Pakai
   ulang `classifyDocker` + `--write`/`--allow-dangerous` seperti `cluster run`.
2. **Kebocoran Secret lewat `cluster run -- get secret -o yaml`** (diklasifikasi
   read, tidak di-redact).
3. **`cluster status` melewatkan CrashLoopBackOff** (phase `Running`),
   deployment tidak lengkap, node pressure (hanya phase); ImagePullBackOff
   ikut terdaftar (phase `Pending`) tetapi tanpa alasan.
4. **Tidak ada diff sebelum `cluster apply`** (padahal ux.md:332 menjanjikan).
5. **Tidak ada status rollout / tunggu konvergensi** (k8s dan Swarm; semua
   perubahan `--detach`).
6. **Tidak ada rollback first-class** (`rollout undo`, `service rollback`).
7. **Tidak ada set image first-class** (k8s `set image`, Swarm `service update --image`).
8. **`cluster logs`: tanpa `--follow`, tanpa log per workload (`deploy/api`) dan
   per selector multi-pod (stern)**.
9. **Tidak ada describe/events yang berguna** (events hanya name/age; `cluster
   ls` tanpa `--selector` dan kolom untuk kind lain via Table API).
10. **Exec ke pod butuh `--allow-dangerous` bahkan untuk baca; port-forward ke
    service tidak terintegrasi `tunnel start`** (background + alamat lokal).

## Verifikasi per baris

Dicek ulang 2026-11-02 terhadap kode di branch `feat/v0.3` (`internal/cli/cluster.go`,
`internal/cli/modules.go`, `internal/cli/exec.go`, `internal/cli/common.go`, `internal/cli/conn.go`,
`internal/kube/kube.go`, `internal/policy/policy.go`, `internal/cli/ops.go`) dan `bin/komando <cmd> --help`
(tanpa koneksi ke server). "Benar" = status, bukti dan prioritas sesuai kode.

| # | Kemampuan (singkat) | Status akhir | Hasil cek | Bukti di kode |
|---|---|---|---|---|
| 1 | Impor kubeconfig | ADA | Benar | cluster.go:1066-1106 `importKubeconfig`; `import --help`: sumber `kubeconfig` |
| 2 | Pindah cluster/context | ADA | Benar | cluster.go:40-60 `resolveCluster` (nama conn per perintah) |
| 3 | Daftar context | ADA | Benar | `conn --help`: `list` = `list kind:conn`; cluster.go:850-853 `config get-contexts` read |
| 4 | Namespace default per cluster | SEBAGIAN P3 | Dikoreksi: bukti salah (`conn edit --option namespace=` ada); P2→P3 | conn.go:75/214 `--option`; cluster.go:78 dipakai `kubeClient`; cluster.go:985 `runKubectl` mengabaikannya |
| 5 | Exec auth plugin | ADA | Benar | kube.go:256-284 `bearer()`; docs/features/cluster.md:16-17 |
| 6 | API server privat | ADA | Benar | cluster.go:64 `openAccess`; cluster.go:989-1006 `forwardLocal` + TLSServerName |
| 7 | Docker Swarm sebagai target | ADA | Benar | cluster.go:54-55 (`clusterTarget{host}`) |
| 8 | Docker host remote | ADA | Benar | modules.go:284-391 via `runOne`/`probe` → `resolveTargets` (exec.go:191-200, 325-332) |
| 9 | Banyak cluster sekaligus | TIDAK ADA P2 | Benar | cluster.go:59 "this command works on one" |
| 10 | Cek koneksi cluster | ADA | Dikoreksi: bukti (`test` hanya TCP) | cluster.go:224-227 `/version`; conn.go:490-501 `testConn` hanya dial TCP |
| 11 | Podman | TIDAK ADA P3 | Benar | grep podman: hanya ops.go:32 (deteksi tool di facts); modules.go hardcode `docker` |
| 12 | Nomad | TIDAK ADA P3 | Benar | grep nomad di internal: 0 hasil; vision.md:95 "nanti: nomad" |
| 13 | k3s/kind/minikube | ADA | Benar | driver.go:71 kind `k8s` generik; vision.md:95 |
| 14 | OpenShift, Rancher | SEBAGIAN P3 | Benar | kube.go:353-399 discovery generik; grep `oc login`/route: 0 hasil |
| 15 | List objek tipe apa pun | ADA | Benar | cluster.go:352-424; kube.go:353-411 (shortNames 376) |
| 16 | Kolom ringkas per kind | ADA | Benar | cluster.go:273-323 `summarize` |
| 17 | Kolom untuk kind lain | SEBAGIAN P1 | Benar | cluster.go:277-281 (default name/ns/age); grep `as=Table`: 0 hasil |
| 18 | `-o wide` | SEBAGIAN P3 | Benar | cluster.go:283-299 (node ada, podIP tidak) |
| 19 | Filter label | TIDAK ADA P1 | Benar | grep `labelSelector`: 0 hasil; `cluster ls --help` tanpa selector |
| 20 | Filter field | TIDAK ADA P2 | Benar | fieldSelector hanya cluster.go:235 (internal status) |
| 21 | Paginasi | SEBAGIAN P3 | Benar | cluster.go:394-416 (`limit`, `truncated`); tidak ada flag continue |
| 22 | Objek lengkap | ADA | Benar | cluster.go:426-463; managedFields 454-456; `redact` 453 |
| 23 | Objek bersih | SEBAGIAN P3 | Benar | cluster.go:454-456 hanya hapus managedFields; last-applied hanya dibuang untuk Secret (338-342) |
| 24 | Describe | TIDAK ADA P1 | Benar | grep describe di cli: hanya cluster.go:855 (classify read) |
| 25 | Events | SEBAGIAN P1 | Benar | cluster.go:277-281 (kind Event → name/ns/age saja) |
| 26 | Ringkasan kesehatan cluster | SEBAGIAN P1 | Dikoreksi: bukti (ImagePullBackOff/Pending terdaftar; baris 233→235) | cluster.go:235 fieldSelector phase; 244-250 |
| 27 | Ringkasan kesehatan Swarm | SEBAGIAN P2 | Benar | cluster.go:220-223 (`swarmRead` JSON mentah) |
| 28 | Lint/sanitasi | TIDAK ADA P3 | Benar | grep popeye/kube-score/lint di internal: 0 hasil |
| 29 | Pohon kepemilikan | TIDAK ADA P3 | Benar | grep ownerReferences/tree di cluster.go/kube: 0 hasil |
| 30 | CPU/mem pod & node | TIDAK ADA P2 | Benar | `top` hanya di classify (cluster.go:855); grep metrics.k8s.io: 0 hasil |
| 31 | Kapasitas | TIDAK ADA P2 | Benar | grep allocatable di internal: 0 hasil |
| 32 | Daftar tipe resource | SEBAGIAN P3 | Benar | kube.go:353 `discover` tidak diekspos; cluster.go:855 `api-resources` read |
| 33 | Dokumentasi field | SEBAGIAN P3 | Benar | cluster.go:855 `explain` read |
| 34 | Watch perubahan | TIDAK ADA P3 | Dikoreksi: NON-GOAL→TIDAK ADA (P3) | vision.md:221-228 tidak menyebut watch; ux.md:108 `-f`; grep watch di internal: 0 hasil |
| 35 | Dashboard interaktif | NON-GOAL | Benar | vision.md:227 (NG-3) |
| 36 | Log satu pod | ADA | Benar | cluster.go:491-511 (tailLines, timestamps=true, sinceSeconds) |
| 37 | Pilih container, previous | ADA | Benar | cluster.go:516-519 |
| 38 | Follow pod | TIDAK ADA P1 | Benar | cluster.go:515-519 tanpa `--follow`; grep follow di cluster.go: 0 hasil; ux.md:108 |
| 39 | Log by workload | TIDAK ADA P1 | Dikoreksi: baris 503→507 | cluster.go:507 path `/pods/<nama>/log` |
| 40 | Log via selector | TIDAK ADA P1 | Benar | grep selector di cluster.go: hanya :235 |
| 41 | Semua container | TIDAK ADA P2 | Benar | grep `all-containers`: 0 hasil |
| 42 | Filter isi log (grep) | TIDAK ADA P2 | Benar | cluster.go:515-519 tanpa `--grep`; modules.go:182 (host punya) |
| 43 | `--until` | TIDAK ADA P3 | Benar | cluster.go:515-519 tanpa `--until` |
| 44 | Log Swarm service | ADA | Benar | cluster.go:484-489 |
| 45 | Follow log Swarm | TIDAK ADA P2 | Benar | cluster.go:485-489 `runOne` (buffer); tanpa follow |
| 46 | Log container di host | ADA | Dikoreksi: bukti (`docker logs -f` tidak streaming) | modules.go:272-273 `followLogs`; modules.go:320-323 alias `docker logs` pakai `runOne` |
| 47 | Log container banyak host | ADA | Benar | modules.go:258-276 `logs` + `resolveTargets` (exec.go:196) |
| 48 | Log compose project | SEBAGIAN P3 | Benar | modules.go:361-377 passthrough `runOne` (buffer) |
| 49 | Exec di pod (non-interaktif) | SEBAGIAN P1 | Benar | cluster.go:862-864 `exec` destructive; 941-951 butuh `--write` + `--allow-dangerous` |
| 50 | Exec interaktif -it | SEBAGIAN P2 | Dikoreksi: baris 1032→1035 | cluster.go:1034-1036 (stdin di mode teks) |
| 51 | Copy file pod | SEBAGIAN P2 | Benar | cluster.go:863 `cp` destructive; grep integrasi `komando cp`↔pod: 0 hasil |
| 52 | Port-forward | SEBAGIAN P1 | Benar | cluster.go:863 destructive; tunnel.go tanpa jenis k8s (`tunnel start --help`) |
| 53 | kubectl proxy | SEBAGIAN P3 | Benar | cluster.go:863 `proxy` destructive |
| 54 | Debug container | SEBAGIAN P3 | Dikoreksi: baris 1015→1025-1026, perlu `--write` | cluster.go:863, 1025-1026 |
| 55 | Pod sementara | SEBAGIAN P3 | Benar | cluster.go:869-872 `run` = write (kecuali --privileged/--overrides) |
| 56 | Attach | SEBAGIAN P3 | Benar | cluster.go:863 `attach` destructive |
| 57 | Exec di container (host) | ADA | Dikoreksi: baris 350→352 | modules.go:343-359; guard 352; `--read-only` 359 |
| 58 | Exec interaktif container (host) | SEBAGIAN P2 | Benar | modules.go:356 `docker exec -i` tanpa TTY; grep pty di modules.go: 0 hasil |
| 59 | Copy host<->container | SEBAGIAN P3 | Benar | modules.go:382-388 `docker raw` (mutating) |
| 60 | Exec di Swarm task | TIDAK ADA P3 | Benar | cluster.go: tidak ada exec Swarm first-class |
| 61 | Apply multi-dokumen SSA | ADA | Benar | cluster.go:655-718; 691 fieldManager komando; 726-758 splitYAML |
| 62 | Dry-run server | ADA | Benar | cluster.go:692-694 `dryRun=All` |
| 63 | Diff sebelum apply | TIDAK ADA P1 | Benar | cluster.go:708-710 hanya nama; ux.md:332; `diff` read di cluster.go:856 |
| 64 | Konflik field manager | SEBAGIAN P2 | Benar | cluster.go:691 `force=true` |
| 65 | Apply direktori | TIDAK ADA P2 | Benar | cluster.go:668 `readFileOrStdin` satu file |
| 66 | Kustomize (apply -k) | TIDAK ADA P2 | Benar | grep kustomize di internal: 0 hasil |
| 67 | Urutan CRD lalu CR | SEBAGIAN P3 | Benar | kube.go:354-356 discovery di-cache sekali |
| 68 | apiVersion non-preferred | SEBAGIAN P2 | Benar | kube.go:394-397 hanya PreferredVersion; 414-421 |
| 69 | Prune objek | NON-GOAL | Benar | vision.md:226 (NG-2 GitOps); cluster.go:865 `--prune` destructive |
| 70 | Ganti image | TIDAK ADA P1 | Benar | grep `set image` di internal: 0 hasil (hanya contoh); cluster.go:872 `set` = write |
| 71 | Status rollout / tunggu | TIDAK ADA P1 | Benar | cluster.go:562/631/684 `--detach`; 581/647/710 langsung kembali; 860 rollout status read |
| 72 | Riwayat rollout | SEBAGIAN P2 | Benar | cluster.go:860 read; 300-302 RS tanpa revision/image |
| 73 | Rollback (undo) | TIDAK ADA P1 | Benar | docs/features/cluster.md:56; cluster.go:872 rollout undo = write |
| 74 | Pause/resume rollout | SEBAGIAN P3 | Benar | cluster.go:872 (default write) |
| 75 | Restart rolling | ADA | Benar | cluster.go:540-587 |
| 76 | Scale | ADA | Benar | cluster.go:598-653; 624-626 0 → destructive |
| 77 | Scale bersyarat | TIDAK ADA P2 | Benar | grep `current-replicas`: 0 hasil; cluster.go:647 tanpa replicas lama |
| 78 | Autoscale (HPA) | SEBAGIAN P3 | Benar | cluster.go:277-281 (hpa name/age); autoscale = write |
| 79 | Patch | SEBAGIAN P3 | Benar | cluster.go:862 destructive |
| 80 | Edit di editor | SEBAGIAN P3 | Benar | cluster.go:862 destructive |
| 81 | Label/annotate | SEBAGIAN P3 | Benar | cluster.go:872 write |
| 82 | Buat Secret/ConfigMap | SEBAGIAN P2 | Dikoreksi: bukti (cakupan redactArgs diperiksa) | cluster.go:1110-1129 `redactArgs`; grep integrasi vault→Secret k8s: 0 hasil |
| 83 | Hapus objek | ADA | Benar | cluster.go:760-806 |
| 84 | Hapus banyak / selector | TIDAK ADA P3 | Benar | cluster.go:767 `ExactArgs(3)`; tanpa selector |
| 85 | Replace | SEBAGIAN P3 | Benar | cluster.go:862 destructive |
| 86 | Job dari CronJob | SEBAGIAN P2 | Benar | cluster.go:867/872 create job = write |
| 87 | Suspend/resume CronJob | SEBAGIAN P3 | Benar | cluster.go:862 patch destructive |
| 88 | Tunggu kondisi | SEBAGIAN P2 | Benar | cluster.go:856 `wait` read |
| 89 | Helm-style template | NON-GOAL | Benar | vision.md:223-226 (NG-1 helm, NG-2) |
| 90 | List node | ADA | Benar | cluster.go:313-316; 238-243 |
| 91 | Kondisi node | SEBAGIAN P2 | Benar | cluster.go:313-316 hanya Ready/versi |
| 92 | Cordon/uncordon | SEBAGIAN P2 | Benar | cluster.go:862 destructive |
| 93 | Drain | SEBAGIAN P2 | Benar | cluster.go:862 destructive; 1022-1028 `--dry-run=server` ditambahkan |
| 94 | Taint | SEBAGIAN P3 | Benar | cluster.go:862 destructive |
| 95 | Pod per node | SEBAGIAN P3 | Benar | cluster.go:299 kolom node; tanpa filter |
| 96 | Shell ke node | SEBAGIAN P3 | Benar | cluster.go:863 debug destructive; `shell`/`exec` untuk host |
| 97 | Nilai Secret disembunyikan | SEBAGIAN P1 | Benar | cluster.go:327-343, 453; 855 `get` read tanpa redaksi stdout (1055) |
| 98 | Lihat nilai Secret | TIDAK ADA P2 | Benar | grep reveal di cluster.go: 0 hasil |
| 99 | Cek izin | SEBAGIAN P2 | Benar | cluster.go:858 can-i/whoami read |
| 100 | Siapa bisa | TIDAK ADA P3 | Benar | grep who-can/rbac-lookup: 0 hasil |
| 101 | Sealed Secrets | TIDAK ADA P3 | Benar | grep kubeseal/sealed: 0 hasil |
| 102 | Approve CSR | SEBAGIAN P3 | Benar | cluster.go:862 `certificate` destructive |
| 103 | Impersonation --as | NON-GOAL | Dikoreksi: bukti (bukan dari vision.md; baris 810→811-813) | cluster.go:811-813 `kubectlForbidden`; vision.md:221-228 tidak menyebutnya |
| 104 | Audit setiap perubahan | ADA | Benar | cluster.go:140-142, 1046-1048; exec.go:309 (Swarm) |
| 105 | Cluster protected | ADA | Benar | common.go:214-224 `guardConns`; docs/features/cluster.md:49 |
| 106 | Daftar release helm | TIDAK ADA P2 | Benar | grep helm di internal: 0 hasil |
| 107 | Status/riwayat release | TIDAK ADA P2 | Benar | grep helm: 0 hasil |
| 108 | Values release | TIDAK ADA P3 | Benar | grep helm: 0 hasil |
| 109 | Rollback release | TIDAK ADA P2 | Benar | grep helm: 0 hasil |
| 110 | Install/upgrade chart | NON-GOAL | Benar | vision.md:223 (NG-1 menyebut `helm`) |
| 111 | Template, repo, plugin helm | NON-GOAL | Benar | vision.md:223-226 (NG-1/NG-2) |
| 112 | Kustomize build | NON-GOAL | Dikoreksi: bukti NG-2→NG-1 (kustomize tidak disebut eksplisit) | vision.md:223-225 NG-1; grep kustomize: 0 hasil |
| 113 | Backup/restore cluster | NON-GOAL | Benar | vision.md:223-226 (NG-1 alat lengkap) |
| 114 | Plugin krew | NON-GOAL | Benar | vision.md:227 (NG-3 sistem plugin) |
| 115 | Status swarm | SEBAGIAN P2 | Benar | cluster.go:220-223 |
| 116 | List service/node/stack/task | ADA | Benar | cluster.go:372-382 |
| 117 | Task satu service/stack | SEBAGIAN P2 | Benar | cluster.go:377 loop semua service |
| 118 | Task gagal --no-trunc | SEBAGIAN P2 | Benar | cluster.go:377 tanpa `--no-trunc` (hanya di logs :485) |
| 119 | Inspect Swarm | ADA | Benar | cluster.go:441-442 |
| 120 | List secret/config/network | SEBAGIAN P2 | Benar | cluster.go:379-381 |
| 121 | Log service | ADA | Benar | cluster.go:484-489 |
| 122 | Update image service | TIDAK ADA P1 | Benar | cluster.go:894 `service update` = write; tidak ada perintah first-class |
| 123 | Rollback service | TIDAK ADA P1 | Benar | cluster.go:894 default write; tidak ada first-class |
| 124 | Restart (force update) | ADA | Benar | cluster.go:561-562 |
| 125 | Tunggu konvergensi | TIDAK ADA P1 | Benar | cluster.go:562/631/684 `--detach` |
| 126 | Scale Swarm | ADA | Benar | cluster.go:627-631 |
| 127 | Deploy stack | ADA | Benar | cluster.go:680-684 |
| 128 | Stack deploy auth registry | TIDAK ADA P2 | Benar | grep with-registry-auth: 0 hasil |
| 129 | File relatif compose | SEBAGIAN P2 | Benar | cluster.go:684 `-c -` lewat stdin; grep docs relative/env_file: 0 hasil |
| 130 | Diff / dry-run stack | SEBAGIAN P3 | Benar | exec.go:212-228 dry-run hanya perintah |
| 131 | Hapus service/stack | ADA | Benar | cluster.go:777-785 |
| 132 | Node drain/active/pause | SEBAGIAN P2 | Benar | cluster.go:891 node update --availability destructive |
| 133 | Promote/demote, label | SEBAGIAN P3 | Benar | cluster.go:888 demote destructive; lainnya write |
| 134 | Buat secret/config Swarm | SEBAGIAN P2 | Dikoreksi: bukti (stdin tidak diteruskan) | cluster.go:953 `runOne` stdin nil; exec.go:318-321 |
| 135 | Init/join swarm | SEBAGIAN P3 | Benar | cluster.go:889 `swarm` destructive; tanpa redaksi output |
| 136 | Network overlay | SEBAGIAN P3 | Benar | cluster.go:894 (network create = write) |
| 137 | ps terstruktur | ADA | Benar | modules.go:302 `ps -a` + parseJSONLines |
| 138 | Filter ps | TIDAK ADA P2 | Benar | modules.go:302 tanpa flag filter |
| 139 | Container unhealthy | SEBAGIAN P2 | Benar | ops.go:134 `docker-overview` (teks) |
| 140 | Stats | ADA | Benar | modules.go:303 |
| 141 | Proses di container | SEBAGIAN P3 | Benar | modules.go:387 raw mutating |
| 142 | Inspect (host) | SEBAGIAN P2 | Benar | modules.go:328-341 tanpa redaksi |
| 143 | Start/stop/restart | ADA | Benar | modules.go:304-314 (mutating=true) |
| 144 | Hapus container | SEBAGIAN P1 | Benar | modules.go:304-311 `rm` mutating; policy.go:34 hanya prune |
| 145 | Kill/pause/update | SEBAGIAN P3 | Benar | modules.go:387 |
| 146 | Run/create container | SEBAGIAN P2 | Benar | modules.go:387; cluster.go:869 (guard hanya di cluster run) |
| 147 | Images | ADA | Benar | modules.go:303 |
| 148 | Pull | ADA | Benar | modules.go:304 |
| 149 | Pull dengan kredensial vault | TIDAK ADA P2 | Benar | grep `docker login` di internal: 0 hasil |
| 150 | Tag/push image | SEBAGIAN P3 | Benar | modules.go:387; `registry copy` ada |
| 151 | Hapus image | SEBAGIAN P3 | Benar | modules.go:387; `registry rm` butuh --allow-dangerous |
| 152 | Build image | SEBAGIAN P3 | Benar | modules.go:387 |
| 153 | Analisis layer | TIDAK ADA P3 | Benar | `registry inspect` (help: digest/size/platform) |
| 154 | Network docker | SEBAGIAN P2 | Benar | modules.go:387 mutating=true |
| 155 | Volume docker | SEBAGIAN P1 | Benar | modules.go:387; policy.go:34 hanya `volume prune -a` |
| 156 | Disk usage | SEBAGIAN P3 | Benar | ops.go:134 |
| 157 | Prune aman | ADA | Benar | ops.go:143 `docker-prune`; policy.go:34 |
| 158 | Events docker | SEBAGIAN P3 | Benar | modules.go:387 |
| 159 | Copy file container | SEBAGIAN P3 | Benar | modules.go:387 |
| 160 | Login registry | SEBAGIAN P3 | Benar | `import --help`: sumber docker; grep login remote: 0 hasil |
| 161 | Docker context | ADA | Benar | exec.go:196 `resolveTargets` |
| 162 | docker raw klasifikasi | SEBAGIAN P1 | Benar | modules.go:387 mutating=true; cluster.go:877 `classifyDocker` hanya dipakai di :927 |
| 163 | Fleet docker | ADA | Benar | exec.go:191-262 `runFleet`/`fanout` |
| 164 | Dashboard TUI | NON-GOAL | Benar | vision.md:227 (NG-3) |
| 165 | Passthrough compose | ADA | Benar | modules.go:361-381 |
| 166 | up/pull/restart/exec | ADA | Benar | modules.go:376-377 mutating; exec.go:212-228 dry-run |
| 167 | ps compose terstruktur | SEBAGIAN P2 | Benar | modules.go:375 `2>&1`, tanpa parse |
| 168 | ls project | ADA | Benar | modules.go:376 prefix `ls` = read |
| 169 | Down compose | SEBAGIAN P1 | Benar | modules.go:376-377 mutating; policy.go tanpa pola compose |
| 170 | Config compose | SEBAGIAN P2 | Benar | modules.go:376 `config` read, tanpa redaksi |
| 171 | Deteksi read-only | SEBAGIAN P3 | Benar | modules.go:376 |
| 172 | Logs follow compose | SEBAGIAN P3 | Benar | modules.go:377 `runOne` (buffer) |
| 173 | Edit compose file | ADA | Benar | `fs` (help: replace) dan `cp` |
| 174 | Deploy alur + health | SEBAGIAN P2 | Benar | modules.go:361-379 tanpa cek health |
| 175 | Update otomatis image | NON-GOAL | Benar | vision.md:227-228 (NG-3/NG-4) |
| 176 | Output JSON first-class | ADA | Benar | cluster.go:146 `out.P.Print`; modules.go:298 |
| 177 | Output jalan pintas | SEBAGIAN P3 | Benar | cluster.go:1055; modules.go:375/387 |
| 178 | Streaming mode JSON | SEBAGIAN P2 | Dikoreksi: baris 1028-1033→1032-1036 | cluster.go:1032-1036 |
| 179 | Perintah panjang background | SEBAGIAN P2 | Dikoreksi: bukti ("tidak jelas"→tidak didukung untuk k8s) | cluster.go:1031-1037 foreground; job.go hanya SSH |
| 180 | Klasifikasi risk konsisten | SEBAGIAN P1 | Benar | cluster.go:624-626, 787, 862; modules.go:311/377/387 |
| 181 | Dry-run semua perubahan | SEBAGIAN P3 | Benar | cluster.go:782-783 blokir sebelum dry-run; exec.go:212 |
| 182 | Hint rollback | TIDAK ADA P2 | Benar | cluster.go:581/647/710 tanpa nilai lama |
| 183 | Selector @grup cluster | TIDAK ADA P2 | Benar | cluster.go:59 |
