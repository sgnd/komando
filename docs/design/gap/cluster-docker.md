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
  ("Bukan tujuan").
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
  terstruktur. Flag `--context/--kubeconfig/--as/--token/--dry-run` ditolak.
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
| Namespace default per cluster (ganti) | kubens, `kubectl config set-context --namespace` | SEBAGIAN | Namespace default diambil dari context kubeconfig saat impor (kube.go:240); `--namespace` per perintah. Tidak ada cara mengubah default namespace sebuah conn tanpa impor ulang (tidak ada `conn edit --option namespace=`) | P2 - mengurangi salah namespace dan flag berulang |
| Exec auth plugin (EKS/GKE/AKS token) | kubectl | ADA | `bearer()` menjalankan plugin exec (kube.go:256); docs/features/cluster.md | - |
| API server privat lewat bastion/VPN | kubectl + ssh tunnel manual, Lens | ADA | `conn edit prod --via bastion`; kubectl di `cluster run` lewat tunnel lokal (`forwardLocal`) dengan TLS server name asli | - |
| Docker Swarm sebagai target | `docker context`, Portainer | ADA | Server manager dipakai langsung sebagai target (`resolveCluster`) | - |
| Docker host remote | `docker context`, `DOCKER_HOST=ssh://` | ADA | Semua `komando docker ... TARGET` lewat SSH; mendukung selector `@grup` (fleet paralel) | - |
| Satu perintah ke banyak cluster sekaligus | k9s (tidak), kubectl (tidak), Lens (catalog) | TIDAK ADA | `resolveCluster` menolak >1 cluster: "this command works on one" (cluster.go:59). Untuk `docker` fleet bisa | P2 - vision: selector `@prod` universal; `cluster status @prod` untuk ringkasan semua cluster |
| Cek koneksi cluster | `kubectl cluster-info`, `kubectl version` | ADA | `komando test <conn>`, `cluster status` (versi) | - |
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
| Ringkasan kesehatan cluster | Lens overview, k9s pulses, popeye | SEBAGIAN | `cluster status`: versi, node ready, pod "not running" berdasar **phase** saja (cluster.go:233). Pod `CrashLoopBackOff`/`ImagePullBackOff` sering ber-phase `Running`/`Pending`→ CrashLoop terlewat; deployment `ready < desired`, node pressure (Memory/Disk/PID), PVC Pending, Job gagal, events Warning tidak dilaporkan | P1 - janji perintah "what is not healthy"; agent mengandalkannya |
| Ringkasan kesehatan Swarm | Portainer, `docker service ls` | SEBAGIAN | `cluster status swarm1` hanya mengembalikan JSON mentah `docker info/node ls/service ls`; tidak menghitung layanan dengan replicas `1/3`, node Down/Drain, task gagal | P2 |
| Lint/sanitasi konfigurasi (tanpa limit, latest tag, probe hilang) | popeye, kube-score, Polaris | TIDAK ADA | - | P3 - "nice to have", bukan 80% harian |
| Pohon kepemilikan (Deployment→RS→Pod) | kubectl-tree, Lens | TIDAK ADA | - | P3 |
| Penggunaan CPU/mem pod & node | `kubectl top`, k9s, Lens | TIDAK ADA | Workaround `cluster run -- top pods -A` (read, butuh metrics-server, teks) | P2 - pertanyaan harian "siapa yang makan memori" |
| Kapasitas: request/limit vs allocatable per node | kube-capacity, Lens | TIDAK ADA | Workaround `cluster run -- describe nodes` | P2 |
| Daftar tipe resource | `kubectl api-resources` | SEBAGIAN | Discovery ada di dalam (kube.go:353) tapi tidak diekspos; `cluster run -- api-resources` (read) | P3 |
| Dokumentasi field | `kubectl explain` | SEBAGIAN | Hanya `cluster run -- explain deploy.spec` (read) | P3 |
| Watch perubahan (`-w`) | `kubectl get -w`, k9s | NON-GOAL | NG-3/NG-4 (bukan TUI, bukan monitoring terus-menerus); `cluster run -- get pods -w` hanya mode teks | - |
| Dashboard interaktif | k9s, Lens, lazydocker, Portainer UI | NON-GOAL | NG-3: "GUI, TUI ... komando tetap CLI murni" | - |

## 3. Logs

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Log satu pod, tail N, since, timestamps | `kubectl logs --tail --since --timestamps` | ADA | `cluster logs TARGET POD -n --since` (timestamps selalu) | - |
| Pilih container, run sebelumnya | `kubectl logs -c`, `--previous` | ADA | `--container/-c`, `--previous` | - |
| Follow (`-f`) pod | `kubectl logs -f`, stern | TIDAK ADA | `cluster logs` tidak punya `--follow`, padahal ux.md:108 menjanjikan `-f` untuk follow dan `komando logs --follow` sudah ada untuk host. Workaround `cluster run -- logs -f POD` (mode teks saja; mode JSON menahan output sampai selesai) | P1 - kebutuhan harian saat deploy; konsistensi verb `logs` |
| Log by workload (`deploy/api`, `svc/x`) | `kubectl logs deploy/api` | TIDAK ADA | Path selalu `pods/<nama>` (cluster.go:503); harus cari nama pod dulu | P1 - nama pod acak berubah tiap rollout; agent butuh 2 langkah |
| Log banyak pod via selector / regex nama | stern, kail, `kubectl logs -l` | TIDAK ADA | Tidak ada `--selector`; `cluster run -- logs -l app=api --prefix` sebagai jalan pintas | P1 - layanan multi-replica: error bisa di replica mana saja |
| Semua container dalam pod | `kubectl logs --all-containers` | TIDAK ADA | Workaround `cluster run` | P2 - sidecar (istio, cloudsql-proxy) |
| Filter isi log (grep) | stern `--include/--exclude` | TIDAK ADA | `komando logs` (host) punya `--grep`, `cluster logs` tidak | P2 - konsistensi dengan `logs --grep` |
| `--until` / rentang waktu | journalctl, docker logs `--until` | TIDAK ADA | k8s API tidak mendukung until; bisa disaring sisi klien | P3 |
| Log Swarm service (tail, since) | `docker service logs` | ADA | `cluster logs swarm1 web -n --since` (`--no-trunc --timestamps`) | - |
| Follow log Swarm service | `docker service logs -f` | TIDAK ADA | Tidak ada `--follow`; `cluster run swarm1 -- service logs -f web` (buffer sampai timeout) | P2 |
| Log container di host (tail/since/until/grep/follow) | `docker logs`, lazydocker | ADA | `docker logs TARGET C` = `logs TARGET --container C` dengan `-f/--follow`, `--grep`, `--since`, `--until`, `-n` | - |
| Log container di banyak host sekaligus | ctop (tidak), Portainer (per env) | ADA | `komando logs @web --container api` (fleet) | - |
| Log compose project (semua service) | `docker compose logs --tail -f` | SEBAGIAN | `docker compose TARGET -- logs --tail 50` (teks); `-f` lewat runOne di-buffer sampai timeout | P3 |

## 4. Akses dan debug ke workload

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Exec perintah di pod (non-interaktif) | `kubectl exec POD -- cmd` | SEBAGIAN | Hanya `cluster run --write --allow-dangerous -- exec POD -- cmd`. Tidak ada exec first-class dengan `--read-only` seperti `docker exec --read-only`; perintah baca (`cat /etc/app.conf`, `env`) pun harus `--allow-dangerous` | P1 - debug harian; memaksa agent memakai `--allow-dangerous` yang mestinya jarang (aturan 7 AGENTS.md) |
| Exec interaktif (`-it` shell) | `kubectl exec -it`, k9s `s`, Lens | SEBAGIAN | `cluster run ... -- exec -it POD -- sh` jalan di mode teks (stdin terhubung, cluster.go:1032); tidak ada perintah first-class | P2 - untuk manusia; agent tidak butuh |
| Copy file ke/dari pod | `kubectl cp` | SEBAGIAN | `cluster run --write --allow-dangerous -- cp`; tidak ada integrasi dengan `komando cp TARGET:PATH` | P2 |
| Port-forward ke pod/service | `kubectl port-forward`, k9s, Lens | SEBAGIAN | `cluster run --write --allow-dangerous -- port-forward svc/x 8080:80` memblok di foreground; tidak terintegrasi `komando tunnel start` (yang mendukung conn db/host, bukan service k8s) | P1 - akses DB/admin UI internal cluster; agent perlu background + alamat lokal seperti `tunnel start` |
| `kubectl proxy` | kubectl | SEBAGIAN | `cluster run ... -- proxy` (destructive); jarang perlu | P3 |
| Debug container ephemeral / debug node | `kubectl debug` | SEBAGIAN | Hanya lewat `cluster run --allow-dangerous`; tidak bisa `--dry-run` (cluster.go:1015) | P3 |
| Pod sementara (busybox/netshoot) | `kubectl run --rm -it` | SEBAGIAN | `cluster run --write -- run tmp --image=busybox --rm -it` (teks) | P3 |
| Attach | `kubectl attach` | SEBAGIAN | `cluster run` (destructive) | P3 |
| Exec di container (host) | `docker exec` | ADA | `docker exec TARGET C -- cmd` dengan `--read-only`, policy dicek pada perintah dalam (modules.go:350) | - |
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
| Buat Secret/ConfigMap dari file/literal | `kubectl create secret generic --from-literal`, `create configmap` | SEBAGIAN | `cluster run --write -- create secret ...` membuat nilai rahasia tampak di argumen/audit (ada `redactArgs`, cluster.go:1110, perlu dicek cakupannya); tidak ada integrasi `komando secret` (vault) → Secret k8s | P2 - vision mengelola secrets; jalur aman dari vault ke cluster |
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
| Impersonation `--as` | kubectl | NON-GOAL (sengaja ditolak) | `kubectlForbidden` menolak `--as`, `--token`, `--context` (cluster.go:810): identitas ditentukan conn. Keputusan safety, bukan gap | - |
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
| Kustomize build | kustomize | NON-GOAL | NG-2 (IaC/GitOps); bisa di-pipe ke `cluster apply --file -` | - |
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
| Buat secret/config Swarm | `docker secret create`, `config create` | SEBAGIAN | `cluster run --write -- secret create NAME -` tanpa jalur stdin dari vault `komando secret` | P2 - rahasia app di Swarm; nilai sebaiknya dari vault, bukan argumen |
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
| Streaming di mode JSON (follow, rollout status, port-forward) | - | SEBAGIAN | `runKubectl` menahan output sampai proses selesai di mode JSON (cluster.go:1028-1033); perintah panjang perlu `job start` | P2 |
| Perintah panjang di background | - | SEBAGIAN | `komando job start` ada untuk host; untuk `cluster run` (kubectl lokal) tidak jelas didukung | P2 - rollout/drain bisa > 2 menit (AGENTS.md aturan 6) |
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
| TIDAK ADA | 42 |
| NON-GOAL | 12 |

Prioritas gap (SEBAGIAN + TIDAK ADA): P1 = 23, P2 = 50, P3 = 52.
(Baris "Impersonation `--as`" dihitung NON-GOAL karena sengaja ditolak demi safety.)

## 10 gap P1 teratas (urutan dampak)

1. **Klasifikasi risk docker di host tidak konsisten**: `docker rm -f/-v`,
   `docker raw -- volume rm`, `docker compose down -v`, `docker raw -- run
   --privileged` hanya "mutating"; `docker raw` tidak membedakan read. Pakai
   ulang `classifyDocker` + `--write`/`--allow-dangerous` seperti `cluster run`.
2. **Kebocoran Secret lewat `cluster run -- get secret -o yaml`** (diklasifikasi
   read, tidak di-redact).
3. **`cluster status` melewatkan CrashLoopBackOff/ImagePullBackOff**,
   deployment tidak lengkap, node pressure (hanya phase).
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
