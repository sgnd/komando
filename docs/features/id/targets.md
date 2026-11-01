# Target

Memilih server dan conn mana yang dikerjakan sebuah perintah. [Semua fitur](README.md)

Sebagian besar perintah menerima *target*. Target memilih server dan conn
(database, cache, storage) sekaligus:

| Tulis | Artinya |
|-------|---------|
| `web1` | satu server atau conn, berdasarkan nama |
| `web-*` | nama yang diawali `web-` |
| `@prod` | semua yang ada di grup `prod` |
| `tag:prod` | semua yang diberi tag `prod` |
| `label:dc=jkt` | semua yang punya label `dc=jkt` |
| `kind:db` | setiap database (juga `kind:host`, `kind:cache`, `kind:storage`, `kind:postgres`, ...) |
| `all` | semuanya |
| `@prod,!web3` | gabungkan dengan `,` dan kecualikan dengan `!` |
| `root@1.2.3.4:22` | server sekali pakai yang tidak ada di daftar Anda |

Setiap perintah memakai yang bisa dikerjakannya dan memberi tahu apa yang
dilewati. Misalnya `komando exec @prod -- uptime` berjalan di server-server
dalam `prod` dan mendaftar database-nya di bagian "skipped";
`komando db query @prod "..."` melakukan kebalikannya. Jika target tidak
memilih apa pun yang bisa dipakai perintah itu, pesan error-nya memberi tahu
perintah mana yang harus dipakai.

Grup, tag, dan label diset saat menambahkan atau mengedit:
`komando host edit web1 --add-group prod --add-tag web --label dc=jkt`, atau
untuk banyak sekaligus, `komando group add prod 'web-*'`.

Lihat apa yang dipilih sebuah target, dan cek apakah semuanya bisa
dijangkau:

```bash
komando list @prod       # server dan conn dalam satu daftar
komando test @prod       # bisakah komando menjangkau dan login ke masing-masing?
```
