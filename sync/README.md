# komando sync library (prototype)

This folder is the open sync format and cryptography used by the Komando
apps. It is a Go module of its own:

```go
import komandosync "github.com/sgnd/komando/sync"
```

The package is named `komandosync`, not `sync`, so it does not hide the
standard library's `sync` package in the files that import it.

## Status

**This is a prototype.** It answers one question: does the sync design work
as written? The freeze re-test passed, so the format can be frozen, but it
is not frozen yet. Do not build on it until it is. What was built, the
test results and the design findings are in
[docs/design/sync-prototype.md](../docs/design/sync-prototype.md).

It needs Go 1.26 or later, the first Go with `crypto/hpke`.

## Not part of the komando CLI

The komando command line never imports this module, so the CLI binary does
not contain it. The CLI never syncs. The library opens no network
connection and has no command; the apps that use it bring their own
transport.

It uses only the Go standard library.

## Test

```
cd sync
go vet ./...
go test -race ./...
```

From the repository root, `make test-sync` runs the same checks. The root
`go test ./...` does not include this folder, because it has its own
`go.mod`.

## Contributing

Outside contributions are welcome under the same terms as komando: before
your first pull request is merged, please sign the
[Contributor License Agreement](../CLA.md). A bot asks you on the pull
request, and you sign once by writing a comment. You keep the copyright of
what you wrote. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## License

AGPL-3.0, like the rest of this repository, and also available under the
[commercial license](../COMMERCIAL-LICENSE.md). See [LICENSE](../LICENSE).
