#!/usr/bin/env bash
# Writes the license texts and NOTICE files of everything built into the
# komando binary (Go modules and the Go standard library), for every release
# platform, into one file. `make dist` puts it into each archive.
#
#   scripts/third-party-licenses.sh [OUT]     (make licenses; OUT defaults to dist/THIRD_PARTY_LICENSES)
set -euo pipefail
cd "$(dirname "$0")/.."
GOLICENSES=${GOLICENSES:-github.com/google/go-licenses/v2@v2.0.1}
PLATFORMS=${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}
out=${1:-dist/THIRD_PARTY_LICENSES}
mod=$(go list -m)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# One record per license file: \036 NAME \t VERSION \t SPDX \t URL, then the text.
printf '%s' $'{{range .}}\036{{.Name}}\t{{.Version}}\t{{.LicenseName}}\t{{.LicenseURL}}\n{{.LicenseText}}\n{{end}}' >"$tmp/tpl"
GOBIN="$tmp/bin" go install "$GOLICENSES"
# go-licenses tells the standard library from modules by GOROOT. When go
# runs a downloaded toolchain (GOTOOLCHAIN, go.mod's go line), go-licenses
# does not find that GOROOT by itself and stops at "archive/tar does not
# have module info".
GOROOT=$(go env GOROOT)
export GOROOT
for p in $PLATFORMS; do
  GOOS=${p%/*} GOARCH=${p#*/} CGO_ENABLED=0 "$tmp/bin/go-licenses" report ./cmd/komando \
    --ignore "$mod" --template "$tmp/tpl" 2>"$tmp/err" >>"$tmp/records" || { cat "$tmp/err" >&2; exit 1; }
  GOOS=${p%/*} GOARCH=${p#*/} CGO_ENABLED=0 go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/komando >>"$tmp/mods"
done

# Keep each license file once (by URL), with every license name found in it.
mkdir "$tmp/r"
awk -v dir="$tmp/r" 'BEGIN { RS = "\036"; FS = "\n" }
  NR > 1 {
    split($1, h, "\t"); key = h[4]
    if (!(key in file)) {
      n++; file[key] = dir "/" n; name[key] = h[1] " " h[2]; lic[key] = h[3]
      body = substr($0, length($1) + 2); printf "%s", body > file[key]; close(file[key])
    } else if (index(" " lic[key] ", ", " " h[3] ", ") == 0) lic[key] = lic[key] ", " h[3]
  }
  END { for (k in file) printf "%s\t%s\t%s\t%s\n", name[k], lic[k], k, file[k] > (dir "/index") }' "$tmp/records"

mkdir -p "$(dirname "$out")"
{
  echo "Third-party licenses for komando"
  echo
  echo "The komando binary includes the Go standard library and the Go modules"
  echo "below. Each one's license (and NOTICE file, where it has one) follows."
  echo "The source code of each module is available at the URL given with it."
  echo
  echo "================================================================================"
  echo "Go standard library ($(go env GOVERSION)), BSD-3-Clause, https://go.dev/LICENSE"
  echo "================================================================================"
  cat "$(go env GOROOT)/LICENSE"
  sort "$tmp/r/index" | while IFS=$'\t' read -r name lic url file; do
    echo
    echo "================================================================================"
    echo "$name, $lic, $url"
    echo "================================================================================"
    cat "$file"
  done
  sort -u "$tmp/mods" | while read -r m dir; do
    for f in "$dir"/NOTICE*; do
      [ -f "$f" ] || continue
      echo
      echo "================================================================================"
      echo "NOTICE: $m (${f##*/})"
      echo "================================================================================"
      cat "$f"
    done
  done
} >"$out"
echo "wrote $out ($(sort "$tmp/r/index" | wc -l | tr -d ' ') license files)"
