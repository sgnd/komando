#!/usr/bin/env bash
# Runs komando's PowerShell for real: the opt-in tests in
# internal/cli/windows_pwsh_test.go against PowerShell 7 in a container of
# their own (a random name, removed afterwards). It does not use the shared
# e2e lab. PowerShell 7 on Linux is not Windows: see docs/design/windows.md.
#
#   make e2e-windows
set -euo pipefail
cd "$(dirname "$0")/../.."
name="komando-pwsh-$$-$RANDOM"
# amd64: the image has no arm64 build; on Apple silicon Docker runs it
# through Rosetta, where .NET needs a heap limit
docker run -d --rm --platform linux/amd64 --name "$name" --entrypoint /bin/sh \
  mcr.microsoft.com/powershell:latest -c 'sleep 3600' >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
KOMANDO_PWSH_CONTAINER="$name" go test ./internal/cli -run 'PwshReal' -count=1 -v -timeout 20m
