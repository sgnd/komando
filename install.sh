#!/bin/sh
# Install the latest komando release.
#
#   curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
#
# Installs to /usr/local/bin when writable, otherwise ~/.local/bin.
# Override with KOMANDO_INSTALL_DIR=/some/dir: it is made if missing, and the script
# stops if it cannot write there (it never puts komando somewhere else).
# Install one version with KOMANDO_VERSION=v0.3.1.
#
# The checksum comes from the same release as the archive. To check that an
# archive was built by komando's release workflow, download it and run
# `gh attestation verify FILE --repo sgnd/komando` (see SECURITY.md).
set -eu

REPO="sgnd/komando"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux | darwin) ;;
  *) echo "komando supports Linux and macOS (on Windows use WSL)." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

file="komando_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/latest/download"
if [ -n "${KOMANDO_VERSION:-}" ]; then
  case "$KOMANDO_VERSION" in v*) v=$KOMANDO_VERSION ;; *) v=v$KOMANDO_VERSION ;; esac
  base="https://github.com/$REPO/releases/download/$v"
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# a komando here already: this run is an update
prev=$(command -v komando 2>/dev/null || true)

echo "Downloading $file ..."
curl -fsSL "$base/$file" -o "$tmp/$file"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"

echo "Verifying checksum ..."
expected=$(grep " $file\$" "$tmp/checksums.txt" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$file" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "Checksum mismatch, aborting." >&2
  exit 1
fi

# --no-same-owner: run with sudo, tar would otherwise give the file the
# owner it had on the build machine (uid 1001) instead of root.
tar --no-same-owner -xzf "$tmp/$file" -C "$tmp"

if [ -n "${KOMANDO_INSTALL_DIR:-}" ]; then
  # A folder you chose: use it or stop. Never put komando somewhere else.
  dir="$KOMANDO_INSTALL_DIR"
  mkdir -p "$dir" 2>/dev/null || true
  if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
    echo "KOMANDO_INSTALL_DIR=$dir is not a folder you can write to." >&2
    echo "Choose another folder, or leave KOMANDO_INSTALL_DIR out to use /usr/local/bin or ~/.local/bin." >&2
    exit 1
  fi
else
  dir="/usr/local/bin"
  if [ ! -w "$dir" ]; then
    dir="$HOME/.local/bin"
    mkdir -p "$dir"
  fi
fi
mv "$tmp/komando" "$dir/komando"
chmod +x "$dir/komando"

echo "Installed: $dir/komando"
case ":$PATH:" in
  *":$dir:"*) ;;
  *)
    case "${SHELL:-}" in
      */zsh) rc="$HOME/.zshrc" ;;
      */bash) rc="$HOME/.bashrc" ;;
      *) rc="your shell's startup file" ;;
    esac
    echo
    echo "Your terminal does not look in $dir yet. Run this line now,"
    echo "and add it to $rc so it stays:"
    echo
    echo "  export PATH=\"$dir:\$PATH\""
    ;;
esac
# another komando earlier in PATH would keep running instead of this one
hash -r 2>/dev/null || true
now=$(command -v komando 2>/dev/null || true)
if [ -n "$now" ] && [ "$now" != "$dir/komando" ]; then
  echo
  echo "Note: your terminal runs another komando first: $now"
  echo "Remove it, or run this installer again with sudo to replace it there."
  echo "\`komando version\` shows which one runs."
fi
echo
# bash: eval, not source <(...), which the bash 3.2 of macOS reads as nothing;
# a new macOS terminal reads ~/.bash_profile, Linux ~/.bashrc
bashrc="~/.bashrc"
[ "$os" = darwin ] && bashrc="~/.bash_profile"
case "${SHELL:-}" in
  */zsh) completion="echo 'source <(komando completion zsh)' >> ~/.zshrc" ;;
  */bash) completion="echo 'eval \"\$(komando completion bash)\"' >> $bashrc" ;;
  *) completion="komando completion --help" ;;
esac
if [ -n "$prev" ]; then
  echo "Updated. Give your AI agents this version's skill too:"
  echo "  komando guide install"
else
  echo "Next: add your first server, then check it:"
  echo "  komando host add web1 ubuntu@203.0.113.10"
  echo "  komando test web1"
  echo "Teach your AI agents (Claude Code, Codex, Cursor, Gemini CLI) to use komando:"
  echo "  komando guide install"
fi
echo "Tab completion of commands and server names: $completion"
echo "Help: komando (a menu), komando --help, or https://github.com/$REPO#your-first-five-minutes"
