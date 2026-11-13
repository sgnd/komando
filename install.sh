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
  mingw* | msys* | cygwin*)
    echo "This installer is for Linux and macOS. On Windows, download" >&2
    echo "komando_windows_amd64.zip (or _arm64.zip) from https://github.com/$REPO/releases," >&2
    echo "or run this line inside WSL." >&2
    exit 1 ;;
  *) echo "komando supports Linux, macOS and Windows; there is no release for $os." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "There is no komando release for this CPU ($(uname -m)): amd64 and arm64 only." >&2; exit 1 ;;
esac
for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "The installer needs $tool. Install it, then run the line again." >&2; exit 1; }
done

# Where komando goes, checked before anything is downloaded.
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

# get URL FILE: download, or say in words why not
get() {
  if curl -fsSL "$1" -o "$2"; then return 0; fi
  if [ -n "${v:-}" ]; then
    echo "Could not download komando $v. Is there such a version? See https://github.com/$REPO/releases" >&2
  else
    echo "Could not download komando. Check the internet connection (and HTTPS_PROXY), then run the line again." >&2
  fi
  exit 1
}

echo "Downloading $file ..."
get "$base/$file" "$tmp/$file"
get "$base/checksums.txt" "$tmp/checksums.txt"

echo "Verifying checksum ..."
expected=$(grep " $file\$" "$tmp/checksums.txt" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$file" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "The download does not match checksums.txt of its release; nothing was installed." >&2
  echo "Run the line again; if it happens again, report it at https://github.com/$REPO/issues" >&2
  exit 1
fi

# --no-same-owner: run with sudo, tar would otherwise give the file the
# owner it had on the build machine (uid 1001) instead of root.
tar --no-same-owner -xzf "$tmp/$file" -C "$tmp"

# Copy it into the folder under a temporary name, then rename it over the
# old one: a rename never writes into a komando that is running (macOS kills
# a program whose file is changed in place), and nobody runs a half-copied one.
new="$dir/.komando.new.$$"
trap 'rm -rf "$tmp"; rm -f "$new"' EXIT
cp "$tmp/komando" "$new"
chmod 755 "$new"
mv -f "$new" "$dir/komando"

echo "Installed: $dir/komando"
case ":$PATH:" in
  *":$dir:"*) ;;
  *)
    case "${SHELL:-}" in
      */zsh) rc="$HOME/.zshrc" ;;
      */bash) if [ "$os" = darwin ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
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
  echo "Remove that one, or install into its folder instead (with sudo if only root may write there):"
  echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | KOMANDO_INSTALL_DIR=${now%/*} sh"
  echo "\`komando version\` shows which one runs."
fi
echo
# bash: eval, not source <(...), which the bash 3.2 of macOS reads as nothing;
# a new macOS terminal reads ~/.bash_profile, Linux ~/.bashrc
# shellcheck disable=SC2088 # printed for the person to type, ~ and all
if [ "$os" = darwin ]; then bashrc="~/.bash_profile"; else bashrc="~/.bashrc"; fi
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
echo "Help: komando --help, or https://github.com/$REPO#your-first-five-minutes"
