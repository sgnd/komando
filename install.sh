#!/bin/sh
# Install the latest komando release.
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
#
# Installs to /usr/local/bin when writable, otherwise ~/.local/bin.
# Override with KOMANDO_INSTALL_DIR=/some/dir: it is made if missing, and the script
# stops if it cannot write there (it never puts komando somewhere else).
# Install one version with KOMANDO_VERSION=v0.3.1.
#
# A release is installed only when its checksums.txt is signed with the
# komando project's key (checksums.txt.sig), the check `komando update`
# makes, and the archive matches checksums.txt. The check needs OpenSSL 3
# or perl; a computer with neither installs nothing. A release up to 0.13.0
# (they have no signature) installs only with the checksums.txt it was
# released with, which this script knows. To check as well that
# an archive was built by komando's release workflow, download it and run
# `gh attestation verify FILE --repo sgnd/komando` (see SECURITY.md).
set -eu

REPO="sgnd/komando"
# The komando project's release keys (Ed25519 public keys in base64, with a
# space between two): the same list as Keys in internal/releasesig/releasesig.go.
KEYS="GO75zZSPgMzciJXLqfbDrefUFaNQo3sfAZJx1NWxv2k="
# The releases signed before checksums.txt named its version (its first
# line, "komando-release v0.15.0 2026-11-20"): the same list as Unversioned
# in internal/releasesig/releasesig.go. Every later release names it.
UNVERSIONED="v0.14.0 v0.14.1"

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
# v: the version asked for; empty: the newest release
v=
if [ -n "${KOMANDO_VERSION:-}" ]; then
  case "$KOMANDO_VERSION" in
    *[!A-Za-z0-9.+-]* | *..* | .* | -*)
      echo "KOMANDO_VERSION=$KOMANDO_VERSION is not a komando version. Write it as v0.14.1; see https://github.com/$REPO/releases" >&2
      exit 1 ;;
    v*) v=$KOMANDO_VERSION ;;
    *) v=v$KOMANDO_VERSION ;;
  esac
  base="https://github.com/$REPO/releases/download/$v"
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/komando-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
# a komando here already: this run is an update
prev=$(command -v komando 2>/dev/null || true)

# fetch URL FILE: download over HTTPS only, redirects included
fetch() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$2" "$1"
}

# get URL FILE: download, or say in words why not
get() {
  if fetch "$1" "$2"; then return 0; fi
  if [ -n "$v" ]; then
    echo "Could not download komando $v. Is there such a version? See https://github.com/$REPO/releases" >&2
  else
    echo "Could not download komando. Check the internet connection (and HTTPS_PROXY), then run the line again." >&2
  fi
  exit 1
}

# sha256_of FILE: the sha256 of FILE, in hex
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# old_release VERSION: the sha256 of the checksums.txt that VERSION was
# released with, for the releases made before releases were signed (up to
# 0.13.0). One of them installs only with exactly that file, so nobody can
# put other files in its place. Any other version needs a signature.
old_release() {
  case "${1#v}" in
    0.1.0) echo 189d7e417ade91769123d4f25e37f09a71bfef6134377f42e19f233157cd93df ;;
    0.2.0) echo b208838dceddb0515a29e8dfa08b26f56b9c58cfae22f648acb37c198237ae2c ;;
    0.3.0) echo 3c09a61ed0cd4558163ad2fb22487dd2ef747fabd8c8a266a54b01ce082c365b ;;
    0.3.1) echo f29aa9eda3cb2d8b620719635081ecd9485f0fd92df61eb3808d2f73fb7cfcd8 ;;
    0.4.0) echo 29e227971cd48d7045c3589ec666722a965340dc0166bd92514ab4ebab00b415 ;;
    0.5.0) echo 4db2fed021d1ce14a301e494e14a9f348dff2788a1d5581841a350107b677b8e ;;
    0.6.0) echo 08ee66a2daaf79bf69676e4d6fe879f19ec84b639607e675620d69ddef2c48b2 ;;
    0.7.0) echo 9867cf4f114b3e3a9b88f2bb88daa335937e22e3daccc00fb262653969944873 ;;
    0.8.0) echo 15b69146c34c4de7ce00a84eed92c6319e0d9540f4a2b1cc9dba243bd5470094 ;;
    0.9.0) echo 9f5620e21adb3bf53504525214a81ea6d92195142f0303d43cf183c631858244 ;;
    0.10.0) echo 4a4b14e3bdace694903dfcf942cb98ec8b7b63dc05154a2173a72480342cf20c ;;
    0.11.0) echo d3d26bd1225c6abd45a6f5d2e2a77489f571f1797385cb7d08e7bcb95e716b65 ;;
    0.12.0) echo dd1cf9e07b84824ae802bcf15f83867677e4387fe0fb12805765d2b34163cc6c ;;
    0.13.0) echo e0dd5d810fd4aa7c3bbf711e2c16bf6b7f7d299bd11d72033e6ca5bab690c4a6 ;;
  esac
}

# checked_by PROGRAM KEY SIGNATURE: PROGRAM finds that SIGNATURE (base64) is
# the signature of checksums.txt by KEY (base64)
checked_by() {
  case "$1" in
    openssl)
      # the key as OpenSSL reads it: the 12 bytes that say "Ed25519 public
      # key" (MCowBQYDK2VwAyEA in base64), then the key
      printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$2" '-----END PUBLIC KEY-----' >"$tmp/key"
      printf '%s' "$3" | openssl base64 -d -A >"$tmp/sig" 2>/dev/null || return 1
      openssl pkeyutl -verify -pubin -inkey "$tmp/key" -rawin -in "$tmp/checksums.txt" -sigfile "$tmp/sig" >/dev/null 2>&1
      ;;
    perl) perl -e "$ed25519_pl" "$2" "$3" "$tmp/checksums.txt" >/dev/null 2>&1 ;;
  esac
}

# can_check PROGRAM: PROGRAM is here and can check an Ed25519 signature
# (the openssl of macOS is LibreSSL, which cannot; OpenSSL 3 can)
can_check() {
  command -v "$1" >/dev/null 2>&1 || return 1
  case "$1" in
    openssl) openssl pkeyutl -help 2>&1 | grep -q -e -rawin ;;
    perl) perl -MMath::BigInt -MDigest::SHA -MMIME::Base64 -e 1 >/dev/null 2>&1 ;;
  esac
}

# Ed25519 (RFC 8032) in perl, for a computer without OpenSSL 3: ends with 0
# when the signature (base64) of the file is by the key (base64).
# shellcheck disable=SC2016 # perl's variables, not the shell's
ed25519_pl='
use strict; use warnings;
use Math::BigInt; use Digest::SHA qw(sha512); use MIME::Base64;
my ($key, $sig) = map { decode_base64($_) } @ARGV[0, 1];
exit 1 unless length($key) == 32 && length($sig) == 64;
open(my $fh, "<:raw", $ARGV[2]) or exit 1;
my $msg = do { local $/; <$fh> };
my $two255 = Math::BigInt->new(2)->bpow(255);
my $p = $two255 - 19;
my $L = Math::BigInt->new(2)->bpow(252) + Math::BigInt->new("27742317777372353535851937790883648493");
my $d = (Math::BigInt->new(-121665) * Math::BigInt->new(121666)->bmodinv($p)) % $p;
my $sqrtm1 = Math::BigInt->new(2)->bmodpow(($p - 1) / 4, $p);
# a number from its bytes, lowest first
sub num { Math::BigInt->new("0x" . unpack("H*", scalar reverse $_[0])) }
# the point with this y whose x is odd (sign 1) or even (sign 0), if any
sub point {
  my ($y, $sign) = @_;
  return if $y >= $p;
  my $xx = (($y * $y - 1) * (($d * $y * $y + 1) % $p)->bmodinv($p)) % $p;
  my $x = $xx->copy->bmodpow(($p + 3) / 8, $p);
  $x = ($x * $sqrtm1) % $p if ($x * $x - $xx) % $p != 0;
  return if ($x * $x - $xx) % $p != 0;
  return if $x == 0 && $sign == 1;
  $x = $p - $x if $x % 2 != $sign;
  return [$x, $y, Math::BigInt->new(1), ($x * $y) % $p];
}
sub add {
  my ($P, $Q) = @_;
  my $A = (($P->[1] - $P->[0]) * ($Q->[1] - $Q->[0])) % $p;
  my $B = (($P->[1] + $P->[0]) * ($Q->[1] + $Q->[0])) % $p;
  my $C = (2 * $P->[3] * $Q->[3] * $d) % $p;
  my $D = (2 * $P->[2] * $Q->[2]) % $p;
  my ($E, $F, $G, $H) = ($B - $A, $D - $C, $D + $C, $B + $A);
  return [($E * $F) % $p, ($G * $H) % $p, ($F * $G) % $p, ($E * $H) % $p];
}
sub mul {
  my ($n, $P) = @_;
  my $Q = [Math::BigInt->new(0), Math::BigInt->new(1), Math::BigInt->new(1), Math::BigInt->new(0)];
  for my $bit (split //, substr($n->as_bin, 2)) {
    $Q = add($Q, $Q);
    $Q = add($Q, $P) if $bit;
  }
  return $Q;
}
sub bytes {
  my $P = shift;
  my $zi = $P->[2]->copy->bmodinv($p);
  my ($x, $y) = (($P->[0] * $zi) % $p, ($P->[1] * $zi) % $p);
  $y = $y + $two255 if $x % 2 == 1;
  my $h = substr($y->as_hex, 2);
  return scalar reverse pack("H*", ("0" x (64 - length $h)) . $h);
}
my $base = point((4 * Math::BigInt->new(5)->bmodinv($p)) % $p, 0);
my $ky = num($key);
my $A = point($ky % $two255, $ky >= $two255 ? 1 : 0) or exit 1;
my $s = num(substr($sig, 32));
exit 1 if $s >= $L;
my $h = num(sha512(substr($sig, 0, 32) . $key . $msg)) % $L;
my $negA = [($p - $A->[0]) % $p, $A->[1], $A->[2], ($p - $A->[3]) % $p];
exit(bytes(add(mul($s, $base), mul($h, $negA))) eq substr($sig, 0, 32) ? 0 : 1);
'

# check_signature: stop unless checksums.txt is signed with one of KEYS
check_signature() {
  refused="nothing was installed. Do not install it another way: someone may have replaced the release's files.
Run the line again; if it happens again, report it privately at https://github.com/$REPO/security"
  rc=0
  fetch "$base/checksums.txt.sig" "$tmp/checksums.txt.sig" 2>/dev/null || rc=$?
  # curl ends with 22 when the release has no such file
  if [ "$rc" -eq 22 ]; then
    echo "This release has no signature (checksums.txt.sig), so the installer cannot tell it comes from the komando project; $refused" >&2
    exit 1
  elif [ "$rc" -ne 0 ]; then
    echo "Could not download the release's signature (checksums.txt.sig), so nothing was installed. Check the internet connection (and HTTPS_PROXY), then run the line again." >&2
    exit 1
  fi
  # a signature is 64 bytes: 88 characters of base64, one signature a line
  sigs=$(tr -d '\r' <"$tmp/checksums.txt.sig" | head -n 8 | grep -E '^[A-Za-z0-9+/]{86}==$' || true)
  if [ -z "$sigs" ]; then
    echo "This release has no signature (its checksums.txt.sig holds none), so the installer cannot tell it comes from the komando project; $refused" >&2
    exit 1
  fi
  able=
  for program in openssl perl; do
    can_check "$program" || continue
    able=yes
    for key in $KEYS; do
      for sig in $sigs; do
        if checked_by "$program" "$key" "$sig"; then return 0; fi
      done
    done
  done
  if [ -z "$able" ]; then
    echo "The installer checks that a release is signed by the komando project, and needs OpenSSL 3 or perl (with Math::BigInt) for that. This computer has neither, so nothing was installed." >&2
    echo "Install one (the package is named openssl or perl), then run the line again." >&2
    exit 1
  fi
  echo "This release is not signed with the komando project's key; $refused" >&2
  exit 1
}

# check_version: stop unless the signed checksums.txt is the release asked
# for: its first line names that version (any version for the newest), or
# it is one of UNVERSIONED asked for by version. Without this the signed
# files of an older release, put under a newer tag, would install.
check_version() {
  refused="nothing was installed. Do not install it another way: someone may have replaced the release's files. Report it privately at https://github.com/$REPO/security"
  # shellcheck disable=SC2046 # the line's words, one argument each
  set -- $(head -n 1 "$tmp/checksums.txt" | tr -d '\r')
  if [ $# -eq 3 ] && [ "$1" = komando-release ]; then
    if [ -n "$v" ] && [ "$2" != "$v" ]; then
      echo "The release under $v holds komando $2; $refused" >&2
      exit 1
    fi
    echo "Installing komando ${2#v} (released $3)"
    return 0
  fi
  for u in $UNVERSIONED; do
    [ "$u" = "$v" ] && return 0
  done
  echo "This release does not name its version, though every release after ${UNVERSIONED##* } does; $refused" >&2
  exit 1
}

echo "Downloading $file ..."
get "$base/$file" "$tmp/$file"
get "$base/checksums.txt" "$tmp/checksums.txt"

old=
[ -z "$v" ] || old=$(old_release "$v")
if [ -n "$old" ]; then
  echo "Note: komando ${v#v} has no signature (releases up to 0.13.0 have none); its files are checked against the checksums it was released with."
  if [ "$(sha256_of "$tmp/checksums.txt")" != "$old" ]; then
    echo "This is not the checksums.txt komando ${v#v} was released with; nothing was installed. Do not install it another way: someone may have replaced the release's files." >&2
    echo "Run the line again; if it happens again, report it privately at https://github.com/$REPO/security" >&2
    exit 1
  fi
else
  echo "Verifying signature ..."
  check_signature
  check_version
fi

echo "Verifying checksum ..."
expected=$(awk -v f="$file" '$2 == f { print $1 }' "$tmp/checksums.txt")
actual=$(sha256_of "$tmp/$file")
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
  echo "  curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | KOMANDO_INSTALL_DIR=${now%/*} sh"
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
  echo "  komando host ssh add web1 ubuntu@203.0.113.10"
  echo "  komando test web1"
  echo "Teach your AI agents (Claude Code, Codex, Cursor, Gemini CLI) to use komando:"
  echo "  komando guide install"
fi
echo "Tab completion of commands and server names: $completion"
echo "Help: komando --help, or https://github.com/$REPO#your-first-five-minutes"
