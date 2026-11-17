#!/usr/bin/env bash
# Signs the macOS komando binaries in DIR (from `make bins`) with the
# project's Developer ID and has Apple notarize them, so Gatekeeper accepts
# them and the Mac app can carry them. The release workflow runs it on a
# macOS runner; CONTRIBUTING.md ("macOS signing") says how to set it up.
#
#   scripts/macos-sign.sh DIR
#
# It reads these secrets from the environment:
#   MACOS_CERT_P12       the "Developer ID Application" certificate with its
#                        private key, exported as .p12, in base64
#   MACOS_CERT_PASSWORD  the password of that .p12
#   APPLE_TEAM_ID        the 10-character team ID the certificate belongs to
#   NOTARY_KEY_P8        an App Store Connect API key (.p8), in base64
#   NOTARY_KEY_ID        that key's ID
#   NOTARY_ISSUER_ID     the issuer ID shown above the API keys
#
# None set: it signs nothing, says so, and the release goes out unsigned.
# Some set: it stops, so a typo never ships unsigned binaries by mistake.
# It writes signed=true or signed=false to $GITHUB_OUTPUT.
set -euo pipefail

dir=${1:?usage: scripts/macos-sign.sh DIR}
out=${GITHUB_OUTPUT:-/dev/null}
vars="MACOS_CERT_P12 MACOS_CERT_PASSWORD APPLE_TEAM_ID NOTARY_KEY_P8 NOTARY_KEY_ID NOTARY_ISSUER_ID"
have=0
missing=""
for v in $vars; do
  if [ -n "${!v:-}" ]; then have=$((have + 1)); else missing="$missing $v"; fi
done
if [ "$have" = 0 ]; then
  echo "::notice::macOS binaries are NOT signed or notarized: the Developer ID secrets are not set up (CONTRIBUTING.md, \"macOS signing\")"
  echo "signed=false" >>"$out"
  exit 0
fi
if [ -n "$missing" ]; then
  echo "::error::macOS signing is set up only in part; missing secrets:$missing"
  exit 1
fi

bins=$(find "$dir" -type f -name komando -path '*komando_darwin_*')
[ -n "$bins" ] || { echo "::error::no macOS komando binaries in $dir"; exit 1; }

work=$(mktemp -d)
keychain="$work/sign.keychain-db"
cleanup() {
  security delete-keychain "$keychain" 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT

# a keychain of its own for the certificate, gone when this script ends
kcpass=$(uuidgen)
security create-keychain -p "$kcpass" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$kcpass" "$keychain"
printf '%s' "$MACOS_CERT_P12" | base64 --decode >"$work/cert.p12"
security import "$work/cert.p12" -k "$keychain" -P "$MACOS_CERT_PASSWORD" -T /usr/bin/codesign >/dev/null
rm -f "$work/cert.p12"
security set-key-partition-list -S apple-tool:,apple: -s -k "$kcpass" "$keychain" >/dev/null
# shellcheck disable=SC2046 # the keychain list is several words
security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')

identity=$(security find-identity -v -p codesigning "$keychain" |
  awk -v team="($APPLE_TEAM_ID)\"" 'index($0, "\"Developer ID Application:") && index($0, team) { print $2; exit }')
if [ -z "$identity" ]; then
  echo "::error::the certificate in MACOS_CERT_P12 is not a \"Developer ID Application\" certificate of team $APPLE_TEAM_ID"
  exit 1
fi

for b in $bins; do
  echo "signing $b"
  codesign --force --options runtime --timestamp --keychain "$keychain" --sign "$identity" "$b"
  codesign --verify --strict --verbose=2 "$b"
  codesign --display --verbose=2 "$b" 2>&1 | grep -q "^TeamIdentifier=$APPLE_TEAM_ID\$" ||
    { echo "::error::$b is not signed by team $APPLE_TEAM_ID"; exit 1; }
done

# Apple notarizes a zip; a bare program cannot hold the ticket (Gatekeeper
# asks Apple for it online), so the binaries themselves stay as they are
ditto -c -k --keepParent "$dir" "$work/komando-macos.zip"
printf '%s' "$NOTARY_KEY_P8" | base64 --decode >"$work/key.p8"
xcrun notarytool submit "$work/komando-macos.zip" \
  --key "$work/key.p8" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" \
  --wait --timeout 30m --output-format json >"$work/result.json" || true
status=$(jq -r '.status // "no answer"' "$work/result.json" 2>/dev/null || echo "no answer")
id=$(jq -r '.id // ""' "$work/result.json" 2>/dev/null || echo "")
if [ "$status" != "Accepted" ]; then
  echo "::error::Apple did not notarize the macOS binaries (status: $status)"
  if [ -n "$id" ]; then
    xcrun notarytool log "$id" --key "$work/key.p8" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" || true
  fi
  exit 1
fi
echo "notarized: submission $id"
echo "signed=true" >>"$out"
