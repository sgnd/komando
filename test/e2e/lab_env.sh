# shellcheck shell=bash
# Sourced by run.sh and lib.sh: the lab runs komando on this computer, and
# must never reach the person's home folder, login keychain, desktop
# keyring or ssh-agent (gaps C117).

# lab_refuse_here stops the lab where komando cannot be kept off the login
# keychain: on macOS an AI agent's call keeps the store's change count in
# the default keychain whatever KOMANDO_KEYCHAIN says
# (internal/vault/keychain.go, countOff), so the agent checks would write to
# the person's login keychain. CI runs the lab on Linux.
lab_refuse_here() {
  if [ "$(uname)" = Darwin ]; then
    echo "the e2e lab does not run on macOS: its AI-agent checks would read and write this Mac's login keychain (komando keeps an agent's store change count there). Run it in CI or on a Linux machine." >&2
    return 1
  fi
}

# lab_env gives every komando call of this run its own empty home: a fresh
# HOME (and USERPROFILE and the XDG folders), no desktop keyring bus, and
# no ssh-agent, so nothing of the person's is read or written.
lab_env() {
  LAB_HOME="$(mktemp -d)" || return 1
  export HOME="$LAB_HOME" USERPROFILE="$LAB_HOME"
  export XDG_CONFIG_HOME="$LAB_HOME/.config" XDG_DATA_HOME="$LAB_HOME/.local/share" XDG_CACHE_HOME="$LAB_HOME/.cache" XDG_STATE_HOME="$LAB_HOME/.local/state"
  unset DBUS_SESSION_BUS_ADDRESS SSH_AUTH_SOCK
}
