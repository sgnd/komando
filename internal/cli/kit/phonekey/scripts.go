package phonekey

// The scripts run on the server with sh -c SCRIPT NAME ARG...: every
// value reaches them as a positional parameter, never in the script's
// text, and each was checked before (UserName, Line).

// ProbeScript prints the Facts for the user in $1: its uid by id (not by
// name), its home from the user database, who komando logs in as,
// komando's real path with the owner and mode of it and of every folder
// above it, whether that komando has the server mode, and whether the
// server has a system log. It changes nothing.
const ProbeScript = `u=$1
pw=$(getent passwd "$u" 2>/dev/null) || pw=$(awk -F: -v u="$u" '$1 == u' /etc/passwd 2>/dev/null)
if [ -z "$pw" ]; then echo "user none"; exit 0; fi
echo "uid $(id -u "$u")"
echo "home $(printf '%s\n' "$pw" | cut -d: -f6)"
echo "login $(id -un)"
k=$(command -v komando 2>/dev/null)
for c in "$k" /usr/local/bin/komando /usr/bin/komando /opt/komando/bin/komando; do
  if [ -n "$c" ] && [ -x "$c" ]; then k=$c; break; fi
done
if [ -z "$k" ] || [ ! -x "$k" ]; then echo "komando none"; exit 0; fi
r=$(readlink -f "$k" 2>/dev/null || realpath "$k" 2>/dev/null || printf '%s' "$k")
echo "komando $r"
p=$r
while :; do
  s=$(stat -c '%u %a' "$p" 2>/dev/null || stat -f '%u %Lp' "$p" 2>/dev/null) || s='? ?'
  echo "stat $s $p"
  [ "$p" = / ] && break
  p=$(dirname "$p")
done
if "$r" ssh-gate --here --name komando-check --help >/dev/null 2>&1; then echo "gate yes"; else echo "gate no"; fi
if [ -S /dev/log ] || [ -S /var/run/syslog ] || [ -S /run/systemd/journal/syslog ]; then echo "syslog yes"; else echo "syslog no"; fi
`

// WriteScript adds the line in $2 to $1/.ssh/authorized_keys, run as the
// user who owns that home: "added", "present" (this very line is there),
// "other" (the key is there in another line, which sshd would use first;
// nothing is written) or "symlink PATH" (komando writes through no link).
// $3 is the key without options and name (TYPE DATA).
const WriteScript = `h=$1 line=$2 match=$3
umask 077
d=$h/.ssh f=$h/.ssh/authorized_keys
for p in "$d" "$f" "$d/authorized_keys2"; do
  if [ -L "$p" ]; then echo "symlink $p"; exit 0; fi
done
mkdir -p "$d" && chmod 700 "$d" || exit 4
for g in "$f" "$d/authorized_keys2"; do
  if [ -f "$g" ] && grep -qF -- "$match" "$g"; then
    if [ "$g" = "$f" ] && grep -qxF -- "$line" "$g"; then echo present; else echo other; fi
    exit 0
  fi
done
if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then printf '\n' >> "$f" || exit 4; fi
printf '%s\n' "$line" >> "$f" && chmod 600 "$f" || exit 4
echo added
`
