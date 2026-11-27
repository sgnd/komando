package phonekey

import "strings"

// The scripts run on the server with sh -c SCRIPT NAME ARG...: every
// value reaches them as a positional parameter, never in the script's
// text, and each was checked before (UserName, Line).

// ProbeScript prints the Facts for the user in $1: its uid by id (not by
// name), its home from the user database, who komando logs in as,
// komando's real path with the owner and mode of it and of every folder
// above it, whether that komando has the server mode (asked only when root
// alone could have changed it, as the login may be root), and whether the
// server has a system log, and the owner and mode of each folder of
// PathDirs. It changes nothing.
var ProbeScript = `u=$1
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
p=$r safe=1
while :; do
  s=$(stat -c '%u %a' "$p" 2>/dev/null || stat -f '%u %Lp' "$p" 2>/dev/null) || s='? ?'
  echo "stat $s $p"
  case $s in
    "0 "*[2367]?|"0 "*[2367]|"0 "*[!0-7]*) safe=0 ;;
    "0 "*) ;;
    *) safe=0 ;;
  esac
  [ "$p" = / ] && break
  p=$(dirname "$p")
done
# run that komando only when no one but root can have changed it: the
# login may be root
if [ "$safe" = 1 ] && "$r" ssh-gate --here --name komando-check --help >/dev/null 2>&1; then echo "gate yes"; else echo "gate no"; fi
if [ -S /dev/log ] || [ -S /var/run/syslog ] || [ -S /run/systemd/journal/syslog ]; then echo "syslog yes"; else echo "syslog no"; fi
for d in ` + strings.Join(PathDirs, " ") + `; do
  [ -d "$d" ] || continue
  s=$(stat -L -c '%u %a' "$d" 2>/dev/null || stat -L -f '%u %Lp' "$d" 2>/dev/null) || s='? ?'
  echo "pathdir $s $d"
done
`

// PathDirs are the folders of the PATH the gate gives the commands it runs
// on its server (C549): a program planted in one the paired user can
// write would run as that user at the next allowed command, so C372
// refuses such a server.
var PathDirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// WriteScript adds the line in $2 to $1/.ssh/authorized_keys, run as the
// user who owns that home: "added", "present" (this very line is there),
// "other" (the key is there in another line, which sshd would use first;
// nothing is written) or "symlink PATH" (komando writes through no link).
// $3 is the key's base64 data alone: an older line with other spacing
// between type and key still counts.
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
