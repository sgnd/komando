# shellcheck shell=bash
# Sourced by the e2e scripts.

# ptyrun INPUT CMD... runs CMD in a pseudo-terminal, as a person typing would:
# INPUT is typed once a [y/N] question shows or after 3s. Prints what the
# terminal showed and exits with CMD's exit code.
ptyrun() {
  python3 -I - "$@" <<'PY'
import os, pty, select, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[2], sys.argv[2:])
out, sent, start = b"", False, time.time()
while time.time() - start < 30:
    if not sent and (b"[y/N]" in out or time.time() - start > 3):
        os.write(fd, sys.argv[1].encode().replace(b"\\n", b"\n")); sent = True
    if select.select([fd], [], [], 0.2)[0]:
        try:
            b = os.read(fd, 4096)
        except OSError:
            break
        if not b:
            break
        out += b
_, st = os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(st))
PY
}

# ptykeys KEYS... -- CMD... runs CMD in a pseudo-terminal and types each KEYS
# once the screen has been still for a moment (a menu waits for keys, so it
# never prints [y/N]). KEYS take escapes: \r Enter, \x1b[B down, \x03 Ctrl-C.
# Prints what the terminal showed and exits with CMD's exit code.
ptykeys() {
  python3 -I - "$@" <<'PY'
import os, pty, select, sys, time
args = sys.argv[1:]
cut = args.index("--")
keys = [k.encode().decode("unicode_escape").encode("latin-1") for k in args[:cut]]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(args[cut + 1], args[cut + 1:])
out, start, last = b"", time.time(), time.time()
while time.time() - start < 60:
    if keys and time.time() - last > 1.5:
        os.write(fd, keys.pop(0)); last = time.time()
    if select.select([fd], [], [], 0.2)[0]:
        try:
            b = os.read(fd, 4096)
        except OSError:
            break
        if not b:
            break
        out += b; last = time.time()
_, st = os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(st))
PY
}
