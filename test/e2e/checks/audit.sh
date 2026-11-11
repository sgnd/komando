# shellcheck shell=bash
# The audit chain, the sealed store and doctor.
check "audit chain intact" True "$($K audit verify | jget 'd["data"]["ok"]')"
check "audit names the agent" True "$($K audit -n 200 | jget 'any(e.get("agent") == "Claude Code" for e in d["data"]["entries"])')"
# a record removed from the middle of the store's audit table
cp "$KOMANDO_HOME/store.db" "$TMP/store.bak"
python3 - "$KOMANDO_HOME/store.db" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
n = db.execute("SELECT max(seq) FROM audit").fetchone()[0]
db.execute("DELETE FROM audit WHERE seq=?", (n // 2,))
db.commit()
PY
check "removed audit record found" AUDIT_TAMPERED "$($K audit verify | jget 'd["error"]["code"]' || true)"
cp "$TMP/store.bak" "$KOMANDO_HOME/store.db"
# nothing in the store can be read without its key
check "no server name readable in store.db" 0 "$(grep -c -a -E 'bastion|direct-sm|agentpass' "$KOMANDO_HOME/store.db" || true)"
check "a sealed folder has no files of before" 0 "$(ls "$KOMANDO_HOME" | grep -c -x -E 'state.json|vault.json|known_hosts|audit.jsonl' || true)"
check "doctor checks security" True "$($K doctor | jget 'any(c["name"] == "security:audit_chain" and c["ok"] for c in d["data"]["security"])')"
