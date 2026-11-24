---
id: "01"
area: core
expects: []
cap_steps: 40
cap_minutes: 20
check: lab:ssh-uptime-ran
---

# Add a server with a password and run uptime

Add the server `direct` (address `127.0.0.1`, user `root`, its password is the one in the file `/lab/direct.pw`) to the list, then run `uptime` on it and tell me the result.
