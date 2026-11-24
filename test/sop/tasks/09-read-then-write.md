---
id: "09"
area: data
expects: [WRITE_REQUIRES_FLAG]
cap_steps: 40
cap_minutes: 20
check: lab:pg-row-9001
---

# Read a PostgreSQL table, then write to it

Read the first five rows of the table `orders` in the database `pg`. Then add a row to `orders` with the id 9001.
