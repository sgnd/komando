# Health and network checks

Find out what a server is and whether it is healthy. [All features](README.md)

## Check server health

```bash
komando facts web1               # OS, CPU, memory, disk, IPs, installed tools
komando ops list                 # 39 ready-made checks
komando ops run health @web
komando ops run disk all
komando ops run top-mem web1
komando ops run cert-expiry web1 --var name=example.com
komando ops run updates all
```

## Network checks

Run *from* your servers:

```bash
komando net check @web db.internal:5432 redis.internal:6379
komando net http web1 https://example.com
komando net ports web1 --sudo
komando net dns web1 api.example.com
```
