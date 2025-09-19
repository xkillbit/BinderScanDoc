# Run the following commands:

## Clone and Change Directory
```bash
git clone https://github.com/xkillbit/BinderScanDoc.git; cd BinderScanDoc
```

### Example Command with defaults against the CIDR of your choice
```bash
docker-compose run --rm binderscan -r [CIDR]
```

### Example Command with defaults against multiple CIDRs
```bash
docker-compose run --rm binderscan -r [CIDR],[CIDR],[CIDR],[CIDR]
```

Results are saved into `logs/discovery-outfile-run-on-<timestamp>.csv`

# USAGE

```bash
usage: docker-compose run --rm binderscan [-h] -r IP_RANGE [-u] [-n] [-a] [-p]

Network discovery smart scanner (fping + nmap + masscan)

Options:
  -h, --help            show this help message and exit
  -r                    IP_RANGE, --range IP_RANGE
                        ENTER NETWORK CIDR RANGE - e.g., 192.168.0.0/24
  -u, --no-udp          Disable async UDP probes (masscan)
  -n, --no-nmap         Disable nmap TCP probes
  -a, --no-tcp-async    Disable async TCP probes (masscan)
  -p, --no-ping         Disable ICMP probes (fping)
```
