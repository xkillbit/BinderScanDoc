# Run the following commands to use after cloning:

`cd BinderScanDoc`

`docker compose run --rm binderscan -r [CIDR]`

Results are saved into `logs/discovery-outfile-run-on-<timestamp>.csv

# USAGE

```bash
docker-compose run --rm binderscan -h

usage: binderscan.py [-h] -r IP_RANGE [-u] [-n] [-a] [-p]

Network discovery scanner (fping + nmap + masscan)

options:
  -h, --help            show this help message and exit
  -r IP_RANGE, --range IP_RANGE
                        ENTER NETWORK CIDR RANGE - e.g., 192.168.0.0/24
  -u, --no-udp          Disable async UDP probes (masscan)
  -n, --no-nmap         Disable nmap TCP probes
  -a, --no-tcp-async    Disable async TCP probes (masscan)
  -p, --no-ping         Disable ICMP probes (fping)
```
