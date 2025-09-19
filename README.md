# Run the following commands to use after cloning:

## Change Directory
```bash
cd BinderScanDoc
```

## Example Command with defaults against the CIDR of your choice
```bash
docker-compose run --rm binderscan -r [CIDR]
```

## Example Commands - Multiple CIDRs
```bash
cat ranges.txt
192.1.1.0/24
192.1.2.0/24
192.1.3.0/24
```

```bash
for range in $(cat ranges.txt);do docker-compose run --rm binderscan -r $range;done
```

Results are saved into `logs/discovery-outfile-run-on-<timestamp>.csv

# USAGE

```bash
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
