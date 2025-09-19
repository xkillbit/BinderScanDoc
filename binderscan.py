#!/usr/bin/env python3
import argparse
import datetime
import ipaddress
import random
import subprocess
import pandas as pd
import nmap
from pathlib import Path
import timeit
import json

# ----------- Argument Parsing -----------
parser = argparse.ArgumentParser(description="Network discovery scanner (fping + nmap + masscan)")
parser.add_argument("-r", "--range", dest="ip_range", required=True,
                    help="ENTER NETWORK CIDR RANGE - e.g., 192.168.0.0/24")
parser.add_argument("-u", "--no-udp", action="store_true",
                    help="Disable async UDP probes (masscan)")
parser.add_argument("-n", "--no-nmap", action="store_true",
                    help="Disable nmap TCP probes")
parser.add_argument("-a", "--no-tcp-async", action="store_true",
                    help="Disable async TCP probes (masscan)")
parser.add_argument("-p", "--no-ping", action="store_true",
                    help="Disable ICMP probes (fping)")
args = parser.parse_args()

# ----------- Constants -----------
TOP_20_TCP = ['80','23','443','21','22','25','3389','110','445','139',
              '143','53','135','3306','8080','1723','111','995','993','5900']
TOP_100_UDP = ['7','9','17','19','49','53','67','68','69','80','88','111','120','123','135','136','137','138',
               '139','158','161','162','177','427','443','445','497','500','514','515','518','520','593','623',
               '626','631','996','997','998','999','1022','1023','1025','1026','1027','1028','1029','1030',
               '1433','1434','1645','1646','1701','1718','1719','1812','1813','1900','2000','2048','2049',
               '2222','2223','3283','3456','3703','4444','4500','5000','5060','5353','5632','9200','10000',
               '17185','20031','30718','31337','32768','32769','32771','32815','33281','49152','49153',
               '49154','49156','49181','49182','49185','49186','49188','49190','49191','49192','49193',
               '49194','49200','49201','65024']

tracking = {}

# ----------- Helpers -----------
def get_samples(host_ips, percentage):
    count = max(1, int(len(host_ips) * percentage))
    chosen1 = set(random.sample(host_ips, count))
    remaining1 = set(host_ips) - chosen1
    chosen2 = set(random.sample(remaining1, count)) if remaining1 else set()
    remaining2 = remaining1 - chosen2
    chosen3 = set(random.sample(remaining2, count)) if remaining2 else set()
    return [list(map(str, s)) for s in (chosen1, chosen2, chosen3)]

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()

def classify_network(hosts):
    n = len(hosts)
    if n <= 32512:
        return "C"
    elif n < 16777214:
        return "B"
    return "A"

def update_tracking(ip_range, ip, ports):
    if ip not in tracking[ip_range]["responsive"]:
        tracking[ip_range]["uphost_count"] += 1
        tracking[ip_range]["responsive"][ip] = ports
    else:
        tracking[ip_range]["responsive"][ip].extend(
            p for p in ports if p not in tracking[ip_range]["responsive"][ip]
        )

# ----------- Scans -----------
def fping_sweep(ip_range, host_ips, net_class):
    print(f"[*] PING SWEEP on {ip_range}")
    targets = (ip_range if net_class == "C"
               else " ".join(get_samples(host_ips, 0.1 if net_class == "B" else 0.005)[0]))
    cmd = f"fping -4 --addr -r 1 -a -i 1 -g {targets} 2>/dev/null"
    for ip in run_cmd(cmd):
        update_tracking(ip_range, ip, ["ICMP"])
    print(f"[*] PING SWEEP COMPLETE on {ip_range}")

def masscan_scan(ip_range, ports, proto, net_class, host_ips):
    print(f"[*] Masscan ({proto}) on {ip_range}")
    targets = (ip_range if net_class == "C"
               else " ".join(get_samples(host_ips, 0.1 if net_class == "B" else 0.05)[0]))
    portlist = ",".join(ports)
    cmd = f"masscan {targets} -p{portlist} --rate 100000 --wait 0 --open --output-format json --output-filename -"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        try:
            obj = json.loads(line)
            ip = obj["ip"]
            port = obj["ports"][0]["port"]
            update_tracking(ip_range, ip, [f"{port} ({proto})"])
        except Exception:
            continue
    print(f"[*] Masscan COMPLETE ({proto}) on {ip_range}")

def nmap_top_ports(ip_range, host_ips, net_class):
    print(f"[*] Nmap top 100 TCP ports on {ip_range}")
    nm = nmap.PortScanner()
    targets = (ip_range if net_class == "C"
               else " ".join(get_samples(host_ips, 0.1 if net_class == "B" else 0.005)[0]))
    results = nm.scan(hosts=targets, arguments='-Pn --open -T5 -n --top-ports 100')
    for ip, data in results.get("scan", {}).items():
        ports = [f"{p} (TCP)" for p in data.get("tcp", {}).keys()]
        update_tracking(ip_range, ip, ports)
    print(f"[*] Nmap COMPLETE on {ip_range}")

# ----------- Main Logic -----------
start = timeit.default_timer()
for ip_range in args.ip_range.split(","):
    hosts = list(ipaddress.ip_network(ip_range).hosts())
    net_class = classify_network(hosts)
    tracking[ip_range] = {"net_class": net_class, "uphost_count": 0, "responsive": {}}

    if not args.no_ping: fping_sweep(ip_range, hosts, net_class)
    if not args.no_tcp_async: masscan_scan(ip_range, TOP_20_TCP, "TCP", net_class, hosts)
    if not args.no_nmap: nmap_top_ports(ip_range, hosts, net_class)
    if not args.no_udp: masscan_scan(ip_range, TOP_100_UDP, "UDP", net_class, hosts)

stop = timeit.default_timer()
elapsed = str(datetime.timedelta(seconds=int(stop - start)))

# ----------- Output -----------
dt = datetime.datetime.now().strftime("%Y-%m-%d-%H%M")
Path("logs").mkdir(exist_ok=True)
df = pd.DataFrame.from_dict(tracking, orient="index")
outfile = Path(f"logs/discovery-outfile-run-on-{dt}.csv")
df.to_csv(outfile, index_label="ip range")

print(f"[*] Results written to {outfile}")
print(f"[*] Total runtime: {elapsed}")
