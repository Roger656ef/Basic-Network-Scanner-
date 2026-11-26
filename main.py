#!/usr/bin/env python3
"""pyscan — pure-Python, stdlib-only TCP connect port/host scanner."""

import argparse
import csv
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# --------------------------------------------------------------------------
# Static data
# --------------------------------------------------------------------------

TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1080, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]

PORT_SERVICE = {
    7: "echo", 9: "discard", 13: "daytime", 20: "ftp-data", 21: "ftp",
    22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 53: "dns",
    67: "dhcp-server", 68: "dhcp-client", 69: "tftp", 79: "finger",
    80: "http", 81: "http-alt", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmp-trap", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 520: "router", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1434: "ms-sql-m",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
    3128: "squid-http", 3260: "iscsi", 3306: "mysql", 3389: "ms-wbt-server",
    5060: "sip", 5061: "sips", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "k8s-api", 7001: "weblogic", 8000: "http-alt", 8008: "http",
    8009: "ajp13", 8080: "http-proxy", 8081: "http-alt", 8086: "influxdb",
    8088: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
    9042: "cassandra", 9090: "zeus-admin", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 9999: "abyss", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 50000: "sap", 50070: "hdfs",
}

DISCOVERY_TCP_PORTS = [80, 443, 22, 21, 25, 53, 3389, 8080, 445, 139]

if os.name == "nt":
    errno_ECONNREFUSED = 10061
else:
    errno_ECONNREFUSED = 111

# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    state: str
    service: str = "unknown"
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class HostResult:
    host: str
    up: bool = False
    discovery_method: str = ""
    ports: List[PortResult] = field(default_factory=list)
    error: str = ""

# --------------------------------------------------------------------------
# Target / port parsing
# --------------------------------------------------------------------------

def parse_targets(spec: str) -> List[str]:
    spec = spec.strip()
    if not spec:
        raise ValueError("empty target specification")

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as e:
            raise ValueError(f"invalid CIDR '{spec}': {e}")
        if net.num_addresses > 2:
            return [str(ip) for ip in net.hosts()]
        return [str(net.network_address)]

    if "-" in spec and ":" not in spec.split("-")[0]:
        left, right = spec.split("-", 1)
        try:
            start = ipaddress.IPv4Address(left.strip())
        except ValueError:
            start = None
        if start is not None:
            right = right.strip()
            try:
                if "." in right:
                    end = ipaddress.IPv4Address(right)
                else:
                    prefix = ".".join(str(start).split(".")[:3])
                    end = ipaddress.IPv4Address(f"{prefix}.{right}")
            except ValueError as e:
                raise ValueError(f"invalid IP range '{spec}': {e}")
            if int(end) < int(start):
                raise ValueError(f"range end {end} is before start {start}")
            if int(end) - int(start) > 65535:
                raise ValueError("IP range too large (max 65536 addresses)")
            return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]

    try:
        ipaddress.ip_address(spec)
        return [spec]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(spec, None)
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve host '{spec}': {e}")
    ips = []
    for fam, _, _, _, sockaddr in infos:
        if fam in (socket.AF_INET, socket.AF_INET6):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    if not ips:
        raise ValueError(f"no addresses found for host '{spec}'")
    return ips


def parse_ports(spec: str) -> List[int]:
    if spec is None:
        return list(TOP_PORTS)
    spec = spec.strip().lower()
    if spec in ("top", "common", "default"):
        return list(TOP_PORTS)

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                raise ValueError(f"invalid port range '{chunk}'")
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"invalid port range '{chunk}'")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                raise ValueError(f"invalid port '{chunk}'")
            if p < 1 or p > 65535:
                raise ValueError(f"port out of range: {p}")
            ports.add(p)
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)

# --------------------------------------------------------------------------
# Host discovery
# --------------------------------------------------------------------------

def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_ping(host: str, timeout: float) -> bool:
    if ":" in host:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (PermissionError, OSError):
        return False

    ident = os.getpid() & 0xFFFF
    seq = random.randint(0, 0xFFFF)
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    payload = b"pyscan-discover"
    chksum = _icmp_checksum(header + payload)
    packet = struct.pack("!BBHHH", 8, 0, chksum, ident, seq) + payload

    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, 0))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                break
            if addr[0] != host:
                continue
            if len(data) < 20:
                continue
            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 8:
                continue
            icmp = data[ihl:]
            if icmp[0] == 0 and icmp[1] == 0:
                r_ident, r_seq = struct.unpack("!HH", icmp[4:8])
                if r_ident == ident and r_seq == seq:
                    return True
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return False


def tcp_connect_test(host: str, port: int, timeout: float) -> str:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        r = sock.connect_ex((host, port))
        if r == 0:
            return "open"
        if r == errno_ECONNREFUSED:
            return "closed"
        return "filtered"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def host_discovery(host: str, timeout: float) -> Tuple[bool, str]:
    if icmp_ping(host, timeout):
        return True, "icmp-echo"
    for port in DISCOVERY_TCP_PORTS:
        state = tcp_connect_test(host, port, timeout)
        if state == "open":
            return True, f"tcp-connect:{port}"
        if state == "closed":
            return True, f"tcp-rst:{port}"
    return False, "no-response"

# --------------------------------------------------------------------------
# Service / banner detection
# --------------------------------------------------------------------------

def grab_banner(host: str, port: int, timeout: float) -> str:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) != 0:
            return ""
        nudge = b""
        if port in (80, 8000, 8008, 8080, 8888):
            nudge = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
        elif port == 25:
            nudge = b"EHLO pyscan\r\n"
        elif port == 110:
            nudge = b"USER test\r\n"
        if nudge:
            try:
                sock.sendall(nudge)
            except OSError:
                pass
        sock.settimeout(timeout)
        try:
            data = sock.recv(1024)
        except (socket.timeout, OSError):
            return ""
        if not data:
            return ""
        text = data.decode("utf-8", "replace")
        first = text.splitlines()[0] if text.splitlines() else text
        printable = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in first)
        return printable.strip()[:120]
    finally:
        try:
            sock.close()
        except OSError:
            pass


def classify_service(port: int, banner: str) -> str:
    name = PORT_SERVICE.get(port, "unknown")
    if banner:
        lower = banner.lower()
        if lower.startswith("ssh-"):
            return "ssh"
        if "http/" in lower or lower.startswith("http"):
            return "http" if port not in (443, 8443) else "https"
        if "smtp" in lower or (lower.startswith("220") and "mail" in lower):
            return "smtp"
        if "ftp" in lower:
            return "ftp"
        if "mysql" in lower:
            return "mysql"
        if "redis" in lower:
            return "redis"
    return name

# --------------------------------------------------------------------------
# Per-host scan
# --------------------------------------------------------------------------

def scan_host(host: str, ports: List[int], timeout: float, do_banner: bool) -> HostResult:
    res = HostResult(host=host)
    up, method = host_discovery(host, timeout)
    res.up = up
    res.discovery_method = method
    if not up:
        return res

    for port in ports:
        t0 = time.monotonic()
        state = tcp_connect_test(host, port, timeout)
        latency = (time.monotonic() - t0) * 1000.0
        pr = PortResult(port=port, state=state, latency_ms=round(latency, 2))
        if state == "open":
            if do_banner:
                banner = grab_banner(host, port, timeout)
                pr.banner = banner
                pr.service = classify_service(port, banner)
            else:
                pr.service = PORT_SERVICE.get(port, "unknown")
        res.ports.append(pr)
    return res

# --------------------------------------------------------------------------
# Output formatting
# --------------------------------------------------------------------------

def render_table(results: List[HostResult]) -> str:
    lines = []
    lines.append("=" * 90)
    lines.append("pyscan results")
    lines.append("=" * 90)
    for hr in results:
        if not hr.up:
            lines.append(f"\nHost: {hr.host}  ->  DOWN ({hr.discovery_method})")
            continue
        lines.append(f"\nHost: {hr.host}  ->  UP   (via {hr.discovery_method})")
        open_ports = [p for p in hr.ports if p.state == "open"]
        if not open_ports:
            lines.append("  No open TCP ports found on the tested set.")
            continue
        lines.append(f"  {'PORT':<7}{'STATE':<10}{'SERVICE':<18}{'LAT(ms)':>10}  BANNER")
        lines.append("  " + "-" * 86)
        for p in open_ports:
            banner = p.banner[:60] if p.banner else "-"
            lines.append(
                f"  {p.port:<7}{p.state:<10}{p.service:<18}{p.latency_ms:>10.2f}  {banner}"
            )
    lines.append("\n" + "-" * 90)
    lines.append("NOTE: TCP connect scan only. No SYN/UDP/OS-fingerprinting (requires raw sockets/root).")
    lines.append("Only scan hosts/networks you are authorized to test.")
    lines.append("-" * 90)
    return "\n".join(lines)


def render_json(results: List[HostResult]) -> str:
    payload = {
        "scanner": "pyscan",
        "mode": "tcp-connect",
        "limitations": [
            "No SYN scan, OS fingerprinting, or UDP scan (requires raw sockets/root).",
            "Service names are port-map + best-effort banner heuristics, not a version DB.",
            "Only scan authorized targets.",
        ],
        "hosts": [],
    }
    for hr in results:
        h = {
            "host": hr.host,
            "up": hr.up,
            "discovery_method": hr.discovery_method,
            "open_ports": [],
        }
        for p in hr.ports:
            if p.state == "open":
                h["open_ports"].append({
                    "port": p.port,
                    "state": p.state,
                    "service": p.service,
                    "banner": p.banner,
                    "latency_ms": p.latency_ms,
                })
        payload["hosts"].append(h)
    return json.dumps(payload, indent=2)


def render_csv(results: List[HostResult]) -> str:
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "up", "discovery_method", "port", "state",
                "service", "banner", "latency_ms"])
    for hr in results:
        if not hr.up:
            w.writerow([hr.host, "DOWN", hr.discovery_method, "", "", "", "", ""])
            continue
        opens = [p for p in hr.ports if p.state == "open"]
        if not opens:
            w.writerow([hr.host, "UP", hr.discovery_method, "", "", "", "", ""])
        for p in opens:
            w.writerow([hr.host, "UP", hr.discovery_method, p.port, p.state,
                        p.service, p.banner, f"{p.latency_ms:.2f}"])
    return buf.getvalue()

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyscan",
        description=(
            "Pure-Python TCP connect port/host scanner (stdlib only). "
            "Host discovery, TCP connect scanning, basic service/banner detection, "
            "and JSON/CSV output. Does NOT implement SYN scans, OS fingerprinting, "
            "or UDP scans (those require raw sockets/root)."
        ),
        epilog=(
            "Examples:\n"
            "  python pyscan.py 192.168.1.10\n"
            "  python pyscan.py 192.168.1.0/24 -p 22,80,443\n"
            "  python pyscan.py example.com --ports top --json\n"
            "  python pyscan.py 10.0.0.5-10.0.0.25 -p 1-1024 -t 1.0 -c 200\n\n"
            "AUTHORIZATION: only scan hosts/networks you own or have permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target",
        help="Target: single IP, hostname, CIDR (a.b.c.d/nn), or IP range (a.b.c.d-e.f.g.h or a.b.c.d-ee).")
    p.add_argument("-p", "--ports", default="top",
        help="Ports: single (80), list (22,80,443), range (1-1024), or 'top'. Default: top.")
    p.add_argument("-t", "--timeout", type=float, default=1.0,
        help="Per-connection timeout in seconds. Default: 1.0")
    p.add_argument("-c", "--concurrency", type=int, default=100,
        help="Max concurrent workers. Default: 100")
    p.add_argument("-T", "--threads", type=int, default=None,
        help="Alias for --concurrency (Nmap-style timing flag).")
    p.add_argument("--no-banner", action="store_true",
        help="Skip banner grabbing on open ports.")
    p.add_argument("--json", action="store_true",
        help="Emit machine-readable JSON instead of the terminal table.")
    p.add_argument("--csv", action="store_true",
        help="Emit machine-readable CSV instead of the terminal table.")
    p.add_argument("-o", "--output", default=None,
        help="Write output to this file (otherwise stdout).")
    p.add_argument("--no-discovery", action="store_true",
        help="Skip host discovery; attempt port scans on every target.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.json and args.csv:
        parser.error("--json and --csv are mutually exclusive")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")
    if args.threads is not None:
        if args.concurrency != 100 and args.threads != args.concurrency:
            parser.error("specify only one of --concurrency / --threads")
        args.concurrency = args.threads
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")

    try:
        targets = parse_targets(args.target)
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))

    if len(targets) > 65536:
        parser.error(f"target set too large ({len(targets)} addresses); narrow it")

    start = time.monotonic()
    results: List[HostResult] = []
    max_workers = max(1, args.concurrency)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(scan_host, host, ports, args.timeout, not args.no_banner): host
            for host in targets
        }
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                h = futures[fut]
                results.append(HostResult(host=h, up=False, error=str(e)))

    def sort_key(hr: HostResult):
        try:
            return (0, ipaddress.ip_address(hr.host))
        except ValueError:
            return (1, hr.host)

    results.sort(key=sort_key)

    if args.json:
        out = render_json(results)
    elif args.csv:
        out = render_csv(results)
    else:
        out = render_table(results)

    elapsed = time.monotonic() - start
    if not args.json and not args.csv:
        out += f"\nScan completed in {elapsed:.2f}s over {len(targets)} host(s), {len(ports)} port(s)/host."

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
                if not out.endswith("\n"):
                    fh.write("\n")
        except OSError as e:
            print(f"error: cannot write {args.output}: {e}", file=sys.stderr)
            return 2
    else:
        print(out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
