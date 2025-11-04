# FILE: scanner.py
"""
Mini Network Security Scanner (Extended)
Features:
- Multithreaded port scanning using ThreadPoolExecutor
- Optional banner grabbing
- Save scan report to CSV or JSON
- Customizable port range, thread count, timeout
- Service identification for common ports
- Safe to import for tests
"""

import socket
import argparse
import concurrent.futures
import csv
import json
from datetime import datetime
import threading
from typing import List, Optional

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

LOCK = threading.Lock()


def parse_ports(ports_str: Optional[str], start: int, end: int) -> List[int]:
    """Parse a ports string like '22,80,8000-8100' into a sorted list of unique ports.

    If ports_str is falsy, return the list from start to end (inclusive).
    Ports outside 1-65535 are filtered out.
    """
    if ports_str:
        ports = set()
        for part in ports_str.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-')
                try:
                    a_i = int(a)
                    b_i = int(b)
                except ValueError:
                    continue
                if a_i <= b_i:
                    ports.update(range(a_i, b_i + 1))
                else:
                    ports.update(range(b_i, a_i + 1))
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
        return sorted([p for p in ports if 1 <= p <= 65535])
    else:
        s = max(1, start)
        e = min(65535, end)
        if s > e:
            return []
        return list(range(s, e + 1))


def grab_banner(sock, port: int, timeout: float) -> str:
    """Attempt to grab a service banner from an open socket-like object."""
    try:
        sock.settimeout(timeout)
        if port in (80, 8080, 8000):
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            except Exception:
                pass
        else:
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
        data = sock.recv(1024)
        if data:
            try:
                return data.decode('utf-8', errors='ignore').strip()
            except Exception:
                return repr(data)
    except Exception:
        return ''
    return ''


def scan_port(host: str, port: int, timeout: float = 0.5, banner: bool = False):
    """Attempt a TCP connect to host:port and optionally grab a banner.

    Returns a dict with keys 'port', 'service', 'banner' on success, otherwise None.
    """
    result = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            conn_result = s.connect_ex((host, port))
            if conn_result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                banner_text = ''
                if banner:
                    try:
                        banner_text = grab_banner(s, port, timeout)
                    except Exception:
                        banner_text = ''
                result = {
                    'port': port,
                    'service': service,
                    'banner': banner_text
                }
    except Exception:
        return None
    return result


def save_report(results: List[dict], output_path: str) -> None:
    if not results:
        return
    if output_path.lower().endswith('.csv'):
        keys = ['port', 'service', 'banner']
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, '') for k in keys})
    else:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)


def run_scan(target: str, ports: List[int], threads: int, timeout: float, banner: bool, verbose: bool = False) -> dict:
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        raise RuntimeError(f"Unable to resolve target '{target}': {e}")

    start_time = datetime.now()
    if verbose:
        print(f"Scanning {target} ({ip})")
        print(f"Ports to scan: {len(ports)} | Threads: {threads} | Timeout: {timeout}s | Banner: {banner}")
        print(f"Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    open_ports = []
    scanned = 0

    def worker(p):
        nonlocal scanned
        res = scan_port(ip, p, timeout=timeout, banner=banner)
        with LOCK:
            scanned += 1
            if verbose and scanned % max(1, len(ports)//10) == 0:
                print(f"Progress: {scanned}/{len(ports)} ports scanned")
        if res:
            with LOCK:
                open_ports.append(res)
        return res

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            pass

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    open_ports_sorted = sorted(open_ports, key=lambda x: x['port'])

    return {
        'target': target,
        'ip': ip,
        'start_time': start_time.isoformat(),
        'end_time': end_time.isoformat(),
        'duration_seconds': duration,
        'open_ports': open_ports_sorted
    }


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description='Mini Network Security Scanner (extended)')
    parser.add_argument('target', nargs='?', help='Target hostname or IP (required)')
    parser.add_argument('--start', type=int, default=1, help='Start port (default 1)')
    parser.add_argument('--end', type=int, default=1024, help='End port (default 1024)')
    parser.add_argument('--ports', type=str, help='Comma-separated ports or ranges (e.g. 22,80,8000-8100)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default 100)')
    parser.add_argument('--timeout', type=float, default=0.5, help='Socket timeout in seconds (default 0.5)')
    parser.add_argument('--banner', action='store_true', help='Attempt to grab service banners')
    parser.add_argument('--output', type=str, help='Save report to file (.csv or .json). Optional')
    parser.add_argument('--verbose', action='store_true', help='Verbose progress output')

    args = parser.parse_args(argv)

    if not args.target:
        parser.print_help()
        return

    ports = parse_ports(args.ports, args.start, args.end)
    try:
        report = run_scan(args.target, ports, args.threads, args.timeout, args.banner, verbose=args.verbose)
    except RuntimeError as e:
        print(e)
        return

    print(f"\nScan complete for {report['target']} ({report['ip']})")
    print(f"Duration: {report['duration_seconds']:.2f}s | Open ports: {len(report['open_ports'])}\n")

    if report['open_ports']:
        for p in report['open_ports']:
            banner_summary = f" | Banner: {p['banner'][:80]}..." if p['banner'] else ''
            print(f"[OPEN] Port {p['port']} -> {p['service']}{banner_summary}")

    if args.output:
        results = [{'port': p['port'], 'service': p['service'], 'banner': p['banner']} for p in report['open_ports']]
        save_report(results, args.output)
        print(f"Report saved to {args.output}")


if __name__ == '__main__':
    main()


