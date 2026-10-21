import sys
import re
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

SUSPICIOUS_PATTERNS = {
    "Path Traversal": re.compile(r"(\.\./|\.\.\\|etc/passwd|boot\.ini)", re.IGNORECASE),
    "SQL Injection": re.compile(r"(union.*select|select.*from|waitfor.*delay|information_schema|order\s+by\s+\d+)", re.IGNORECASE),
    "Cross-Site Scripting (XSS)": re.compile(r"(<script|alert\(|javascript:|onerror=)", re.IGNORECASE),
    "Sensitive File Probing": re.compile(r"(\.env|\.git/|wp-config\.php|server-status)", re.IGNORECASE)
}

# Common Log Format (Nginx/Apache)
LOG_PATTERN = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)')

def analyze_log(file_path: str):
    findings = []
    ip_counter = defaultdict(int)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, 1):
                match = LOG_PATTERN.match(line.strip())
                if not match:
                    continue
                
                ip = match.group("ip")
                request_str = match.group("request")
                status = match.group("status")
                
                ip_counter[ip] += 1

                for attack_type, pattern in SUSPICIOUS_PATTERNS.items():
                    if pattern.search(request_str):
                        findings.append({
                            "line": line_number,
                            "ip": ip,
                            "type": attack_type,
                            "request": request_str,
                            "status": status
                        })

    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {file_path}")
        sys.exit(1)

    print(f"\n{Fore.CYAN}=== Log Analysis Report ==={Style.RESET_ALL}")
    print(f"Target File: {file_path}")
    print(f"Total Suspicious Requests Detected: {len(findings)}\n")

    if findings:
        print(f"{'Line':<6} | {'IP Address':<16} | {'Detected Issue':<25} | {'HTTP':<5} | {'Request'}")
        print("-" * 85)
        for item in findings:
            print(f"{item['line']:<6} | {Fore.YELLOW}{item['ip']:<16}{Style.RESET_ALL} | {Fore.RED}{item['type']:<25}{Style.RESET_ALL} | {item['status']:<5} | {item['request'][:35]}...")
        print("-" * 85)

    print(f"\n{Fore.CYAN}=== Top Requesting IP Addresses ==={Style.RESET_ALL}")
    sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in sorted_ips:
        alert = f"{Fore.RED}(High Volume){Style.RESET_ALL}" if count > 50 else ""
        print(f"  {ip:<16} : {count} requests {alert}")
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detector.py <path-to-access.log>")
        sys.exit(1)

    analyze_log(sys.argv[1])