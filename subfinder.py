#!/usr/bin/env python3
import requests
import json
import time
import sys
from concurrent.futures import ThreadPoolExecutor

# ==============================
# CONFIG
# ==============================
INPUT_FILE = "domains.txt"
OUTPUT_FILE = "subdomains.txt"
TIMEOUT = 10   # seconds for each request
MAX_RETRIES = 2

# ==============================
# Utility
# ==============================
def fetch_url(url, headers=None):
    """Fetch data with retry and timeout"""
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT)
            if r.status_code == 200:
                return r.text
        except requests.RequestException:
            time.sleep(2)  # wait before retry
    return None

# ==============================
# Data Sources
# ==============================
def from_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = fetch_url(url)
    subs = set()
    if data:
        try:
            for entry in json.loads(data):
                subs.add(entry['name_value'])
        except Exception:
            pass
    return subs

def from_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    data = fetch_url(url)
    subs = set()
    if data:
        for line in data.splitlines():
            parts = line.split(",")
            if parts:
                subs.add(parts[0])
    return subs

def from_threatcrowd(domain):
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    data = fetch_url(url)
    subs = set()
    if data:
        try:
            js = json.loads(data)
            for s in js.get("subdomains", []):
                subs.add(s)
        except Exception:
            pass
    return subs

# ==============================
# Main Logic
# ==============================
def enumerate_subdomains(domain):
    print(f"[*] Enumerating subdomains for {domain}")
    all_subs = set()
    
    sources = [from_crtsh, from_hackertarget, from_threatcrowd]
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(src, domain) for src in sources]
        for f in futures:
            try:
                subs = f.result()
                all_subs.update(subs)
            except Exception:
                pass
    
    # Cleanup: remove wildcards and duplicates
    clean_subs = set()
    for s in all_subs:
        s = s.lower().strip()
        if "*" not in s and s.endswith(domain):
            clean_subs.add(s)
    
    return clean_subs

def main():
    try:
        with open(INPUT_FILE, "r") as f:
            domains = [d.strip() for d in f if d.strip()]
    except FileNotFoundError:
        print(f"[!] File {INPUT_FILE} not found")
        sys.exit(1)
    
    all_results = {}
    for domain in domains:
        subs = enumerate_subdomains(domain)
        all_results[domain] = subs
        with open(OUTPUT_FILE, "a") as f:
            for s in subs:
                f.write(s + "\n")
        print(f"[+] {domain}: Found {len(subs)} subdomains")
    
    print(f"\n[✔] Done. Results saved in {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
