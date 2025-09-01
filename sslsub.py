#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Improved SSL Labs Scanner (TrullJ/ssllabsscanner compatible)
- Serial (one host at a time) to avoid SSL Labs concurrency limits
- Polls until status == "READY" or "ERROR"
- Backs off if "Concurrent assessment limit reached"
- Saves CSV summary, TXT with full JSON, and per-host JSON files
"""

import socket
import time
import json
import csv
import os
from datetime import datetime

# Import ssllabs module from TrullJ repository (already in your environment)
import ssllabsscanner as ssl

INPUT_FILE = "results.txt"      # one host per line (your list)
OUTPUT_CSV = "ssl_results.csv"
OUTPUT_TXT = "ssl_results.txt"
OUTPUT_DIR = "ssl_reports"

POLL_WAIT = 30                  # seconds between polling a host
BACKOFF_START = 60              # initial backoff when limit reached
BACKOFF_MAX = 600               # cap backoff to 10 minutes
MAX_POLL_MINUTES = 20           # stop polling a host after this many minutes

# ---------- Read Subdomains ---------- #
def read_subdomains(file_path):
    subs = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("---"):
                continue
            subs.append(line)
    # de-dup but preserve order
    seen = set()
    ordered = []
    for s in subs:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    return ordered

# ---------- Check HTTPS (TCP 443 reachable) ---------- #
def has_https(host, port=443, timeout=4):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False

# ---------- Helpers ---------- #
def is_limit_error(resp: dict) -> bool:
    errs = resp.get("errors") or []
    for e in errs:
        if "Concurrent assessment limit" in str(e.get("message", "")):
            return True
    return False

def pretty_ts(ms):
    try:
        return datetime.utcfromtimestamp(ms/1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"

# ---------- Extract useful fields for CSV ---------- #
def extract_summary(data):
    try:
        host = data.get("host", "N/A")
        status = data.get("status", "N/A")
        endpoint = (data.get("endpoints") or [{}])[0]

        ip = endpoint.get("ipAddress", "N/A")
        grade = endpoint.get("grade", "N/A")

        details = endpoint.get("details", {}) if isinstance(endpoint, dict) else {}
        cert = details.get("cert", {}) if isinstance(details, dict) else {}

        subject = cert.get("subject", "N/A")
        issuer = cert.get("issuerLabel", "N/A")
        notBefore = cert.get("notBefore", 0)
        notAfter = cert.get("notAfter", 0)

        valid_from = pretty_ts(notBefore)
        valid_to = pretty_ts(notAfter)

        key_size = cert.get("keySize", "N/A")
        key_algo = cert.get("keyAlgorithm", "N/A")

        # Protocols
        protocols = details.get("protocols", []) if isinstance(details, dict) else []
        proto_list = []
        for p in protocols:
            name = str(p.get("name", "")).strip()
            ver = str(p.get("version", "")).strip()
            proto_list.append((name + " " + ver).strip())
        proto_str = ", ".join([x for x in proto_list if x]) if proto_list else "N/A"

        # Cipher Suites (handshake list order)
        suites = (details.get("suites") or {}).get("list", []) if isinstance(details, dict) else []
        ciphers = [s.get("name", "") for s in suites if s.get("name")]
        cipher_str = ", ".join(ciphers) if ciphers else "N/A"
        strongest = suites[0]["name"] if suites else "N/A"
        weakest = suites[-1]["name"] if suites else "N/A"

        # Chain issues
        chain = details.get("chain", {}) if isinstance(details, dict) else {}
        chain_issues = chain.get("issues", "N/A")

        return [
            host, ip, grade, status, proto_str,
            strongest, weakest, cipher_str,
            subject, issuer, valid_from, valid_to,
            key_algo, key_size, chain_issues
        ]
    except Exception:
        # Keep columns aligned
        return [data.get("host", "N/A")] + ["N/A"] * 13

# ---------- Core scan logic (serial, with backoff) ---------- #
def scan_until_ready(host):
    """
    Uses only functions available in TrullJ wrapper:
      - ssl.resultsFromCache(host)
      - ssl.newScan(host)
    Polls the same host until status is READY/ERROR, handling concurrency limit with backoff.
    """
    # Try cache first
    try:
        cached = ssl.resultsFromCache(host)
    except Exception:
        cached = None

    if cached and cached.get("status") == "READY":
        return cached

    # Start or resume scan
    backoff = BACKOFF_START
    started_at = time.time()
    attempt = 0

    # First call to kick off the assessment (or attach to existing)
    try:
        data = ssl.newScan(host)
    except Exception as e:
        return {"host": host, "status": "ERROR", "error": f"newScan failed: {e}"}

    # Immediate limit handling
    if is_limit_error(data):
        while True:
            wait_for = min(backoff, BACKOFF_MAX)
            print(f"    -> Limit reached; backing off {wait_for}s before retrying {host}...")
            time.sleep(wait_for)
            backoff = min(backoff * 2, BACKOFF_MAX)
            try:
                data = ssl.newScan(host)
            except Exception as e:
                data = {"host": host, "status": "ERROR", "error": f"newScan retry failed: {e}"}
                break
            if not is_limit_error(data):
                break

    # Poll loop
    while True:
        status = data.get("status")
        if status in ("READY", "ERROR"):
            return data

        elapsed_min = (time.time() - started_at) / 60.0
        if elapsed_min >= MAX_POLL_MINUTES:
            data.setdefault("warnings", [])
            data["warnings"].append(f"Stopped polling after {MAX_POLL_MINUTES} minutes.")
            return data

        attempt += 1
        print(f"    -> [{host}] status={status or 'UNKNOWN'} | poll#{attempt} | waiting {POLL_WAIT}s...")
        time.sleep(POLL_WAIT)

        # Re-poll the same host using newScan() again (TrullJ wrapper attaches to existing run)
        try:
            data = ssl.newScan(host)
            if is_limit_error(data):
                # Back off and continue polling
                wait_for = min(backoff, BACKOFF_MAX)
                print(f"    -> Limit reached mid-poll; back off {wait_for}s...")
                time.sleep(wait_for)
                backoff = min(backoff * 2, BACKOFF_MAX)
                # Try one more time to get a non-error status without resetting polling loop counters
                data = ssl.newScan(host)
        except Exception as e:
            # Keep going; transient network issues
            data = {"host": host, "status": "ERROR", "error": f"poll failed: {e}"}
            return data

# ---------- Main ---------- #
def main():
    subdomains = read_subdomains(INPUT_FILE)
    print(f"[*] Found {len(subdomains)} hosts in {INPUT_FILE}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile, \
         open(OUTPUT_TXT, "w", encoding="utf-8") as txtfile:

        writer = csv.writer(csvfile)
        writer.writerow([
            "Host", "IP", "Grade", "Status", "Protocols",
            "Strongest Cipher", "Weakest Cipher", "All Ciphers",
            "Cert Subject", "Cert Issuer", "Valid From", "Valid To",
            "Key Algorithm", "Key Size", "Chain Issues"
        ])

        for sub in subdomains:
            print(f"\n[+] Checking HTTPS: {sub}")
            if not has_https(sub):
                writer.writerow([sub, "N/A", "No HTTPS", "N/A", "N/A",
                                 "N/A", "N/A", "N/A",
                                 "N/A", "N/A", "N/A", "N/A",
                                 "N/A", "N/A", "N/A"])
                txtfile.write(f"\n--- {sub} ---\nHTTPS not found on this host.\n")
                print("    -> HTTPS not found")
                continue

            print(f"    -> Starting/attaching to SSL Labs assessment for: {sub}")
            data = scan_until_ready(sub)

            # CSV summary
            summary = extract_summary(data)
            writer.writerow(summary)

            # Append full JSON to TXT
            txtfile.write(f"\n--- {sub} ---\n")
            txtfile.write(json.dumps(data, indent=2))
            txtfile.write("\n")

            # Save per-host JSON
            with open(os.path.join(OUTPUT_DIR, f"{sub}.json"), "w", encoding="utf-8") as jf:
                json.dump(data, jf, indent=2)

            print(f"    -> Completed: {sub} | status={data.get('status')}")

    print(f"\n[✓] Summary saved in {OUTPUT_CSV}")
    print(f"[✓] Full combined results saved in {OUTPUT_TXT}")
    print(f"[✓] Individual JSON files saved in {OUTPUT_DIR}/")

if __name__ == "__main__":
    main()
