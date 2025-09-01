#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main Orchestrator for Subdomain + SSL Scan
- Validates dependencies
- Creates timestamped results folder
- Runs: subfinder -> sslsub -> txttoexcel
- Collects all results in one folder
- Copies Excel file into Downloads
"""

import os
import sys
import subprocess
import datetime
import importlib
import shutil

# ==============================
# Dependency check + install
# ==============================
DEPENDENCIES = [
    "requests",
    "openpyxl"
]

def ensure_dependencies():
    for pkg in DEPENDENCIES:
        try:
            importlib.import_module(pkg)
        except ImportError:
            print(f"[!] {pkg} not found, installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

# ==============================
# Run script helper
# ==============================
def run_script(script, args=None):
    print(f"\n[>] Running {script} ...")
    cmd = [sys.executable, script]
    if args:
        cmd.extend(args)
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[!] {script} failed!")
        sys.exit(1)

# ==============================
# Main
# ==============================
def main():
    ensure_dependencies()

    # Timestamped folder
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"results_{ts}"
    os.makedirs(outdir, exist_ok=True)
    print(f"[*] Results will be stored in: {outdir}")

    # Copy domains.txt into results folder if exists
    if os.path.exists("domains.txt"):
        shutil.copy("domains.txt", outdir)

    # Step 1: Subfinder -> produces subdomains.txt
    run_script("subfinder.py")
    shutil.move("subdomains.txt", os.path.join(outdir, "subdomains.txt"))

    # Step 2: SSL Labs -> ssl_results.txt
    shutil.copy(os.path.join(outdir, "subdomains.txt"), "results.txt")  # sslsub.py expects results.txt
    run_script("sslsub.py")
    shutil.move("ssl_results.txt", os.path.join(outdir, "ssl_results.txt"))
    os.remove("results.txt")

    # Step 3: Excel
    # Copy ssl_results.txt back into current dir so txttoexcel.py can find it
    shutil.copy(os.path.join(outdir, "ssl_results.txt"), "ssl_results.txt")
    run_script("txttoexcel.py")

    # Handle Excel filename mismatch
    possible_outputs = ["ssl_results_full.xlsx", "ssl_results.xlsx"]
    excel_file = None
    for candidate in possible_outputs:
        if os.path.exists(candidate):
            excel_file = candidate
            break

    if not excel_file:
        print("[!] txttoexcel.py did not produce an Excel file")
        sys.exit(1)

    # Move Excel into results folder
    shutil.move(excel_file, os.path.join(outdir, excel_file))
    os.remove("ssl_results.txt")

    # Optional: copy Excel to Downloads
    downloads_path = os.path.expanduser(f"~/storage/downloads/{excel_file}")
    try:
        shutil.copy(os.path.join(outdir, excel_file), downloads_path)
        print(f"[✓] Excel file also copied to Downloads: {downloads_path}")
    except Exception as e:
        print(f"[!] Could not copy Excel to Downloads: {e}")

    print(f"\n[✓] All tasks completed. See folder: {outdir}")

if __name__ == "__main__":
    main()
