#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from openpyxl import Workbook

INPUT_FILE = "ssl_results.txt"
OUTPUT_FILE = "ssl_results.xlsx"

# Function to flatten nested JSON
def flatten_json(y, prefix=''):
    out = {}
    if isinstance(y, dict):
        for k, v in y.items():
            out.update(flatten_json(v, f"{prefix}{k}." if prefix else f"{k}."))
    elif isinstance(y, list):
        for i, item in enumerate(y):
            out.update(flatten_json(item, f"{prefix}{i}." ))
    else:
        out[prefix[:-1]] = y
    return out

# Parse file
results = []
current_domain = None
current_json = ""

with open(INPUT_FILE, "r") as f:
    for line in f:
        line = line.strip()

        # Detect domain markers
        if line.startswith("---") and line.endswith("---"):
            # Save previous JSON if exists
            if current_domain and current_json:
                try:
                    data = json.loads(current_json)
                    flat = flatten_json(data)
                    flat["Domain"] = current_domain
                    results.append(flat)
                except Exception:
                    results.append({"Domain": current_domain, "Message": current_json})
            elif current_domain:
                results.append({"Domain": current_domain, "Message": current_json})

            # Start new domain
            current_domain = line.strip("- ").strip()
            current_json = ""
            continue

        # Collect JSON or plain messages
        if line.startswith("{") or current_json.startswith("{"):
            current_json += line
        else:
            current_json = line

# Handle last entry
if current_domain and current_json:
    try:
        data = json.loads(current_json)
        flat = flatten_json(data)
        flat["Domain"] = current_domain
        results.append(flat)
    except Exception:
        results.append({"Domain": current_domain, "Message": current_json})

# Collect all headers
all_headers = set()
for r in results:
    all_headers.update(r.keys())
headers = sorted(list(all_headers))

# Create Excel
wb = Workbook()
ws = wb.active
ws.title = "SSL Results"
ws.append(headers)

for r in results:
    ws.append([r.get(h, "") for h in headers])

wb.save(OUTPUT_FILE)
print(f"Results saved to {OUTPUT_FILE}")
