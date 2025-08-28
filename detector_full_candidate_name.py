#!/usr/bin/env python3
"""
detector_full_candidate_name.py

Usage:
    python3 detector_full_candidate_name.py iscp_pii_dataset.csv

Output:
    redacted_output_candidate_full_name.csv
"""

import sys
import csv
import json
import re
from pathlib import Path

PATTERNS = {
    "phone": re.compile(r"\b[6-9]\d{9}\b"),
    "aadhar": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "passport": re.compile(r"\b[A-Z][0-9]{7}\b"),
    "upi": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9]+\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

COMBINATORIAL_FIELDS = [
    "name",
    "email",
    "address",
    "ip_address",
    "device_id",
    "first_name",
    "last_name",
    "pin_code",
]

def mask_phone(v: str) -> str:
    s = re.sub(r"\D", "", v)
    if len(s) == 10:
        return s[:2] + "XXXXXX" + s[-2:]
    return "[REDACTED_PII]"

def mask_aadhar(v: str) -> str:
    s = re.sub(r"\D", "", v)
    if len(s) == 12:
        return s[:4] + " XXXX XXXX"
    return "[REDACTED_PII]"

def mask_passport(v: str) -> str:
    v = v.strip()
    if len(v) >= 2:
        return v[0] + "XXXXXXX"
    return "[REDACTED_PII]"

def mask_upi(v: str) -> str:
    if "@" in v:
        u, d = v.split("@", 1)
        u_mask = (u[:2] + "XXX") if len(u) > 2 else "XXX"
        return u_mask + "@" + d
    return "[REDACTED_PII]"

def mask_email(v: str) -> str:
    if "@" in v:
        u, d = v.split("@", 1)
        u_mask = (u[:2] + "XXX") if len(u) > 2 else "XXX"
        return u_mask + "@" + d
    return "[REDACTED_PII]"

def mask_ip_or_device(v: str) -> str:
    return "[REDACTED_PII]"

def mask_name(v: str) -> str:
    parts = v.strip().split()
    if len(parts) >= 2:
        masked_parts = []
        for p in parts:
            if len(p) <= 2:
                masked_parts.append(p[0] + "X")
            else:
                masked_parts.append(p[0] + "XXX")
        return " ".join(masked_parts)
    return v[0] + "XXX" if v else "[REDACTED_PII]"

def mask_address(v: str) -> str:
    return "[REDACTED_PII]"

MASKERS = {
    "phone": mask_phone,
    "aadhar": mask_aadhar,
    "passport": mask_passport,
    "upi": mask_upi,
    "email": mask_email,
    "ip_address": mask_ip_or_device,
    "device_id": mask_ip_or_device,
    "name": mask_name,
    "address": mask_address,
}

def detect_standalone_pii(record_json, redacted):
    found_any = False
    for key, val in record_json.items():
        if val is None:
            continue
        if not isinstance(val, str):
            continue
        s = val.strip()
        if PATTERNS["phone"].search(s) and key.lower() in ["phone", "contact", "mobile"]:
            redacted[key] = MASKERS["phone"](s)
            found_any = True
            continue
        if PATTERNS["aadhar"].search(s) and key.lower() in ["aadhar", "aadhar_number", "aadhaar"]:
            redacted[key] = MASKERS["aadhar"](s)
            found_any = True
            continue
        if PATTERNS["passport"].search(s) and key.lower() in ["passport", "passport_no", "passport_number"]:
            redacted[key] = MASKERS["passport"](s)
            found_any = True
            continue
        if PATTERNS["upi"].search(s) and key.lower() in ["upi_id", "upi"]:
            redacted[key] = MASKERS["upi"](s)
            found_any = True
            continue
    return found_any

def count_b_fields(record_json):
    present = []
    for key in COMBINATORIAL_FIELDS:
        key_l = key.lower()
        if key_l not in record_json:
            continue
        v = record_json.get(key_l) if key_l in record_json else record_json.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        if key == "name":
            if len(s.split()) >= 2:
                present.append("name")
        elif key in ("first_name", "last_name"):
            present.append(key)
        elif key in ("address", "ip_address", "device_id", "email", "pin_code"):
            present.append(key)
    return present

def detect_and_redact_record(record_json):
    rc = {k: (v if v is not None else "") for k, v in record_json.items()}
    redacted = {}
    for k, v in rc.items():
        redacted[k] = v if not isinstance(v, str) else v.strip()
    is_pii = False
    standalone_found = detect_standalone_pii(rc, redacted)
    if standalone_found:
        is_pii = True
    found_email = False
    found_ip = False
    for k, v in rc.items():
        if not isinstance(v, str):
            continue
        s = v.strip()
        if not s:
            continue
        if PATTERNS["email"].search(s):
            found_email = True
        if PATTERNS["ip"].search(s):
            found_ip = True
    present_b = count_b_fields({k.lower(): v for k, v in rc.items()})
    unique_b = set(present_b)
    b_count = len(unique_b)
    if b_count >= 2:
        is_pii = True
        for b in unique_b:
            for orig_k in record_json.keys():
                if orig_k.lower() == b:
                    val = str(record_json[orig_k]).strip()
                    if b in ("email",):
                        redacted[orig_k] = mask_email(val)
                    elif b in ("ip_address",):
                        redacted[orig_k] = mask_ip_or_device(val)
                    elif b in ("device_id",):
                        redacted[orig_k] = mask_ip_or_device(val)
                    elif b in ("name",):
                        redacted[orig_k] = mask_name(val)
                    elif b in ("address",):
                        redacted[orig_k] = mask_address(val)
                    else:
                        redacted[orig_k] = "[REDACTED_PII]"
    return redacted, bool(is_pii)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)
    input_csv = Path(sys.argv[1])
    if not input_csv.exists():
        print("Input file not found:", input_csv)
        sys.exit(2)
    output_path = Path.cwd() / "redacted_output_candidate_full_name.csv"
    rows_out = []
    with input_csv.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if "record_id" not in reader.fieldnames or "Data_json" not in reader.fieldnames:
            print("Input CSV must contain 'record_id' and 'Data_json' columns.")
            sys.exit(3)
        for r in reader:
            rec_id = r.get("record_id")
            raw_json = r.get("Data_json", "{}")
            try:
                obj = json.loads(raw_json)
            except Exception:
                obj = {}
            redacted_obj, is_pii = detect_and_redact_record(obj)
            rows_out.append({
                "record_id": rec_id,
                "redacted_data_json": json.dumps(redacted_obj, ensure_ascii=False),
                "is_pii": str(bool(is_pii))
            })
    with output_path.open("w", encoding="utf-8", newline="") as outfh:
        writer = csv.DictWriter(outfh, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()
        for ro in rows_out:
            writer.writerow(ro)
    print("Redacted output saved to:", output_path)

if __name__ == "__main__":
    main()
