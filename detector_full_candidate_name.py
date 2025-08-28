
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PII Detector & Redactor
Usage:
    python3 detector_full_candidate_name.py iscp_pii_dataset.csv
Produces:
    redacted_output_candidate_full_name.csv
"""

import sys, json, re
from pathlib import Path
import pandas as pd

# --------- Regex patterns (India-focused where applicable) ---------
RE_PHONE = re.compile(r'(?<!\d)(?:\+91[-\s]?)?\d{10}(?!\d)')
RE_AADHAR = re.compile(r'(?<!\d)(?:\d{4}[-\s]?\d{4}[-\s]?\d{4})(?!\d)')
# Indian passport: 1 letter (not O/I) + 7 digits
RE_PASSPORT = re.compile(r'(?i)\b([A-PR-WY])[0-9]{7}\b')
RE_UPI = re.compile(r'\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b')
RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b')
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_PINCODE = re.compile(r'(?<!\d)\d{6}(?!\d)')

# Keys that likely contain PII candidates
KEY_PHONE = {'phone', 'contact'}
KEY_AADHAR = {'aadhar', 'aadhaar'}
KEY_PASSPORT = {'passport'}
KEY_UPI = {'upi', 'upi_id'}
KEY_EMAIL = {'email'}
KEY_NAME = {'name'}
KEY_FIRST = {'first_name'}
KEY_LAST = {'last_name'}
KEY_ADDRESS = {'address'}
KEY_IP = {'ip', 'ip_address'}
KEY_DEVICE = {'device', 'device_id'}

# --------------- Masking helpers ------------------
def mask_phone(s: str) -> str:
    digits = re.sub(r'\D', '', s)
    if len(digits) >= 10:
        core = digits[-10:]
        masked = core[:2] + 'X'*6 + core[-2:]
        return masked
    return re.sub(r'\d', 'X', s)

def mask_aadhar(s: str) -> str:
    digits = re.sub(r'\D', '', s)
    if len(digits) >= 12:
        core = digits[-12:]
        masked = 'XXXX XXXX ' + core[-4:]
        return masked
    return re.sub(r'\d', 'X', s)

def mask_passport(s: str) -> str:
    s = s.strip()
    if len(s) >= 3:
        return s[0] + 'XXXXX' + s[-2:]
    return 'XXXXXXX'

def mask_upi(s: str) -> str:
    parts = s.split('@', 1)
    if len(parts) == 2:
        local, dom = parts
        keep = local[:2]
        return keep + 'X'*max(3, len(local)-2) + '@' + dom
    return '[REDACTED_UPI]'

def mask_email(s: str) -> str:
    parts = s.split('@', 1)
    if len(parts) == 2:
        local, dom = parts
        keep = local[:2]
        return keep + 'XXX' + '@' + dom
    return '[REDACTED_EMAIL]'

def mask_name_full(s: str) -> str:
    tokens = [t for t in re.split(r'\s+', s.strip()) if t]
    def m(t):
        if not t: return t
        return t[0] + 'X'*(max(3, len(t)-1))
    return ' '.join(m(t) for t in tokens)

def mask_address(_: str) -> str:
    return '[REDACTED_ADDRESS]'

def mask_ip(s: str) -> str:
    parts = s.split('.')
    if len(parts) == 4:
        parts[-1] = 'xxx'
        return '.'.join(parts)
    return '[REDACTED_IP]'

def mask_device(_: str) -> str:
    return '[REDACTED_DEVICE]'

# --------------- Detection helpers ------------------
def has_full_name(obj) -> bool:
    # name with a space OR presence of both first and last keys
    name = obj.get('name')
    if isinstance(name, str) and re.search(r'\S+\s+\S+', name):
        return True
    if obj.get('first_name') and obj.get('last_name'):
        return True
    return False

def has_email(obj) -> bool:
    val = obj.get('email')
    return isinstance(val, str) and bool(RE_EMAIL.search(val))

def has_physical_address(obj) -> bool:
    # "street + city + pin code" approximation: require address + (city or state/region) + pin_code
    if not isinstance(obj.get('address'), str):
        return False
    has_loc = bool(obj.get('city') or obj.get('state') or obj.get('region'))
    has_pin = bool(RE_PINCODE.search(str(obj.get('pin_code', ''))))
    return has_loc and has_pin

def has_device_or_ip(obj) -> bool:
    dev = obj.get('device_id') or obj.get('device')
    ip = obj.get('ip_address') or obj.get('ip')
    return bool(dev or (isinstance(ip, str) and RE_IPV4.search(ip)))

def detect_standalone(obj) -> bool:
    # check obvious fields first
    for k in obj:
        v = obj[k]
        if v is None: 
            continue
        sv = str(v)
        lk = k.lower()
        if lk in KEY_PHONE and RE_PHONE.search(sv):
            return True
        if lk in KEY_AADHAR and RE_AADHAR.search(sv):
            return True
        if lk in KEY_PASSPORT and RE_PASSPORT.search(sv):
            return True
        if lk in KEY_UPI and RE_UPI.search(sv):
            return True
        # also scan any string field for standalone PII patterns
        if isinstance(v, str):
            if RE_AADHAR.search(v) or RE_UPI.search(v):
                return True
            # Phone as "any 10-digit number" — ensure not misfiring on aadhar (handled above)
            if RE_PHONE.search(v):
                return True
            if RE_PASSPORT.search(v):
                return True
    return False

def detect_combinatorial(obj) -> bool:
    count = 0
    if has_full_name(obj): count += 1
    if has_email(obj): count += 1
    if has_physical_address(obj): count += 1
    if has_device_or_ip(obj): count += 1
    return count >= 2

def redact_obj(obj, is_pii: bool):
    # Copy to avoid mutating original
    red = dict(obj)
    def try_mask_key(keys, masker):
        for k in keys:
            if k in red and isinstance(red[k], str) and red[k].strip():
                red[k] = masker(red[k])

    # Always redact standalone PII fields when present
    try_mask_key(KEY_PHONE, mask_phone)
    try_mask_key(KEY_AADHAR, mask_aadhar)
    try_mask_key(KEY_PASSPORT, mask_passport)
    try_mask_key(KEY_UPI, mask_upi)

    # For combinatorial PII, redact contributing fields
    if is_pii:
        # Names
        if 'name' in red and isinstance(red['name'], str):
            red['name'] = mask_name_full(red['name'])
        if 'first_name' in red and isinstance(red['first_name'], str):
            red['first_name'] = red['first_name'][:1] + 'XXX' if red['first_name'] else red['first_name']
        if 'last_name' in red and isinstance(red['last_name'], str):
            red['last_name'] = red['last_name'][:1] + 'XXX' if red['last_name'] else red['last_name']
        # Email
        if 'email' in red and isinstance(red['email'], str):
            red['email'] = mask_email(red['email'])
        # Address & IP & Device
        if 'address' in red and isinstance(red['address'], str):
            red['address'] = mask_address(red['address'])
        if 'ip_address' in red and isinstance(red['ip_address'], str):
            red['ip_address'] = mask_ip(red['ip_address'])
        if 'device_id' in red and isinstance(red['device_id'], str):
            red['device_id'] = mask_device(red['device_id'])
    return red

def process(input_csv: Path, output_csv: Path):
    df = pd.read_csv(input_csv)
    # Expect columns: record_id, Data_json
    out_rows = []
    for _, row in df.iterrows():
        rid = row.get('record_id', '')
        raw = row.get('Data_json', '{}')
        try:
            obj = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            # Attempt to repair common JSON issues (single quotes)
            try:
                safe = raw.replace("'", '"')
                obj = json.loads(safe)
            except Exception:
                obj = {}
        # Detection
        standalone = detect_standalone(obj)
        combinatorial = detect_combinatorial(obj)
        is_pii = bool(standalone or combinatorial)
        # Redaction
        red = redact_obj(obj, is_pii=is_pii)
        out_rows.append({
            'record_id': rid,
            'redacted_data_json': json.dumps(red, ensure_ascii=False),
            'is_pii': is_pii
        })
    out_df = pd.DataFrame(out_rows, columns=['record_id','redacted_data_json','is_pii'])
    out_df.to_csv(output_csv, index=False)

def main():
    # Allow CLI, default to /mnt/data path if not provided
    in_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/mnt/data/iscp_pii_dataset_-_Sheet1.csv")
    out_path = Path("redacted_output_candidate_full_name.csv") if len(sys.argv) <= 2 else Path(sys.argv[2])
    process(in_path, out_path)

if __name__ == "__main__":
    main()
