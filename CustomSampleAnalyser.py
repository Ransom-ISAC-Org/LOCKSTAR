#!/usr/bin/env python3
"""
Static malware analysis template (defensive example).
- Computes hashes
- Extracts printable strings
- Reads PE metadata using pefile
- Calculates section entropy
- Runs simple YARA rules (example)
- Produces a JSON report with extracted IOCs

Dependencies:
    pip install pefile yara-python python-magic
Optional:
    pip install lief   # for more advanced PE introspection
"""

import sys
import os
import hashlib
import json
import math
import re
import argparse
from collections import Counter
from datetime import datetime

try:
    import pefile
except Exception as e:
    print("Missing dependency: pefile. Install with `pip install pefile`", file=sys.stderr)
    raise

# YARA is optional
try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

# ---------- Utility functions ----------

def compute_hashes(path):
    """Compute md5, sha1, sha256, and file size."""
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            size += len(chunk)
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
        "size": size
    }

# printable strings extraction
PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{4,}")  # minimal length 4

def extract_strings(path, min_len=4):
    strings = []
    with open(path, "rb") as f:
        data = f.read()
    for match in PRINTABLE_RE.finditer(data):
        s = match.group().decode("latin-1", errors="replace")
        if len(s) >= min_len:
            strings.append(s)
    return strings

def shannon_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    counts = Counter(data_bytes)
    length = len(data_bytes)
    entropy = -sum((count/length) * math.log2(count/length) for count in counts.values())
    return entropy

# ---------- PE analysis ----------

def analyze_pe(path):
    """Extract common PE fields, imports, exports, resources, sections, entropies."""
    info = {}
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
    ])
    # Basic header fields
    info['timestamp'] = datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() + "Z" if pe.FILE_HEADER.TimeDateStamp else None
    info['machine'] = hex(pe.FILE_HEADER.Machine)
    info['characteristics'] = pe.FILE_HEADER.Characteristics
    try:
        info['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        info['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
        info['subsystem'] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.Subsystem)
    except Exception:
        pass

    # Sections + entropy
    sections = []
    for s in pe.sections:
        sec_bytes = s.get_data()
        sections.append({
            "name": s.Name.decode(errors="ignore").rstrip("\x00"),
            "virtual_address": hex(s.VirtualAddress),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(shannon_entropy(sec_bytes), 4)
        })
    info['sections'] = sections

    # Imports
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode(errors="ignore"))
                else:
                    funcs.append(f"ord_{imp.ordinal}")
            imports.append({"dll": dll, "functions": funcs})
    info['imports'] = imports

    # Exports
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(exp.name.decode(errors="ignore") if exp.name else f"ord_{exp.ordinal}")
    info['exports'] = exports

    # Resources count (basic)
    res_count = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        def count_resources(dir_entry):
            total = 0
            for entry in dir_entry.entries:
                if hasattr(entry, 'directory'):
                    total += count_resources(entry.directory)
                else:
                    total += 1
            return total
        res_count = count_resources(pe.DIRECTORY_ENTRY_RESOURCE)
    info['resource_count'] = res_count

    # Optional: detect suspicious imports commonly used by ransomware-ish samples
    suspicious_api = set(["CreateRemoteThread", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "OpenProcess", "SetFileTime", "CreateFileA", "CreateFileW", "DeviceIoControl"])
    used_suspicious = []
    for imp in imports:
        for f in imp['functions']:
            if f in suspicious_api:
                used_suspicious.append({"dll": imp['dll'], "function": f})
    info['suspicious_api'] = used_suspicious

    return info

# ---------- YARA scanning (optional) ----------

SAMPLE_YARA_RULE = r'''
rule suspicious_strings_ransomware_example
{
    meta:
        author = "example"
        description = "Example rule that looks for common ransom-related English words (for detection/triage)."
    strings:
        $ransom = /ransom/i
        $decrypt = /decrypt/i
        $payment = /payment/i
        $bitcoin = /bitcoin/i
        $ext = ".encrypted"
    condition:
        (any of ($ransom, $decrypt, $payment, $bitcoin)) or filesize < 10000000
}
'''

def yara_scan(path, rules_text=None):
    if not YARA_AVAILABLE:
        return {"error": "yara-python not available"}
    if rules_text is None:
        rules_text = SAMPLE_YARA_RULE
    rules = yara.compile(source=rules_text)
    matches = rules.match(path)
    # convert to readable
    result = []
    for m in matches:
        result.append({
            "rule": m.rule,
            "tags": m.tags,
            "metas": m.meta
        })
    return {"matches": result}

# ---------- Report generation ----------

def generate_report(path, yara_rules=None):
    report = {}
    report['file_path'] = os.path.abspath(path)
    report['analysis_time'] = datetime.utcnow().isoformat() + "Z"
    report['hashes'] = compute_hashes(path)
    report['strings'] = []  # keep light: top N strings
    all_strings = extract_strings(path, min_len=4)
    # include top 200 unique strings for triage
    report['strings'] = all_strings[:200]
    # Attempt PE analysis if file appears to be PE
    try:
        with open(path, "rb") as f:
            header = f.read(2)
        if header == b"MZ":
            report['pe'] = analyze_pe(path)
        else:
            report['pe'] = {"note": "Not a PE file"}
    except Exception as e:
        report['pe'] = {"error": str(e)}

    # YARA
    if yara_rules is not None and YARA_AVAILABLE:
        report['yara'] = yara_scan(path, rules_text=yara_rules)
    elif yara_rules is not None:
        report['yara'] = {"error": "YARA library not available"}
    else:
        report['yara'] = {"note": "No YARA rules provided"}

    # Derive a few quick IOCs
    report['iocs'] = {
        "hashes": report['hashes'],
        "suspicious_imports": report['pe'].get('suspicious_api') if isinstance(report['pe'], dict) else []
    }
    return report

# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="Static malware analysis template (defensive).")
    parser.add_argument("file", help="Path to sample")
    parser.add_argument("--yara", help="Path to a YARA rules file (optional)", default=None)
    parser.add_argument("--out", help="JSON output path (default: <sample>.analysis.json)", default=None)
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print("File not found:", args.file, file=sys.stderr)
        sys.exit(2)

    yara_rules = None
    if args.yara:
        with open(args.yara, "r", encoding="utf-8") as yf:
            yara_rules = yf.read()

    report = generate_report(args.file, yara_rules=yara_rules if yara_rules else SAMPLE_YARA_RULE)

    out_path = args.out if args.out else args.file + ".analysis.json"
    with open(out_path, "w", encoding="utf-8") as outf:
        json.dump(report, outf, indent=2)

    print("Analysis complete. Report written to:", out_path)

if __name__ == "__main__":
    main()
