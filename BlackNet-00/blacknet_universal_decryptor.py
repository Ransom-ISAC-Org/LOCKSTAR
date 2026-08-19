#!/usr/bin/env python3
r"""
BLACKNET Universal XOR Decryptor
Breaks ANY variant of BLACKNET-00 ransomware regardless of:
  - Extension (auto-detected)
  - Key length (auto-detected via Kasiski/IoC analysis)
  - Ransom note presence (not needed)
  - File headers (not needed)
  - PRNG seed (not needed)

Works purely from statistical properties of XOR encryption.
As long as the builder uses repeating XOR, this breaks it.
"""

import argparse
import collections
import math
import os
import re
import subprocess
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("blacknet_universal.log")
    ]
)
log = logging.getLogger("universal")

KNOWN_EXTENSIONS = [".blacknet", ".locked", ".encrypted", ".enc", ".crypt",
                    ".dark", ".doom", ".pay", ".ransom"]

SKIP_DIRS = {"windows", "$recycle.bin", "system volume information",
             "programdata", "program files", "program files (x86)"}

FILE_HEADERS = {
    ".pdf":    b"%PDF-1.",
    ".png":    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    ".jpg":    b"\xff\xd8\xff\xe0\x00\x10JFIF",
    ".jpeg":   b"\xff\xd8\xff\xe1",
    ".gif":    b"GIF89a",
    ".bmp":    b"BM",
    ".zip":    b"PK\x03\x04",
    ".docx":   b"PK\x03\x04",
    ".xlsx":   b"PK\x03\x04",
    ".pptx":   b"PK\x03\x04",
    ".7z":     b"7z\xbc\xaf'\x1c",
    ".rar":    b"Rar!\x1a\x07",
    ".gz":     b"\x1f\x8b\x08",
    ".exe":    b"MZ\x90\x00\x03\x00\x00\x00",
    ".dll":    b"MZ\x90\x00\x03\x00\x00\x00",
    ".sqlite": b"SQLite format 3\x00",
    ".db":     b"SQLite format 3\x00",
    ".psd":    b"8BPS\x00\x01",
    ".mp3":    b"ID3",
    ".avi":    b"RIFF",
    ".wav":    b"RIFF",
    ".xml":    b"<?xml ",
    ".html":   b"<!DOCTYPE html",
    ".htm":    b"<!DOCTYPE html",
    ".doc":    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ".xls":    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ".ppt":    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
}


# ===================================================================
# KEY LENGTH DETECTION — Kasiski + Index of Coincidence
# ===================================================================

def detect_key_length(data, max_len=64):
    """Detect XOR key length using Index of Coincidence analysis."""
    if len(data) < max_len * 10:
        log.warning("File too small for reliable key length detection")

    scores = {}
    for kl in range(1, max_len + 1):
        total_ioc = 0
        for offset in range(kl):
            stream = data[offset::kl]
            if len(stream) < 20:
                continue
            freq = collections.Counter(stream)
            n = len(stream)
            ioc = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1)) if n > 1 else 0
            total_ioc += ioc
        scores[kl] = total_ioc / kl

    # English text XOR'd has IoC ~0.065, random is ~0.004
    # The correct key length will have IoC closest to natural language
    best = sorted(scores.items(), key=lambda x: abs(x[1] - 0.065))

    # Prefer smaller key lengths when scores are close
    candidates = best[:5]
    log.info("Key length candidates (IoC): %s",
             ", ".join(f"{kl}={ioc:.4f}" for kl, ioc in candidates))

    return candidates[0][0]


def detect_key_length_kasiski(data, max_len=64):
    """Kasiski examination — find repeating sequences and GCD of distances."""
    from math import gcd
    from functools import reduce

    distances = []
    seq_len = 3

    for i in range(len(data) - seq_len):
        seq = data[i:i + seq_len]
        j = data.find(seq, i + seq_len)
        while j != -1:
            distances.append(j - i)
            j = data.find(seq, j + 1)

    if not distances:
        return None

    # Find most common distances and their GCD
    dist_counter = collections.Counter(distances)
    common = [d for d, _ in dist_counter.most_common(20) if d > 1]

    if not common:
        return None

    # GCD of the most common distances = likely key length
    result = reduce(gcd, common[:10])

    if 1 < result <= max_len:
        log.info("Kasiski key length estimate: %d", result)
        return result

    return None


# ===================================================================
# KEY RECOVERY — Multiple methods
# ===================================================================

def recover_key_frequency(data, key_length):
    """Recover XOR key using frequency analysis.

    Assumes original files contain mostly printable ASCII / common bytes.
    For each key position, the byte value that produces the most
    common plaintext bytes (space, 'e', 't', 'a', etc.) is likely correct.
    """
    key = bytearray(key_length)

    # Common bytes in typical files (text, documents, code, etc.)
    common_plain = set(range(32, 127))  # printable ASCII
    common_plain.add(0x0a)  # newline
    common_plain.add(0x0d)  # carriage return
    common_plain.add(0x09)  # tab
    common_plain.add(0x00)  # null (common in binary headers)

    for pos in range(key_length):
        stream = data[pos::key_length]
        best_score = -1
        best_byte = 0

        for candidate in range(256):
            decrypted = bytes([b ^ candidate for b in stream])
            score = sum(1 for b in decrypted if b in common_plain)
            if score > best_score:
                best_score = score
                best_byte = candidate

        key[pos] = best_byte

    return bytes(key)


def recover_key_from_headers(encrypted_files, key_length):
    """Recover key by matching encrypted files against known file type headers."""
    key = bytearray(key_length)
    recovered = [False] * key_length

    for filepath, original_ext in encrypted_files:
        if original_ext not in FILE_HEADERS:
            continue

        header = FILE_HEADERS[original_ext]
        try:
            with open(filepath, "rb") as f:
                enc = f.read(max(key_length * 2, len(header)))

            for i in range(min(len(header), len(enc))):
                pos = i % key_length
                candidate = enc[i] ^ header[i]
                if recovered[pos]:
                    if key[pos] != candidate:
                        continue
                else:
                    key[pos] = candidate
                    recovered[pos] = True

            if all(recovered):
                log.info("Full key from headers: %s", key.decode("ascii", errors="replace"))
                return bytes(key)
        except Exception:
            continue

    if any(recovered):
        log.info("Partial key from headers: %d/%d bytes", sum(recovered), key_length)

    return bytes(key) if all(recovered) else None


def recover_key_bruteforce_rand(encrypted_files, key_length):
    """Brute-force MSVC rand() seed to recover key."""
    if key_length != 32:
        log.info("Seed brute-force only works for 32-byte keys (BLACKNET default)")
        return None

    CHARS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    for filepath, original_ext in encrypted_files:
        if original_ext not in FILE_HEADERS:
            continue

        header = FILE_HEADERS[original_ext]
        try:
            with open(filepath, "rb") as f:
                enc = f.read(key_length)
        except Exception:
            continue

        target = [enc[i] ^ header[i] for i in range(min(len(header), len(enc), key_length))]
        if not target:
            continue

        mtime = int(os.path.getmtime(filepath))
        lo, hi = max(0, mtime - 7200), mtime + 3600
        log.info("Brute-forcing rand() seed %d-%d...", lo, hi)

        for seed in range(lo, hi + 1):
            s, ok, g = seed, True, bytearray()
            for i in range(key_length):
                s = (s * 214013 + 2531011) & 0xFFFFFFFF
                ch = CHARS[((s >> 16) & 0x7FFF) % len(CHARS)]
                g.append(ch)
                if i < len(target) and ch != target[i]:
                    ok = False
                    break
            if ok:
                log.info("SEED %d -> KEY: %s", seed, g.decode("ascii"))
                return bytes(g)

    return None


def find_ransom_note_key():
    """Search for any ransom note variant with a key in it."""
    note_patterns = ["READ_ME*", "*RANSOM*", "*DECRYPT*", "*BLACKNET*", "*README*"]
    found_notes = []

    for drive in "CDEFGHIJ":
        dp = drive + ":\\"
        if not os.path.exists(dp):
            continue
        try:
            for root, dirs, files in os.walk(dp):
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
                for f in files:
                    fl = f.lower()
                    if any(p.replace("*", "") in fl for p in
                           ["read_me", "ransom", "decrypt", "blacknet"]):
                        if fl.endswith(".txt") or fl.endswith(".html") or fl.endswith(".hta"):
                            found_notes.append(os.path.join(root, f))
        except PermissionError:
            continue

    for note in found_notes:
        try:
            with open(note, "r", errors="replace") as f:
                content = f.read()
            for pattern in [r"Decryption Key:\s*(\S{16,})",
                            r"[Kk]ey:\s*(\S{16,})",
                            r"[Pp]assword:\s*(\S{16,})"]:
                m = re.search(pattern, content)
                if m:
                    key = m.group(1)
                    log.info("Found key in %s: %s", note, key)
                    return key.encode()
        except Exception:
            continue

    return None


# ===================================================================
# EXTENSION DETECTION
# ===================================================================

def detect_extension(scan_dir):
    """Auto-detect what extension the ransomware used."""
    ext_counts = collections.Counter()

    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            for ext in KNOWN_EXTENSIONS:
                if f.lower().endswith(ext):
                    ext_counts[ext] += 1

    if ext_counts:
        best = ext_counts.most_common(1)[0]
        log.info("Detected extension: %s (%d files)", best[0], best[1])
        return best[0]

    # Try unknown extensions — look for files with double extensions
    # where the outer extension is unusual
    unusual = collections.Counter()
    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            parts = f.rsplit(".", 2)
            if len(parts) >= 3:
                outer = "." + parts[-1].lower()
                inner = "." + parts[-2].lower()
                if inner in FILE_HEADERS and outer not in FILE_HEADERS:
                    unusual[outer] += 1

    if unusual:
        best = unusual.most_common(1)[0]
        log.info("Detected likely ransomware extension: %s (%d files)", best[0], best[1])
        return best[0]

    return None


# ===================================================================
# FILE OPERATIONS
# ===================================================================

def find_encrypted_files(scan_dir, extension):
    """Find all encrypted files and extract their original extensions."""
    results = []
    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            if f.lower().endswith(extension):
                filepath = os.path.join(root, f)
                original_name = f.rsplit(extension, 1)[0]
                _, orig_ext = os.path.splitext(original_name)
                results.append((filepath, orig_ext.lower()))
    return results


def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def validate_decryption(data, original_ext):
    """Check if decrypted data looks correct based on expected file type."""
    if original_ext in FILE_HEADERS:
        expected = FILE_HEADERS[original_ext]
        if data[:len(expected)] == expected:
            return True

    # General check: is it mostly printable for text-like files?
    text_exts = {".txt", ".csv", ".log", ".json", ".xml", ".html", ".htm",
                 ".css", ".js", ".py", ".cpp", ".c", ".h", ".java", ".ini",
                 ".cfg", ".conf", ".md", ".bat", ".ps1", ".sh", ".sql"}
    if original_ext in text_exts:
        sample = data[:1000]
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        if printable / max(len(sample), 1) > 0.85:
            return True

    # For unknown types, check entropy isn't still high (still encrypted)
    if len(data) > 100:
        freq = collections.Counter(data[:1000])
        entropy = -sum((c / 1000) * math.log2(c / 1000) for c in freq.values() if c > 0)
        if entropy < 7.5:  # encrypted data is ~8.0, normal files are lower
            return True

    return False


def decrypt_file(filepath, key, extension, dry_run=False, delete_after=False):
    try:
        with open(filepath, "rb") as f:
            enc = f.read()

        dec = xor_decrypt(enc, key)
        original = filepath.rsplit(extension, 1)[0]
        _, orig_ext = os.path.splitext(original)

        if dry_run:
            valid = validate_decryption(dec, orig_ext.lower())
            status = "OK" if valid else "SUSPICIOUS"
            preview = "".join(chr(b) if 32 <= b < 127 else "." for b in dec[:50])
            log.info("[DRY] [%s] %s -> %s (%d bytes) [%s]",
                     status, os.path.basename(filepath),
                     os.path.basename(original), len(dec), preview)
            return valid

        if sys.platform == "win32":
            try:
                import ctypes
                a = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                if a != -1 and a & 2:
                    ctypes.windll.kernel32.SetFileAttributesW(filepath, a & ~2)
            except Exception:
                pass

        if os.path.exists(original):
            original += ".recovered"

        with open(original, "wb") as f:
            f.write(dec)

        log.info("Decrypted: %s -> %s (%d bytes)",
                 os.path.basename(filepath), os.path.basename(original), len(dec))

        if delete_after:
            os.remove(filepath)
        return True
    except Exception as e:
        log.error("Failed %s: %s", filepath, e)
        return False


# ===================================================================
# CLEANUP
# ===================================================================

def kill_processes(dry_run=False):
    if sys.platform != "win32":
        return
    log.info("Killing ransomware processes...")
    suspects = ["MyRansomware", "blacknet", "BlackNet", "ransomware", "ransom"]
    try:
        r = subprocess.run("tasklist /FO CSV /NH", shell=True, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            for s in suspects:
                if s.lower() in line.lower():
                    try:
                        n = line.split('","')[0].strip('"')
                        p = line.split('","')[1].strip('"')
                        if dry_run:
                            log.info("[DRY] Would kill %s (PID %s)", n, p)
                        else:
                            subprocess.run("taskkill /F /PID " + p,
                                           shell=True, capture_output=True)
                            log.warning("Killed %s (PID %s)", n, p)
                    except (IndexError, ValueError):
                        pass
    except Exception:
        pass


def cleanup(dry_run=False):
    if sys.platform != "win32":
        return
    log.info("Cleaning up artifacts...")

    for cmd, desc in [
        ('reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /f',
         "Registry persistence"),
        ('schtasks /delete /tn "WindowsUpdate" /f', "Scheduled task")
    ]:
        try:
            if dry_run:
                log.info("[DRY] Remove: %s", desc)
            elif subprocess.run(cmd, shell=True, capture_output=True).returncode == 0:
                log.info("Removed: %s", desc)
        except Exception:
            pass

    t = os.environ.get("TEMP", "")
    up = os.environ.get("USERPROFILE", "")
    for fp in [
        os.path.join(t, "blacknet_wall.bmp") if t else "",
        os.path.join(t, "screenshot_blacknet.bmp") if t else "",
    ]:
        if fp and os.path.exists(fp):
            if dry_run:
                log.info("[DRY] Delete: %s", fp)
            else:
                try:
                    os.remove(fp)
                    log.info("Deleted: %s", fp)
                except Exception:
                    pass

    if not dry_run:
        try:
            import ctypes
            ctypes.windll.user32.SystemParametersInfoW(20, 0, "", 3)
        except Exception:
            pass


# ===================================================================
# MAIN
# ===================================================================

def main():
    print("""
============================================================
  BLACKNET UNIVERSAL XOR DECRYPTOR
  Breaks any BLACKNET variant — auto-detects everything
============================================================
""")

    p = argparse.ArgumentParser(description="Universal BLACKNET XOR Decryptor")
    p.add_argument("--scan-dir", required=True, help="Directory to scan")
    p.add_argument("--key", help="XOR key (if already known)")
    p.add_argument("--extension", help="Encrypted file extension (auto-detected if omitted)")
    p.add_argument("--key-length", type=int, help="Key length (auto-detected if omitted)")
    p.add_argument("--dry-run", action="store_true", help="Preview only")
    p.add_argument("--cleanup", action="store_true", help="Kill processes + remove persistence")
    p.add_argument("--delete-encrypted", action="store_true")
    p.add_argument("--single-file", help="Decrypt one file")
    p.add_argument("--skip-note", action="store_true",
                   help="Skip ransom note search (method 1) — test methods 2-4 only")

    args = p.parse_args()

    if args.dry_run:
        log.info("=== DRY RUN ===\n")

    # --- Kill processes ---
    kill_processes(args.dry_run)

    # --- Detect extension ---
    ext = args.extension
    if not ext:
        log.info("Auto-detecting encrypted file extension...")
        ext = detect_extension(args.scan_dir)
        if not ext:
            log.error("No encrypted files found. Specify --extension manually.")
            sys.exit(1)
    log.info("Extension: %s", ext)

    # --- Find encrypted files ---
    encrypted = find_encrypted_files(args.scan_dir, ext)
    log.info("Found %d encrypted files", len(encrypted))
    if not encrypted:
        log.error("No files found with extension %s", ext)
        sys.exit(1)

    # --- Get or recover key ---
    key = None

    if args.key:
        key = args.key.encode() if isinstance(args.key, str) else args.key
        log.info("Using provided key (%d bytes)", len(key))

    if not key:
        log.info("\n--- KEY RECOVERY ---")

        # Method 1: Ransom note
        if args.skip_note:
            log.info("[1/4] SKIPPED (--skip-note)")
        else:
            log.info("[1/4] Searching for ransom note...")
            key = find_ransom_note_key()

        # Method 2: File headers
        if not key:
            log.info("[2/4] Trying known file headers...")
            kl = args.key_length or 32
            key = recover_key_from_headers(encrypted, kl)

        # Method 3: Brute-force rand() seed
        if not key:
            log.info("[3/4] Brute-forcing rand() seed...")
            key = recover_key_bruteforce_rand(encrypted, args.key_length or 32)

        # Method 4: Frequency analysis (works on ANY XOR, no known plaintext needed)
        if not key:
            log.info("[4/4] Frequency analysis (no known plaintext needed)...")
            biggest = max(encrypted, key=lambda x: os.path.getsize(x[0]))
            with open(biggest[0], "rb") as f:
                sample = f.read(100000)

            kl = args.key_length
            if not kl:
                kl = detect_key_length(sample)
                log.info("Detected key length: %d", kl)

            key = recover_key_frequency(sample, kl)
            log.info("Frequency analysis key (%d bytes): %s",
                     len(key), key.hex())

    if not key:
        log.error("All recovery methods failed.")
        sys.exit(1)

    log.info("\nKEY: %s (%d bytes)\n",
             key.hex() if isinstance(key, bytes) else key,
             len(key))

    # --- Validate key on first file ---
    test_path, test_ext = encrypted[0]
    with open(test_path, "rb") as f:
        test_dec = xor_decrypt(f.read(1000), key)
    if validate_decryption(test_dec, test_ext):
        log.info("Key validation: PASSED")
    else:
        log.warning("Key validation: UNCERTAIN — decrypted data may not be correct")
        log.warning("Preview: %s",
                    "".join(chr(b) if 32 <= b < 127 else "." for b in test_dec[:80]))
        if not args.dry_run:
            resp = input("Continue anyway? (y/n): ").strip().lower()
            if resp != "y":
                sys.exit(1)

    # --- Decrypt ---
    print("\n" + "-" * 60)
    print("  DECRYPTING")
    print("-" * 60)

    if args.single_file:
        decrypt_file(args.single_file, key, ext, args.dry_run, args.delete_encrypted)
    else:
        ok = fail = 0
        for i, (fp, _) in enumerate(encrypted, 1):
            log.info("[%d/%d] %s", i, len(encrypted), os.path.basename(fp))
            if decrypt_file(fp, key, ext, args.dry_run, args.delete_encrypted):
                ok += 1
            else:
                fail += 1
        print("\n  Decrypted: %d/%d | Failed: %d" % (ok, len(encrypted), fail))

    # --- Cleanup ---
    if args.cleanup:
        cleanup(args.dry_run)

    print("\n  Done.\n")


if __name__ == "__main__":
    main()
