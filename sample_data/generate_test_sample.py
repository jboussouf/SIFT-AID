#!/usr/bin/env python3
"""
Sample evidence generator for testing SIFT-AID without real malware.
Creates a synthetic PE-like binary with embedded IOCs.
"""

import hashlib
import os
import struct
from pathlib import Path

SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"
SAMPLE_DIR.mkdir(parents=True, exist_ok=True)


def create_fake_pe():
    """Create a synthetic PE-like binary with detectable IOC patterns."""
    # MZ header
    mz_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

    # PE signature at offset 0x80
    pe_sig = b"PE\x00\x00"

    # Machine: x64 (0x8664), sections: 3
    coff = struct.pack("<HHIIIHH",
        0x8664,   # Machine: AMD64
        3,        # NumberOfSections
        0,        # TimeDateStamp
        0,        # PointerToSymbolTable
        0,        # NumberOfSymbols
        0xF0,     # SizeOfOptionalHeader
        0x022F,   # Characteristics
    )

    # Embedded IOCs that specialists should detect
    ioc_payload = b"\x00" * 256
    ioc_payload += b"http://c2.example-malware.ru/drop/payload.exe\x00"
    ioc_payload += b"http://185.220.101.1:4444/beacon\x00"
    ioc_payload += b"YOUR FILES HAVE BEEN ENCRYPTED\x00"
    ioc_payload += b"IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00"
    ioc_payload += b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    ioc_payload += b"Global\\MutexMalware2024\x00"
    ioc_payload += b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    ioc_payload += b"192.168.1.1\x00"    # private — should be filtered
    ioc_payload += b"185.220.101.1\x00"  # public IOC
    ioc_payload += b"evil-domain.top\x00"
    ioc_payload += b"malware-c2.xyz\x00"
    ioc_payload += b"attacker@protonmail.com\x00"
    ioc_payload += b"C:\\Windows\\Temp\\payload.exe\x00"
    ioc_payload += b".docx\x00.xlsx\x00.pdf\x00.sql\x00.pst\x00"  # ransomware targeting
    ioc_payload += b"CryptEncrypt\x00FindFirstFileW\x00"
    ioc_payload += b"UPX!" * 4

    sample = mz_header + b"\x00" * (0x80 - len(mz_header)) + pe_sig + coff + ioc_payload

    output_path = SAMPLE_DIR / "synthetic_malware.bin"
    output_path.write_bytes(sample)

    sha256 = hashlib.sha256(sample).hexdigest()
    print(f"[+] Created: {output_path}")
    print(f"   Size:    {len(sample):,} bytes")
    print(f"   SHA-256: {sha256}")
    print(f"   Embedded IOCs: URLs, IPs, domains, registry keys, mutex, ransomnote strings")
    return output_path


if __name__ == "__main__":
    print("SIFT-AID — Generating synthetic test evidence...")
    path = create_fake_pe()
    print(f"\nRun triage: python main.py --sample {path} --log-level DEBUG")
