"""
IOCSpecialist — wraps the extract_iocs MCP tool.
Single responsibility: extract structured IOCs from a file via strings + regex.
Filters known benign patterns to reduce false positives on clean binaries.
"""

import asyncio
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sift_aid.specialists.ioc")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "60"))

# IOC extraction patterns
_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9\-]{1,63}\.)+(?:com|net|org|io|ru|cn|biz|info|top|xyz|pw|cc|in|co|gov|edu)\b"
    ),
    "url": re.compile(r"https?://[^\s\"'<>]{4,256}"),
    "email": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "registry_key": re.compile(
        r"(?:HKEY_LOCAL_MACHINE|HKLM|HKCU|HKEY_CURRENT_USER|HKEY_USERS|HKU)[\\][^\s\"]{4,256}"
    ),
    "file_path_win": re.compile(
        r"[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)*[^\\\/:*?\"<>|\r\n]{3,}"
    ),
    "mutex": re.compile(r"(?:Global\\|Local\\)[A-Za-z0-9_\-\.]{4,64}"),
    "base64_blob": re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})"),
}

_PRIVATE_IP_PATTERNS = re.compile(
    r"^(127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|0\.)"
)

# Benign domains commonly found embedded in clean ELF binaries (metadata, docs, etc.)
_BENIGN_DOMAINS = {
    "w3.org", "iana.org", "gnu.org", "ubuntu.com", "debian.org",
    "kernel.org", "sourceware.org", "pypi.org", "python.org",
    "microsoft.com", "github.com", "gitlab.com", "google.com",
    "googleapis.com", "gstatic.com", "nist.gov", "ietf.org",
    "rfc-editor.org", "apache.org", "openssl.org", "sqlite.org",
    "oracle.com", "ibm.com", "redhat.com", "archlinux.org",
    "freebsd.org", "openbsd.org", "docker.com", "npmjs.com",
    "npmjs.org", "nodejs.org", "cpan.org", "rubygems.org",
    "crates.io", "mozilla.org", "mozilla.com", "eclipse.org",
    "spring.io", "nginx.org", "mysql.com", "postgresql.org",
    "gnome.org", "kde.org", "x.org", "freedesktop.org",
    "githubusercontent.com", "localhost",
    "savannah.gnu.org", "sourceforge.net",
    "savannah.nongnu.org", "alioth.debian.org", "launchpad.net",
    "cpan.org", "metacpan.org", "rt.cpan.org",
}

_BENIGN_URL_PREFIXES = (
    "http://www.w3.org/", "https://www.w3.org/",
    "http://iana.org/", "https://iana.org/",
    "http://gnu.org/", "https://gnu.org/",
    "http://ubuntu.com/", "https://ubuntu.com/",
    "http://savannah.gnu.org/", "https://savannah.gnu.org/",
    "http://sourceforge.net/", "https://sourceforge.net/",
)

# ELF/library strings that are never malicious indicators
_ELF_NOISE_PREFIXES = (
    "GLIBC_", "__libc_start_main", "__gmon_start__", "__cxa_",
    "_ZTV", "_ZTI", "_ZTS",
    "/lib/", "/usr/lib/", "/usr/local/lib/",
    "/usr/share/", "/etc/",
)

_BENIGN_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "domain.com",
}


def is_benign_ioc(ioc: str, ioc_type: str) -> bool:
    """Return True if the IOC matches known benign/noise patterns."""
    ioc_lower = ioc.lower()

    if ioc_type == "domain":
        if ioc_lower in _BENIGN_DOMAINS:
            return True
        if ioc_lower.startswith("localhost"):
            return True
        # Check subdomains of benign domains (e.g. www.w3.org)
        parts = ioc_lower.split(".")
        if len(parts) >= 2:
            parent = ".".join(parts[-2:])
            if parent in _BENIGN_DOMAINS:
                return True
            if len(parts) >= 3:
                grandparent = ".".join(parts[-3:])
                if grandparent in _BENIGN_DOMAINS:
                    return True

    if ioc_type == "url":
        for prefix in _BENIGN_URL_PREFIXES:
            if ioc_lower.startswith(prefix):
                return True
        domain_part = ioc_lower.split("://", 1)[-1].split("/")[0]
        if domain_part in _BENIGN_DOMAINS:
            return True
        # Check subdomains in URLs too
        parts = domain_part.split(".")
        if len(parts) >= 2:
            parent = ".".join(parts[-2:])
            if parent in _BENIGN_DOMAINS:
                return True

    if ioc_type == "email":
        domain = ioc_lower.split("@", 1)[-1] if "@" in ioc_lower else ""
        if domain in _BENIGN_EMAIL_DOMAINS:
            return True

    if ioc_type == "file_path_win":
        for prefix in _ELF_NOISE_PREFIXES:
            if ioc.startswith(prefix):
                return True

    if ioc_type == "ipv4":
        if _PRIVATE_IP_PATTERNS.match(ioc_lower):
            return True

    # General noise: GLIBC version strings, ELF symbols
    if _ELF_NOISE_PREFIXES:
        for prefix in _ELF_NOISE_PREFIXES:
            if ioc_lower.startswith(prefix.lower()):
                return True

    # Empty / whitespace-only / very short strings
    if len(ioc.strip()) < 3:
        return True

    return False


class IOCSpecialist:
    """Extract IOCs from binary/text evidence files. Fully read-only."""

    @staticmethod
    async def run(path: str, min_length: int = 6) -> dict:
        """
        Extract IOCs using the 'strings' utility + regex patterns.
        Returns structured dict. Never modifies the input file.
        """
        t0 = time.monotonic()
        p = Path(path)

        if not p.exists():
            return {"error": f"File not found: {path}", "total_iocs": 0}

        # Try strings binary first, fall back to Python implementation
        text = await IOCSpecialist._extract_strings(str(p), min_length)
        if text is None:
            text = IOCSpecialist._py_strings(p.read_bytes(), min_length)

        iocs: dict[str, list[str]] = {}
        for ioc_type, pattern in _PATTERNS.items():
            found = list(set(pattern.findall(text)))

            # Apply benign filter to all IOC types
            found = [i for i in found if not is_benign_ioc(i, ioc_type)]

            # Cap per type to avoid context explosion
            if found:
                iocs[ioc_type] = sorted(found)[:50]

        result = {
            "file": str(p),
            "min_string_length": min_length,
            "ioc_types_found": list(iocs.keys()),
            "total_iocs": sum(len(v) for v in iocs.values()),
            "iocs": iocs,
            "elapsed_seconds": round(time.monotonic() - t0, 3),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log.info(
            "[IOCSpecialist] %d total IOCs from %s in %.2fs",
            result["total_iocs"],
            p.name,
            time.monotonic() - t0,
        )
        return result

    @staticmethod
    async def _extract_strings(path: str, min_length: int) -> str | None:
        """Run the 'strings' binary for efficient wide+narrow string extraction."""
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "strings", f"-n{min_length}", "-a", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                ),
                timeout=TOOL_TIMEOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
            text = stdout.decode("utf-8", errors="replace")

            # Also run for wide (UTF-16LE) strings
            proc2 = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "strings", f"-n{min_length}", "-el", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                ),
                timeout=TOOL_TIMEOUT,
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=TOOL_TIMEOUT)
            text += "\n" + stdout2.decode("utf-8", errors="replace")

            return text
        except (FileNotFoundError, asyncio.TimeoutError):
            return None

    @staticmethod
    def _py_strings(data: bytes, min_length: int) -> str:
        """Pure-Python fallback: extract printable ASCII and UTF-16LE strings."""
        result = []
        current = []

        # ASCII pass
        for byte in data:
            ch = chr(byte)
            if ch.isprintable() and byte < 0x80:
                current.append(ch)
            else:
                if len(current) >= min_length:
                    result.append("".join(current))
                current = []
        if len(current) >= min_length:
            result.append("".join(current))

        return "\n".join(result)
