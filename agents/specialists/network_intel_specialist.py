"""
NetworkIntelSpecialist — enrich extracted IOCs with network intelligence.

Enriches IPs, domains, and URLs from IOC extraction with:
  - DNS resolution (domain -> IP mapping)
  - WHOIS age estimation (newly registered domains flagged)
  - Blocklist/reputation checks (mock + extensible)

Pure Python (stdlib: socket, asyncio). Optional: `whois` library.
"""

import asyncio
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sift_aid.specialists.network_intel")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "30"))

_MOCK_BLOCKLIST = {
    "185.130.5.0", "185.130.5.1", "185.130.5.2",
    "198.51.100.0", "198.51.100.1", "198.51.100.2",
    "203.0.113.0", "203.0.113.1",
    "malware-test.example.com", "evil.example.org",
    "c2.payment.xyz", "botnet.cc",
}

_MOCK_WHOIS_DB: dict[str, dict] = {
    "evil.example.org": {"created": "2026-03-15", "registrar": "Unknown"},
    "c2.payment.xyz": {"created": "2026-04-01", "registrar": "FastRegister"},
    "malware-test.example.com": {"created": "2026-05-20", "registrar": "QuickDomains"},
}


class NetworkIntelSpecialist:
    """Enrich extracted IOCs with network intelligence. Read-only network lookups."""

    @staticmethod
    async def run(ioc_results: dict) -> dict:
        t0 = time.monotonic()
        iocs = ioc_results.get("iocs", {}) if ioc_results else {}

        domains = iocs.get("domain", [])
        ips = iocs.get("ipv4", [])
        urls = iocs.get("url", [])

        if not domains and not ips and not urls:
            return {
                "note": "No network IOCs to enrich",
                "domain_analysis": [],
                "ip_analysis": [],
                "url_analysis": [],
                "warnings": [],
                "elapsed_seconds": round(time.monotonic() - t0, 3),
            }

        domain_tasks = [NetworkIntelSpecialist._analyze_domain(d) for d in domains[:30]]
        ip_tasks = [NetworkIntelSpecialist._analyze_ip(ip) for ip in ips[:30]]
        url_tasks = [NetworkIntelSpecialist._analyze_url(u) for u in urls[:30]]

        domain_results = await asyncio.gather(*domain_tasks, return_exceptions=True) if domain_tasks else []
        ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True) if ip_tasks else []
        url_results = await asyncio.gather(*url_tasks, return_exceptions=True) if url_tasks else []

        def _safe(d, default=None):
            return d if not isinstance(d, Exception) else default

        domain_analysis = [_safe(r) for r in domain_results if _safe(r) is not None]
        ip_analysis = [_safe(r) for r in ip_results if _safe(r) is not None]
        url_analysis = [_safe(r) for r in url_results if _safe(r) is not None]

        warnings: list[dict] = []

        for da in domain_analysis:
            if da.get("in_blocklist"):
                warnings.append({
                    "type": "domain_in_blocklist",
                    "value": da["domain"],
                    "detail": "Domain found in known malicious blocklist",
                    "confidence": 0.5,
                })
            if da.get("newly_registered"):
                warnings.append({
                    "type": "newly_registered_domain",
                    "value": da["domain"],
                    "detail": f"Domain registered recently ({da.get('whois_created', 'unknown')})",
                    "confidence": 0.3,
                })

        for ia in ip_analysis:
            if ia.get("in_blocklist"):
                warnings.append({
                    "type": "ip_in_blocklist",
                    "value": ia["ip"],
                    "detail": "IP found in known malicious blocklist",
                    "confidence": 0.5,
                })

        result = {
            "domain_count": len(domain_analysis),
            "ip_count": len(ip_analysis),
            "url_count": len(url_analysis),
            "domain_analysis": domain_analysis,
            "ip_analysis": ip_analysis,
            "url_analysis": url_analysis,
            "warnings": warnings,
            "warning_count": len(warnings),
            "elapsed_seconds": round(time.monotonic() - t0, 3),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        log.info(
            "[NetworkIntelSpecialist] %d domains, %d IPs, %d URLs — %d warnings",
            len(domain_analysis), len(ip_analysis), len(url_analysis), len(warnings),
        )
        return result

    @staticmethod
    async def _analyze_domain(domain: str) -> dict:
        result: dict[str, Any] = {
            "domain": domain,
            "resolved_ips": [],
            "has_dns_record": False,
            "in_blocklist": False,
            "newly_registered": False,
            "whois_created": None,
        }

        try:
            addrinfo = await asyncio.wait_for(
                asyncio.get_event_loop().getaddrinfo(domain, None),
                timeout=5.0,
            )
            resolved = list(set(
                addr[4][0] for addr in addrinfo
            ))
            result["resolved_ips"] = resolved[:5]
            result["has_dns_record"] = bool(resolved)
        except (socket.gaierror, asyncio.TimeoutError, Exception):
            result["has_dns_record"] = False

        if domain.lower() in _MOCK_BLOCKLIST:
            result["in_blocklist"] = True

        whois_data = _MOCK_WHOIS_DB.get(domain.lower())
        if whois_data:
            result["whois_created"] = whois_data["created"]
            try:
                created = datetime.fromisoformat(whois_data["created"])
                age_days = (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)).days
                result["age_days"] = age_days
                if age_days < 90:
                    result["newly_registered"] = True
            except (ValueError, TypeError):
                pass

        return result

    @staticmethod
    async def _analyze_ip(ip: str) -> dict:
        result: dict[str, Any] = {
            "ip": ip,
            "in_blocklist": False,
        }
        if ip in _MOCK_BLOCKLIST:
            result["in_blocklist"] = True
        return result

    @staticmethod
    async def _analyze_url(url: str) -> dict:
        parsed = NetworkIntelSpecialist._extract_domain_from_url(url)
        if parsed:
            domain_result = await NetworkIntelSpecialist._analyze_domain(parsed)
            return {
                "url": url,
                "domain": parsed,
                "domain_resolved_ips": domain_result.get("resolved_ips", []),
                "domain_in_blocklist": domain_result.get("in_blocklist", False),
                "domain_newly_registered": domain_result.get("newly_registered", False),
            }
        return {"url": url, "note": "Could not parse domain from URL"}

    @staticmethod
    def _extract_domain_from_url(url: str) -> Optional[str]:
        m = re.match(r"https?://([^/:]+)", url)
        if m:
            return m.group(1)
        return None
