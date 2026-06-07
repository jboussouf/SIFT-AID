"""
HashSpecialist — wraps compute_hash and query_virustotal MCP tools.
Single responsibility: hash a file and look it up on VirusTotal.
Fallback: returns partial results if VT is unavailable (offline mode).
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("sift_aid.specialists.hash")

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/cases"))

# Helper to automatically load .env if present
def _load_env():
    # Try finding .env in current working dir or project parent dirs
    search_dirs = [Path.cwd(), Path(__file__).resolve().parents[2]]
    for d in search_dirs:
        env_file = d / ".env"
        if env_file.exists():
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass

_load_env()


class HashSpecialist:
    """Compute file hashes and query VirusTotal. Fully read-only."""

    @staticmethod
    async def run(sample_path: str) -> dict:
        """
        Compute SHA-256, MD5, SHA-1 for the given file.
        Returns structured dict. Never modifies the file.
        """
        t0 = time.monotonic()
        p = Path(sample_path)

        if not p.exists():
            return {
                "error": f"File not found: {sample_path}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        try:
            hash_sha256 = hashlib.sha256()
            hash_md5 = hashlib.md5()
            hash_sha1 = hashlib.sha1()
            size_bytes = 0

            def _hash_file():
                nonlocal size_bytes
                with open(p, "rb") as f:
                    while chunk := f.read(65536):
                        size_bytes += len(chunk)
                        hash_sha256.update(chunk)
                        hash_md5.update(chunk)
                        hash_sha1.update(chunk)

            await asyncio.to_thread(_hash_file)

            result = {
                "file": str(p),
                "size_bytes": size_bytes,
                "hashes": {
                    "sha256": hash_sha256.hexdigest(),
                    "md5":    hash_md5.hexdigest(),
                    "sha1":   hash_sha1.hexdigest(),
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": round(time.monotonic() - t0, 3),
            }
            log.info("[HashSpecialist] SHA-256=%s size=%d", result["hashes"]["sha256"], size_bytes)
            return result

        except PermissionError as exc:
            log.error("[HashSpecialist] Permission denied: %s", exc)
            return {"error": f"Permission denied: {exc}", "file": sample_path}
        except Exception as exc:
            log.error("[HashSpecialist] Unexpected error: %s", exc)
            return {"error": str(exc), "file": sample_path}

    @staticmethod
    async def query_vt(sha256: str) -> dict:
        """
        Query VirusTotal for a SHA-256 hash via VTQueryAgent (vt-py SDK).
        Returns structured dict with detection counts.
        Falls back gracefully to offline_mode if VT_API_KEY is not set.
        """
        from agents.specialists.vt_agent import VTQueryAgent
        agent = VTQueryAgent()
        result = await agent.query(sha256)

        # Normalise keys so the rest of the orchestrator pipeline
        # continues to see the same field names as before.
        stats = result.get("analysis_stats", {})
        return {
            "status": result.get("status", "error"),
            "hash": sha256,
            "malicious": result.get("malicious_count", stats.get("malicious")),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "undetected": stats.get("undetected"),
            "total_engines": result.get("total_engines"),
            "reputation": result.get("reputation"),
            "confidence_contribution": result.get("confidence_contribution", 0.0),
            "first_seen": result.get("first_seen"),
            "last_analyzed": result.get("last_analyzed"),
            "elapsed_seconds": result.get("elapsed_seconds"),
            # pass-through fields for offline / not-found / error cases
            "message": result.get("message"),
            "note": result.get("note"),
            "error": result.get("error"),
        }
