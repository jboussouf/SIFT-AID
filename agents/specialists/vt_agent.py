"""
VTQueryAgent — VirusTotal v3 specialist using the official vt-py SDK.

Uses vt.Client.get_object_async() which returns a vt.Object with proper
attribute access (obj.last_analysis_stats, obj.reputation, etc.) — unlike
client.get() which returns a raw HTTP ClientResponse.
"""

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional, Dict

log = logging.getLogger("sift_aid.specialists.vt")

# ── Inline .env loader (same pattern as hash_specialist) ────────────────────
def _load_env() -> None:
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


class VTQueryAgent:
    """Specialist agent for VirusTotal API v3 queries using vt-py."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")

    # ── Public async interface ───────────────────────────────────────────────

    async def query(self, file_hash: str, timeout: int = 30) -> Dict:
        """
        Query VirusTotal for file analysis results.

        Returns a structured dict with:
          - analysis_stats: raw engine breakdown
          - confidence_contribution: float 0-1 (malicious / total engines)
          - status: "found" | "not_found" | "offline_mode" | "api_error" | "error"

        Handles 404 as neutral evidence (not error), per forensic best-practice.
        """
        if not self.api_key:
            log.warning("[VTQueryAgent] VT_API_KEY not set — offline mode")
            return {
                "source": "virustotal",
                "status": "offline_mode",
                "hash": file_hash,
                "confidence_contribution": 0.0,
                "message": "Set VT_API_KEY in .env for live lookups",
            }

        t0 = time.monotonic()
        try:
            import vt  # lazy import — vt-py optional dependency

            async with vt.Client(self.api_key) as client:
                obj = await client.get_object_async(f"/files/{file_hash}")

            elapsed = round(time.monotonic() - t0, 3)

            stats: dict = obj.last_analysis_stats or {}
            malicious: int = stats.get("malicious", 0)
            total: int = sum(v for v in stats.values() if isinstance(v, int))
            confidence = round(min(malicious / total, 1.0), 2) if total > 0 else 0.0

            log.info(
                "[VTQueryAgent] hash=%s malicious=%d/%d confidence=%.2f elapsed=%.3fs",
                file_hash[:16], malicious, total, confidence, elapsed,
            )

            return {
                "source": "virustotal",
                "status": "found",
                "hash": file_hash,
                "analysis_stats": stats,
                "malicious_count": malicious,
                "total_engines": total,
                "reputation": getattr(obj, "reputation", None),
                "confidence_contribution": confidence,
                "first_seen": getattr(obj, "first_submission_date", None),
                "last_analyzed": getattr(obj, "last_analysis_date", None),
                "elapsed_seconds": elapsed,
            }

        except ImportError:
            return {
                "source": "virustotal",
                "status": "error",
                "hash": file_hash,
                "error": "vt-py not installed — run: pip install vt-py",
                "confidence_contribution": 0.0,
            }

        except Exception as exc:
            elapsed = round(time.monotonic() - t0, 3)
            exc_class = type(exc).__name__

            # NotFoundError < APIError — must be checked first
            if "NotFoundError" in exc_class or (
                hasattr(exc, "code") and getattr(exc, "code", "") == "NotFoundError"
            ) or "not found" in str(exc).lower():
                log.info("[VTQueryAgent] Hash %s not in VT database (neutral signal)", file_hash[:16])
                return {
                    "source": "virustotal",
                    "status": "not_found",
                    "hash": file_hash,
                    "confidence_contribution": 0.0,
                    "note": "Hash not present in VirusTotal database",
                    "elapsed_seconds": elapsed,
                }

            if "APIError" in exc_class:
                log.warning("[VTQueryAgent] VT API error: %s", exc)
                return {
                    "source": "virustotal",
                    "status": "api_error",
                    "hash": file_hash,
                    "error": str(exc),
                    "confidence_contribution": 0.0,
                    "elapsed_seconds": elapsed,
                }

            log.error("[VTQueryAgent] Unexpected error: %s", exc)
            return {
                "source": "virustotal",
                "status": "error",
                "hash": file_hash,
                "error": str(exc),
                "confidence_contribution": 0.0,
                "elapsed_seconds": elapsed,
            }


    # ── Synchronous convenience wrapper ─────────────────────────────────────

    def query_sync(self, file_hash: str, timeout: int = 30) -> Dict:
        """Blocking wrapper for use outside async contexts."""
        return asyncio.run(self.query(file_hash, timeout=timeout))
