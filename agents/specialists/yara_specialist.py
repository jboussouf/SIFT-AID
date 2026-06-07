"""
YARASpecialist — wraps the run_yara_scan MCP tool.
Single responsibility: run YARA rules and return structured matches.
Fallback: returns empty match list with error if yara binary is missing.
"""

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sift_aid.specialists.yara")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "60"))
YARA_RULES_DIR = os.environ.get("YARA_RULES_DIR", "./yara_rules")


class YARASpecialist:
    """Run YARA scans against evidence files. Fully read-only."""

    @staticmethod
    async def run(target_path: str, rules_dir: str = YARA_RULES_DIR) -> dict:
        """
        Execute YARA scan and return structured matches.
        Never modifies target file or rule files.
        """
        t0 = time.monotonic()
        target = Path(target_path)
        rules = Path(rules_dir)

        if not target.exists():
            return {"error": f"Target not found: {target_path}", "match_count": 0}

        if not rules.exists():
            log.warning("[YARASpecialist] Rules dir %s not found — using built-in fallback", rules_dir)
            return {
                "target": str(target),
                "rules_dir": rules_dir,
                "match_count": 0,
                "matches": [],
                "warning": "YARA rules directory not found — scan skipped",
                "elapsed_seconds": round(time.monotonic() - t0, 3),
            }

        try:
            def _yara_scan():
                # Try python-yara first (preferred — no subprocess)
                import yara  # type: ignore
                
                # yara.compile needs file paths, not a directory. We build a dict of all .yar files.
                rule_files = {p.stem: str(p) for p in rules.glob("*.yar")}
                ruleset = yara.compile(filepaths=rule_files) if rule_files else yara.compile(rules_dir)
                
                raw_matches = ruleset.match(str(target), timeout=TOOL_TIMEOUT)

                matches = []
                for m in raw_matches:
                    severity = m.meta.get("severity", "medium") if hasattr(m, "meta") else "medium"
                    matches.append({
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "tags": list(m.tags),
                        "severity": severity,
                        "strings": [
                            {
                                "identifier": s.identifier,
                                "offset": s.instances[0].offset if s.instances else 0,
                                "matched_data": s.instances[0].matched_data.hex() if s.instances else "",
                            }
                            for s in m.strings[:10]  # cap at 10 string matches per rule
                        ],
                        "file": str(target),
                    })

                result = {
                    "target": str(target),
                    "rules_dir": rules_dir,
                    "match_count": len(matches),
                    "matches": matches,
                    "elapsed_seconds": round(time.monotonic() - t0, 3),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                log.info("[YARASpecialist] %d matches in %.2fs", len(matches), time.monotonic() - t0)
                return result
                
            return await asyncio.to_thread(_yara_scan)

        except ImportError:
            # Fallback to yara CLI subprocess
            return await YARASpecialist._run_cli(str(target), rules_dir, t0)

        except Exception as exc:
            log.error("[YARASpecialist] Error: %s", exc)
            return {
                "target": str(target),
                "error": str(exc),
                "match_count": 0,
                "matches": [],
                "elapsed_seconds": round(time.monotonic() - t0, 3),
            }

    @staticmethod
    async def _run_cli(target: str, rules_dir: str, t0: float) -> dict:
        """Fallback: run yara CLI binary via subprocess."""
        try:
            cmd = ["yara", "--no-warnings", "-r", rules_dir, target]
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=TOOL_TIMEOUT,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
            raw = stdout.decode("utf-8", errors="replace")

            matches = []
            for line in raw.splitlines():
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    matches.append({"rule": parts[0], "file": parts[1], "source": "cli"})

            return {
                "target": target,
                "rules_dir": rules_dir,
                "match_count": len(matches),
                "matches": matches,
                "stderr": stderr.decode("utf-8", errors="replace")[:512],
                "return_code": proc.returncode,
                "elapsed_seconds": round(time.monotonic() - t0, 3),
            }
        except asyncio.TimeoutError:
            return {"target": target, "error": "YARA CLI timeout", "match_count": 0, "matches": []}
        except FileNotFoundError:
            return {"target": target, "error": "yara binary not found", "match_count": 0, "matches": []}
