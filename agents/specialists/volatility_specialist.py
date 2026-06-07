"""
VolatilitySpecialist — wraps execute_volatility_plugin MCP tool.
Single responsibility: run a whitelisted Volatility 3 plugin.
Fallback: returns empty rows with error message if memory image is missing.
"""

import asyncio
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sift_aid.specialists.volatility")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "120"))

ALLOWED_PLUGINS = {
    "windows.pstree", "windows.pslist", "windows.cmdline", "windows.netscan",
    "windows.malfind", "windows.dlllist", "windows.handles", "windows.envars",
    "linux.pslist", "linux.bash", "linux.netstat", "linux.check_syscall",
}


class VolatilitySpecialist:
    """Run Volatility 3 plugins for memory forensics. Fully read-only."""

    @staticmethod
    async def run(image_path: str, plugin: str, extra_args: list[str] | None = None) -> dict:
        """
        Execute a whitelisted Volatility 3 plugin.
        Returns structured dict with parsed rows, never raw unstructured text.
        """
        t0 = time.monotonic()
        extra_args = extra_args or []

        if plugin not in ALLOWED_PLUGINS:
            return {
                "error": f"Plugin '{plugin}' not in whitelist",
                "allowed_plugins": sorted(ALLOWED_PLUGINS),
            }

        image = Path(image_path)
        if not image.exists():
            return {"error": f"Memory image not found: {image_path}", "plugin": plugin, "row_count": 0}

        try:
            cmd = ["python3", "-m", "volatility3", "-f", str(image), plugin] + extra_args
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=TOOL_TIMEOUT,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)

            raw_out = stdout.decode("utf-8", errors="replace")
            raw_err = stderr.decode("utf-8", errors="replace")

            # Trim to 64KB to protect context window
            if len(raw_out) > 65536:
                raw_out = raw_out[:32768] + "\n[... TRIMMED ...]\n" + raw_out[-32768:]

            # Parse tab/multi-space separated columns into list of dicts
            rows = []
            lines = raw_out.strip().splitlines()
            if len(lines) >= 2:
                # Volatility 3 header detection
                header_line = lines[0]
                header = re.split(r"\t+|\s{2,}", header_line.strip())
                for line in lines[1:]:
                    if not line.strip() or line.startswith("*") or line.startswith("-"):
                        continue
                    values = re.split(r"\t+|\s{2,}", line.strip(), maxsplit=len(header) - 1)
                    if values:
                        rows.append(dict(zip(header, values)))

            result = {
                "image": str(image),
                "plugin": plugin,
                "row_count": len(rows),
                "rows": rows[:200],   # cap rows for context safety
                "raw_output": raw_out[:8192],
                "stderr": raw_err[:1024] if raw_err else None,
                "return_code": proc.returncode,
                "elapsed_seconds": round(time.monotonic() - t0, 3),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            log.info("[VolatilitySpecialist] %s → %d rows in %.2fs", plugin, len(rows), time.monotonic() - t0)
            return result

        except asyncio.TimeoutError:
            log.error("[VolatilitySpecialist] %s timed out after %ds", plugin, TOOL_TIMEOUT)
            return {
                "error": f"Plugin timed out after {TOOL_TIMEOUT}s",
                "plugin": plugin,
                "row_count": 0,
                "rows": [],
            }
        except FileNotFoundError:
            log.error("[VolatilitySpecialist] volatility3 not found in PATH")
            return {
                "error": "volatility3 not installed or not in PATH",
                "plugin": plugin,
                "row_count": 0,
                "rows": [],
            }
        except Exception as exc:
            log.error("[VolatilitySpecialist] %s failed: %s", plugin, exc)
            return {"error": str(exc), "plugin": plugin, "row_count": 0, "rows": []}
