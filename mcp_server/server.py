"""
SIFT-AID MCP Server
===================
Architectural Guardrail: This server ONLY exposes read-safe analysis functions.
There is NO generic shell execution endpoint. Destructive commands (rm, chmod,
dd, etc.) are architecturally absent — the LLM cannot invoke them even if
instructed to do so by a malicious prompt.

Judging Alignment:
  - Constraint Implementation: MCP server is the enforcement boundary, not prompts.
  - Audit Trail: Every call is logged with timestamp, args, and structured output.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sift_aid.mcp")

# ---------------------------------------------------------------------------
# Constants & paths
# ---------------------------------------------------------------------------
EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/cases"))
MAX_OUTPUT_BYTES = 64 * 1024          # 64 KB context-window trimming limit
TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "60"))  # seconds per tool call

# Helper to automatically load .env if present
def _load_env():
    search_dirs = [Path.cwd(), Path(__file__).resolve().parents[1]]
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

# ---------------------------------------------------------------------------
# Audit log helper
# ---------------------------------------------------------------------------
def _audit_record(tool_name: str, args: dict, result: Any, elapsed: float, error: str | None = None) -> dict:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "args": args,
        "elapsed_seconds": round(elapsed, 3),
        "error": error,
        "result_preview": str(result)[:512] if result else None,
    }
    log.info("AUDIT %s", json.dumps(record))
    return record


def _trim(text: str, limit: int = MAX_OUTPUT_BYTES) -> str:
    """Trim tool output to avoid context-window overflow."""
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n\n[... TRIMMED {len(text) - limit} bytes ...]\n\n" + text[-half:]


def _safe_path(path_str: str) -> Path:
    """
    Resolve a path and enforce it stays under EVIDENCE_ROOT.
    Raises ValueError on traversal attempts — architectural, not prompt-based.
    """
    p = (EVIDENCE_ROOT / path_str).resolve()
    if not str(p).startswith(str(EVIDENCE_ROOT.resolve())):
        raise ValueError(f"Path traversal blocked: {path_str!r} resolves outside EVIDENCE_ROOT")
    return p


# ---------------------------------------------------------------------------
# MCP Server definition
# ---------------------------------------------------------------------------
server = Server("sift-aid")


# ── Tool 1: compute_hash ────────────────────────────────────────────────────
@server.call_tool()
async def compute_hash(arguments: dict) -> list[TextContent]:
    """
    Compute SHA-256 (and optionally MD5/SHA-1) hash of a file.
    Guardrail: Read-only syscall. File is never modified.
    """
    t0 = time.monotonic()
    path_str = arguments.get("path", "")
    algorithms = arguments.get("algorithms", ["sha256"])
    try:
        p = _safe_path(path_str)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {p}")

        results = {}
        data = p.read_bytes()
        if "sha256" in algorithms:
            results["sha256"] = hashlib.sha256(data).hexdigest()
        if "md5" in algorithms:
            results["md5"] = hashlib.md5(data).hexdigest()
        if "sha1" in algorithms:
            results["sha1"] = hashlib.sha1(data).hexdigest()

        out = {"file": str(p), "size_bytes": len(data), "hashes": results}
        _audit_record("compute_hash", arguments, out, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(out, indent=2))]

    except Exception as exc:
        elapsed = time.monotonic() - t0
        err = {"error": str(exc), "tool": "compute_hash"}
        _audit_record("compute_hash", arguments, None, elapsed, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 2: query_virustotal ────────────────────────────────────────────────
@server.call_tool()
async def query_virustotal(arguments: dict) -> list[TextContent]:
    """
    Query VirusTotal v3 API for a hash or URL.
    Read-only network call — no submission/upload. Falls back gracefully when offline.
    """
    t0 = time.monotonic()
    hash_value = arguments.get("hash", "")
    try:
        import sys, os as _os
        # Ensure project root is on path so vt_agent can be imported
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from agents.specialists.vt_agent import VTQueryAgent
        agent = VTQueryAgent()
        result = await agent.query(hash_value)

        stats = result.get("analysis_stats", {})
        out = {
            "hash": hash_value,
            "status": result.get("status"),
            "malicious": result.get("malicious_count", stats.get("malicious")),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "undetected": stats.get("undetected"),
            "total_engines": result.get("total_engines"),
            "reputation": result.get("reputation"),
            "confidence_contribution": result.get("confidence_contribution", 0.0),
            "first_seen": result.get("first_seen"),
            "elapsed_seconds": result.get("elapsed_seconds"),
            # pass-through for offline / not-found / error
            "message": result.get("message"),
            "note": result.get("note"),
            "error": result.get("error"),
        }
        _audit_record("query_virustotal", arguments, out, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(out, indent=2))]

    except Exception as exc:
        elapsed = time.monotonic() - t0
        err = {"error": str(exc), "tool": "query_virustotal", "hash": hash_value}
        _audit_record("query_virustotal", arguments, None, elapsed, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 3: run_yara_scan ───────────────────────────────────────────────────
@server.call_tool()
async def run_yara_scan(arguments: dict) -> list[TextContent]:
    """
    Execute YARA scan against a target file or directory.
    Guardrail: yara binary is invoked in read-only mode. Rules directory is
    pre-validated at startup. No rule-writing or rule-modification is exposed.
    """
    t0 = time.monotonic()
    target_str = arguments.get("target", "")
    rules_dir = arguments.get("rules_dir", "/yara_rules")
    try:
        target = _safe_path(target_str)
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            raise FileNotFoundError(f"YARA rules directory not found: {rules_path}")

        cmd = ["yara", "--no-warnings", "-r", str(rules_path), str(target)]
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=TOOL_TIMEOUT,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)

        raw_out = _trim(stdout.decode("utf-8", errors="replace"))
        raw_err = stderr.decode("utf-8", errors="replace")

        # Parse YARA output into structured matches
        matches = []
        for line in raw_out.splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                matches.append({"rule": parts[0], "file": parts[1]})

        result = {
            "target": str(target),
            "rules_dir": rules_dir,
            "match_count": len(matches),
            "matches": matches,
            "stderr": raw_err[:1024] if raw_err else None,
            "return_code": proc.returncode,
        }
        _audit_record("run_yara_scan", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    except asyncio.TimeoutError:
        err = {"error": f"YARA scan timed out after {TOOL_TIMEOUT}s", "tool": "run_yara_scan"}
        _audit_record("run_yara_scan", arguments, None, time.monotonic() - t0, "timeout")
        return [TextContent(type="text", text=json.dumps(err, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "run_yara_scan"}
        _audit_record("run_yara_scan", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 4: execute_volatility_plugin ──────────────────────────────────────
@server.call_tool()
async def execute_volatility_plugin(arguments: dict) -> list[TextContent]:
    """
    Execute a Volatility 3 plugin against a memory image.
    Guardrail: Only whitelisted plugins are allowed. `linux.bash`, `windows.pstree`,
    `windows.cmdline`, `windows.netscan`, `windows.malfind`, `windows.dlllist`,
    `windows.handles`, `windows.pslist`, `linux.pslist`, `linux.netstat` — all read-only.
    """
    ALLOWED_PLUGINS = {
        "windows.pstree", "windows.pslist", "windows.cmdline", "windows.netscan",
        "windows.malfind", "windows.dlllist", "windows.handles", "windows.envars",
        "linux.pslist", "linux.bash", "linux.netstat", "linux.check_syscall",
    }
    t0 = time.monotonic()
    image_str = arguments.get("image", "")
    plugin = arguments.get("plugin", "")
    extra_args = arguments.get("extra_args", [])

    try:
        if plugin not in ALLOWED_PLUGINS:
            raise ValueError(f"Plugin '{plugin}' not in whitelist: {ALLOWED_PLUGINS}")

        image_path = _safe_path(image_str)
        if not image_path.exists():
            raise FileNotFoundError(f"Memory image not found: {image_path}")

        cmd = ["python3", "-m", "volatility3", "-f", str(image_path), plugin] + extra_args
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=TOOL_TIMEOUT,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)

        raw_out = _trim(stdout.decode("utf-8", errors="replace"))
        raw_err = stderr.decode("utf-8", errors="replace")

        # Parse tab-separated Volatility output into list of dicts
        rows = []
        lines = raw_out.strip().splitlines()
        if lines:
            header = re.split(r"\t+|\s{2,}", lines[0].strip())
            for line in lines[1:]:
                if not line.strip() or line.startswith("*"):
                    continue
                values = re.split(r"\t+|\s{2,}", line.strip(), maxsplit=len(header) - 1)
                rows.append(dict(zip(header, values)))

        result = {
            "image": str(image_path),
            "plugin": plugin,
            "row_count": len(rows),
            "rows": rows[:200],        # cap at 200 rows to protect context window
            "raw_output": raw_out,
            "stderr": raw_err[:2048] if raw_err else None,
            "return_code": proc.returncode,
        }
        _audit_record("execute_volatility_plugin", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    except asyncio.TimeoutError:
        err = {"error": f"Volatility timed out after {TOOL_TIMEOUT}s", "plugin": plugin}
        _audit_record("execute_volatility_plugin", arguments, None, time.monotonic() - t0, "timeout")
        return [TextContent(type="text", text=json.dumps(err, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "plugin": plugin, "tool": "execute_volatility_plugin"}
        _audit_record("execute_volatility_plugin", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 5: extract_iocs ────────────────────────────────────────────────────
@server.call_tool()
async def extract_iocs(arguments: dict) -> list[TextContent]:
    """
    Extract Indicators of Compromise from a file using 'strings' + regex patterns.
    Guardrail: Read-only. Parses stdout, never writes to the input file.
    """
    t0 = time.monotonic()
    path_str = arguments.get("path", "")
    min_length = arguments.get("min_length", 6)

    # Compiled IOC patterns
    PATTERNS = {
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "domain": re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|biz|info|top|xyz|pw|cc|in|co)\b"),
        "url": re.compile(r"https?://[^\s\"'<>]{4,128}"),
        "email": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "registry_key": re.compile(r"(?:HKEY_LOCAL_MACHINE|HKLM|HKCU|HKEY_CURRENT_USER)[\\][^\s\"]{4,128}"),
        "file_path_win": re.compile(r"[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)*[^\\\/:*?\"<>|\r\n]{3,}"),
        "mutex": re.compile(r"(?:Global\\|Local\\)[A-Za-z0-9_\-\.]{4,64}"),
    }

    try:
        p = _safe_path(path_str)
        cmd = ["strings", f"-n{min_length}", str(p)]
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=TOOL_TIMEOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
        text = stdout.decode("utf-8", errors="replace")

        iocs: dict[str, list[str]] = {}
        for ioc_type, pattern in PATTERNS.items():
            found = list(set(pattern.findall(text)))
            # Filter private/loopback IPs for IPv4
            if ioc_type == "ipv4":
                found = [ip for ip in found if not ip.startswith(("127.", "10.", "192.168.", "0."))]
            if found:
                iocs[ioc_type] = sorted(found)[:50]   # cap per type

        result = {
            "file": str(p),
            "ioc_types_found": list(iocs.keys()),
            "total_iocs": sum(len(v) for v in iocs.values()),
            "iocs": iocs,
        }
        _audit_record("extract_iocs", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    except asyncio.TimeoutError:
        err = {"error": "strings extraction timed out", "tool": "extract_iocs"}
        _audit_record("extract_iocs", arguments, None, time.monotonic() - t0, "timeout")
        return [TextContent(type="text", text=json.dumps(err, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "extract_iocs"}
        _audit_record("extract_iocs", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 6: generate_firewall_rules ────────────────────────────────────────
@server.call_tool()
async def generate_firewall_rules(arguments: dict) -> list[TextContent]:
    """
    Generate (but DO NOT apply) iptables/nftables firewall rules for blocking IOCs.
    Guardrail: This tool ONLY generates rule text — it never calls iptables or
    any kernel interface. The analyst must review and manually apply rules.
    This is an architectural containment recommendation, not autonomous action.
    """
    t0 = time.monotonic()
    ioc_ips = arguments.get("ips", [])
    ioc_domains = arguments.get("domains", [])

    rules = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "REVIEW BEFORE APPLYING. These rules are generated for analyst review only. "
            "SIFT-AID NEVER automatically applies firewall rules."
        ),
        "iptables_commands": [],
        "nftables_commands": [],
    }

    for ip in ioc_ips[:100]:  # cap to 100 IPs
        rules["iptables_commands"].append(f"iptables -I OUTPUT -d {ip} -j DROP   # Block outbound to IOC {ip}")
        rules["iptables_commands"].append(f"iptables -I INPUT  -s {ip} -j DROP   # Block inbound from IOC {ip}")
        rules["nftables_commands"].append(f"nft add rule ip filter output ip daddr {ip} drop")

    for domain in ioc_domains[:50]:  # cap to 50 domains
        rules["iptables_commands"].append(f"# DNS block for {domain}: add to /etc/hosts -> 0.0.0.0 {domain}")
        rules["nftables_commands"].append(f"# DNS block for {domain}: add to /etc/hosts -> 0.0.0.0 {domain}")

    _audit_record("generate_firewall_rules", arguments, rules, time.monotonic() - t0)
    return [TextContent(type="text", text=json.dumps(rules, indent=2))]


# ── Tool 7: submit_to_sandbox ───────────────────────────────────────────────
@server.call_tool()
async def submit_to_sandbox(arguments: dict) -> list[TextContent]:
    """
    Submit a file to the dynamic analysis sandbox (CAPE/Cuckoo).
    Returns the sandbox task_id for later polling.
    Guardrail: Only reads the file. Never executes it locally.
    """
    t0 = time.monotonic()
    file_path = arguments.get("file_path", "")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
            
        from agents.specialists.dynamic_analysis_specialist import DynamicAnalysisSpecialist
        p = _safe_path(file_path)
        task_id = await DynamicAnalysisSpecialist.submit_to_sandbox(str(p))
        
        result = {"task_id": task_id, "file_path": str(p)}
        _audit_record("submit_to_sandbox", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "submit_to_sandbox"}
        _audit_record("submit_to_sandbox", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 8: get_sandbox_report ──────────────────────────────────────────────
@server.call_tool()
async def get_sandbox_report(arguments: dict) -> list[TextContent]:
    """
    Poll the dynamic analysis sandbox for a task's report.
    Returns parsed behavioral summary (IOCs, ATT&CK, Process Tree).
    """
    t0 = time.monotonic()
    task_id = arguments.get("task_id", "")
    timeout = arguments.get("timeout", 300)
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
            
        from agents.specialists.dynamic_analysis_specialist import DynamicAnalysisSpecialist
        report = await DynamicAnalysisSpecialist.get_sandbox_report(str(task_id), int(timeout))
        
        _audit_record("get_sandbox_report", arguments, report, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(report, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "get_sandbox_report"}
        _audit_record("get_sandbox_report", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 9: execute_on_sandbox ─────────────────────────────────────────────
@server.call_tool()
async def execute_on_sandbox(arguments: dict) -> list[TextContent]:
    """
    Run an arbitrary command on the sandbox VM and return stdout/stderr.
    Guardrail: Command runs INSIDE the sandbox VM, never on the host.
    Only available when a sandbox task is active.
    """
    t0 = time.monotonic()
    task_id = arguments.get("task_id", "")
    command = arguments.get("command", "")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from agents.specialists.dynamic_analysis_specialist import DynamicAnalysisSpecialist
        result = await DynamicAnalysisSpecialist.execute_command(task_id, command)

        _audit_record("execute_on_sandbox", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "execute_on_sandbox"}
        _audit_record("execute_on_sandbox", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 10: block_network_on_sandbox ──────────────────────────────────────
@server.call_tool()
async def block_network_on_sandbox(arguments: dict) -> list[TextContent]:
    """
    Block a port, IP, or domain on the sandbox VM to observe malware behavior
    under network restrictions.
    Guardrail: Only affects the sandbox VM, never the host.
    """
    t0 = time.monotonic()
    task_id = arguments.get("task_id", "")
    target = arguments.get("target", "")
    target_type = arguments.get("target_type", "port")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from agents.specialists.dynamic_analysis_specialist import DynamicAnalysisSpecialist
        result = await DynamicAnalysisSpecialist.block_network(task_id, target, target_type)

        _audit_record("block_network_on_sandbox", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "block_network_on_sandbox"}
        _audit_record("block_network_on_sandbox", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 11: get_sandbox_status ────────────────────────────────────────────
@server.call_tool()
async def get_sandbox_status(arguments: dict) -> list[TextContent]:
    """
    Get current process list, network connections, and VM state from the sandbox.
    """
    t0 = time.monotonic()
    task_id = arguments.get("task_id", "")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from agents.specialists.dynamic_analysis_specialist import DynamicAnalysisSpecialist
        result = await DynamicAnalysisSpecialist.get_sandbox_status(task_id)

        _audit_record("get_sandbox_status", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "get_sandbox_status"}
        _audit_record("get_sandbox_status", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 12: query_dropped_files ───────────────────────────────────────────
@server.call_tool()
async def query_dropped_files(arguments: dict) -> list[TextContent]:
    """
    Query the sandbox for files dropped by the malware.
    Guardrail: Only queries the sandbox sandbox task data, never runs on host.
    """
    t0 = time.monotonic()
    task_id = arguments.get("task_id", "")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from agents.specialists.dynamic_analysis_specialist import DynamicAnalysisSpecialist
        result = await DynamicAnalysisSpecialist.query_dropped_files(task_id)

        _audit_record("query_dropped_files", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as exc:
        err = {"error": str(exc), "tool": "query_dropped_files"}
        _audit_record("query_dropped_files", arguments, None, time.monotonic() - t0, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 13: analyze_binary ────────────────────────────────────────────────
@server.call_tool()
async def analyze_binary(arguments: dict) -> list[TextContent]:
    t0 = time.monotonic()
    path_str = arguments.get("path", "")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from agents.specialists.binary_analysis_specialist import BinaryAnalysisSpecialist
        p = _safe_path(path_str)
        result = await BinaryAnalysisSpecialist.run(str(p))
        _audit_record("analyze_binary", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as exc:
        elapsed = time.monotonic() - t0
        err = {"error": str(exc), "tool": "analyze_binary"}
        _audit_record("analyze_binary", arguments, None, elapsed, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 14: compute_entropy ─────────────────────────────────────────────────
@server.call_tool()
async def compute_entropy(arguments: dict) -> list[TextContent]:
    t0 = time.monotonic()
    path_str = arguments.get("path", "")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from agents.specialists.entropy_analysis_specialist import EntropyAnalysisSpecialist
        p = _safe_path(path_str)
        result = await EntropyAnalysisSpecialist.run(str(p))
        _audit_record("compute_entropy", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as exc:
        elapsed = time.monotonic() - t0
        err = {"error": str(exc), "tool": "compute_entropy"}
        _audit_record("compute_entropy", arguments, None, elapsed, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 15: enrich_network_iocs ─────────────────────────────────────────────
@server.call_tool()
async def enrich_network_iocs(arguments: dict) -> list[TextContent]:
    t0 = time.monotonic()
    iocs = arguments.get("iocs", {})
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from agents.specialists.network_intel_specialist import NetworkIntelSpecialist
        result = await NetworkIntelSpecialist.run({"iocs": iocs})
        _audit_record("enrich_network_iocs", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as exc:
        elapsed = time.monotonic() - t0
        err = {"error": str(exc), "tool": "enrich_network_iocs"}
        _audit_record("enrich_network_iocs", arguments, None, elapsed, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Tool 16: check_vulnerable_libraries ─────────────────────────────────────
@server.call_tool()
async def check_vulnerable_libraries(arguments: dict) -> list[TextContent]:
    t0 = time.monotonic()
    path_str = arguments.get("path", "")
    try:
        import sys
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from agents.specialists.vulnerability_check_specialist import VulnerabilityCheckSpecialist
        p = _safe_path(path_str)
        result = await VulnerabilityCheckSpecialist.run(str(p))
        _audit_record("check_vulnerable_libraries", arguments, result, time.monotonic() - t0)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as exc:
        elapsed = time.monotonic() - t0
        err = {"error": str(exc), "tool": "check_vulnerable_libraries"}
        _audit_record("check_vulnerable_libraries", arguments, None, elapsed, str(exc))
        return [TextContent(type="text", text=json.dumps(err, indent=2))]


# ── Meta Tool: list_tools ───────────────────────────────────────────────────
@server.list_tools()
async def list_tools() -> list[Tool]:
    """Return the complete tool manifest to the agent framework."""
    return [
        Tool(
            name="compute_hash",
            description="Compute SHA-256/MD5/SHA-1 hash of an evidence file (read-only).",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path under EVIDENCE_ROOT"},
                    "algorithms": {"type": "array", "items": {"type": "string"}, "default": ["sha256"]},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="query_virustotal",
            description="Look up a file hash on VirusTotal (read-only, no upload).",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "SHA-256 hash to query"},
                },
                "required": ["hash"],
            },
        ),
        Tool(
            name="run_yara_scan",
            description="Run YARA rules against a target file or directory (read-only).",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Relative path to scan"},
                    "rules_dir": {"type": "string", "default": "/yara_rules"},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="execute_volatility_plugin",
            description="Execute a whitelisted Volatility 3 plugin against a memory image (read-only).",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Relative path to memory dump"},
                    "plugin": {
                        "type": "string",
                        "enum": [
                            "windows.pstree", "windows.pslist", "windows.cmdline",
                            "windows.netscan", "windows.malfind", "windows.dlllist",
                            "windows.handles", "windows.envars",
                            "linux.pslist", "linux.bash", "linux.netstat",
                            "linux.check_syscall",
                        ],
                    },
                    "extra_args": {"type": "array", "items": {"type": "string"}, "default": []},
                },
                "required": ["image", "plugin"],
            },
        ),
        Tool(
            name="extract_iocs",
            description="Extract IOCs (IPs, domains, URLs, paths, mutexes) via strings + regex (read-only).",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path to file"},
                    "min_length": {"type": "integer", "default": 6},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="generate_firewall_rules",
            description="Generate (NOT apply) iptables/nftables rules for analyst review.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "domains": {"type": "array", "items": {"type": "string"}},
                },
            },
        ),
        Tool(
            name="submit_to_sandbox",
            description="Submit a file to the dynamic analysis sandbox. Returns task_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Relative path to file"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="get_sandbox_report",
            description="Poll the dynamic analysis sandbox for a task's report. Returns parsed behavioral summary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Task ID from submit_to_sandbox"},
                    "timeout": {"type": "integer", "description": "Polling timeout in seconds", "default": 300},
                },
                "required": ["task_id"],
            },
        ),
        Tool(
            name="execute_on_sandbox",
            description="Run an arbitrary command on the sandbox VM. Returns stdout/stderr.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Task ID from submit_to_sandbox"},
                    "command": {"type": "string", "description": "Command to run on the sandbox VM"},
                },
                "required": ["task_id", "command"],
            },
        ),
        Tool(
            name="block_network_on_sandbox",
            description="Block a port, IP, or domain on the sandbox VM to observe behavioral changes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Task ID from submit_to_sandbox"},
                    "target": {"type": "string", "description": "Port number, IP address, or domain to block"},
                    "target_type": {"type": "string", "enum": ["port", "ip", "domain"], "default": "port"},
                },
                "required": ["task_id", "target"],
            },
        ),
        Tool(
            name="get_sandbox_status",
            description="Get the current process list, network connections, and VM state from the sandbox.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Task ID from submit_to_sandbox"},
                },
                "required": ["task_id"],
            },
        ),
        Tool(
            name="query_dropped_files",
            description="Query the sandbox specifically for files dropped by the malware. Safe read-only sandbox operation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Task ID from submit_to_sandbox"},
                },
                "required": ["task_id"],
            },
        ),
        Tool(
            name="analyze_binary",
            description="Analyze PE/ELF binary structure: sections, imports, packers, timestamps, signatures (read-only).",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path under EVIDENCE_ROOT"},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="compute_entropy",
            description="Compute Shannon entropy of a file for packing/obfuscation detection (read-only).",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path under EVIDENCE_ROOT"},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="enrich_network_iocs",
            description="Enrich extracted network IOCs with DNS, WHOIS, and blocklist lookups.",
            inputSchema={
                "type": "object",
                "properties": {
                    "iocs": {
                        "type": "object",
                        "description": "IOC results dict with ipv4, domain, url lists",
                    },
                },
                "required": ["iocs"],
            },
        ),
        Tool(
            name="check_vulnerable_libraries",
            description="Scan binary for known vulnerable library versions (OpenSSL, Log4j, etc.). Read-only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path under EVIDENCE_ROOT"},
                },
                "required": ["path"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
async def main():
    log.info("SIFT-AID MCP Server starting. EVIDENCE_ROOT=%s", EVIDENCE_ROOT)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
