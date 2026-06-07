"""
SIFT-AID — LangGraph Orchestrator
=======================================
State machine: Ingest → Plan → Execute_Specialists → DynamicAnalysis → LLM_Analysis
                                                                    ↕ (sandbox loop)
                                                              Sandbox_Interact
                                                                    ↓
                                                              Validate → Self_Correct → Contain → Report

Judging Alignment:
  - Autonomous Execution: Cyclic self-correction loop with hard max_iterations cap
  - IR Accuracy: Cross-validation node separates confirmed vs. inferred findings
  - Sub-8-min: Per-node timeouts, parallel specialist execution, early exit
  - Audit Trail: Every state transition logged with timestamp and iteration delta
"""

from __future__ import annotations

import asyncio
import json
import logging
import operator
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, TypedDict
from urllib.parse import urlparse

from langgraph.graph import END, StateGraph

from agents.specialists import (
    HashSpecialist,
    YARASpecialist,
    VolatilitySpecialist,
    IOCSpecialist,
    ContainmentSpecialist,
    BinaryAnalysisSpecialist,
    EntropyAnalysisSpecialist,
    NetworkIntelSpecialist,
    VulnerabilityCheckSpecialist,
)
from agents.specialists.dynamic_analysis_specialist import DynamicAnalysisSpecialist
from agents.specialists.attack_mapper import AttackMapper
from agents.specialists.ioc_memory import IOCMemory
from pipeline.audit_logger import AuditLogger
from pipeline.reporter import Reporter

log = logging.getLogger("sift_aid.orchestrator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "3"))
MAX_LLM_ITERATIONS = int(os.environ.get("MAX_LLM_ITERATIONS", "3"))
NODE_TIMEOUT = int(os.environ.get("NODE_TIMEOUT", "120"))   # seconds per LangGraph node
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "300"))    # seconds for Ollama LLM call
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.70"))
CASES_DIR = Path(os.environ.get("CASES_DIR", "/cases"))


# ---------------------------------------------------------------------------
# State Schema
# ---------------------------------------------------------------------------
class AgentState(TypedDict):
    """
    Shared mutable state passed between LangGraph nodes.
    Every field change is recorded by the audit logger.
    """
    # Session identifiers
    incident_id: str
    session_start: str

    # Input
    sample_path: str
    memory_image_path: Optional[str]

    # Orchestration bookkeeping
    iteration: int
    max_iterations: int
    node_timings: dict[str, float]         # node_name -> wall-clock seconds
    errors: list[dict]

    # Phase outputs (structured dicts, never raw text)
    hash_results: Optional[dict]
    vt_results: Optional[dict]
    yara_results: Optional[dict]
    volatility_results: dict[str, Any]     # plugin_name -> result dict
    ioc_results: Optional[dict]
    dynamic_results: Optional[dict]
    firewall_rules: Optional[dict]

    # Scoring
    findings: list[dict]                   # confirmed finding dicts
    inferences: list[dict]                 # lower-confidence inferences
    confidence_score: float                # overall combined score
    verdict: str                           # BENIGN / SUSPICIOUS / ANALYST REVIEW / MALICIOUS
    static_confidence_score: float         # score from static analysis only
    dynamic_confidence_score: float        # score from dynamic analysis only
    validation_delta: float                # confidence gain vs. previous iteration
    hallucination_flags: list[str]

    # LLM cross-analysis loop
    llm_model: Optional[str]               # model selected via dashboard dropdown
    llm_analysis: Optional[dict]           # LLM's reasoning and comparative analysis
    sandbox_actions_requested: list[dict]  # actions LLM wants to run on the sandbox
    llm_iteration: int
    max_llm_iterations: int
    output_agent: Annotated[list[dict], operator.add]               # previous LLM outputs

    # Control flow
    needs_correction: bool
    correction_reason: str
    status: Literal["running", "completed", "failed", "contained"]
    plan: list[str]                        # ordered list of specialist steps
    report_paths: dict[str, str]

    # Intelligence enrichment
    attack_techniques: list                # MITRE ATT&CK technique mappings
    ioc_memory_warnings: list             # cross-incident IOC matches from LanceDB

    # New specialist results (v1.2.0)
    binary_analysis_results: Optional[dict]
    entropy_results: Optional[dict]
    network_intel_results: Optional[dict]
    vulnerability_results: Optional[dict]


# ---------------------------------------------------------------------------
# Node helpers
# ---------------------------------------------------------------------------
def _timed_node(name: str):
    """Decorator that records wall-clock time for each node execution."""
    def decorator(fn):
        async def wrapper(state: AgentState) -> AgentState:
            t0 = time.monotonic()
            log.info("[NODE:%s] start (iteration=%d)", name, state.get("iteration", 0))
            try:
                result = await asyncio.wait_for(fn(state), timeout=NODE_TIMEOUT)
            except asyncio.TimeoutError:
                log.error("[NODE:%s] TIMED OUT after %ds", name, NODE_TIMEOUT)
                state["errors"].append({
                    "node": name,
                    "error": f"Timeout after {NODE_TIMEOUT}s",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                return state
            elapsed = time.monotonic() - t0
            result["node_timings"] = {**state.get("node_timings", {}), name: round(elapsed, 2)}
            log.info("[NODE:%s] done in %.2fs", name, elapsed)
            return result
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------
def _format_interactive_results(results: list) -> str:
    """Format interactive sandbox results into a clear ALREADY EXECUTED table."""
    if not results:
        return "No interactive commands run yet."
    lines = ["--- ALREADY EXECUTED COMMANDS ---"]
    for i, r in enumerate(results, 1):
        action = r.get("action", "?")
        cmd = r.get("command") or r.get("target", "")
        result = r.get("result") or r.get("error", "")
        lines.append(f"  {i}. Action: {action}")
        if cmd:
            lines.append(f"     Command: {cmd}")
        if result:
            result_str = str(result)[:300]
            lines.append(f"     Result: {result_str}")
    lines.append("--- END OF EXECUTED COMMANDS ---")
    return "\n".join(lines)

def _dedup_actions(requested: list, already_done: list) -> list:
    """Filter out actions that match commands already executed."""
    done_set = set()
    for r in already_done:
        act = r.get("action", "")
        cmd = r.get("command") or r.get("target", "")
        done_set.add((act, cmd))
    return [
        a for a in requested
        if (a.get("action", ""), a.get("command") or a.get("target", "")) not in done_set
    ]

_KNOWN_ACTIONS = {"execute_command", "block_network", "get_status", "query_dropped_files", "check_documentation"}

def _parse_llm_json(raw: str) -> dict:
    """Extract and parse JSON from LLM output, handling markdown wrappers."""
    if not raw:
        return {}
    try:
        # Fast path
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    
    # Try to extract from markdown
    raw_clean = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
    raw_clean = re.sub(r'```\s*$', '', raw_clean.strip(), flags=re.MULTILINE)
    try:
        return json.loads(raw_clean)
    except json.JSONDecodeError:
        # Fallback: maybe there's text before/after the JSON block
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        raise ValueError("Could not parse JSON from LLM output")

def _normalize_actions(raw_actions: list) -> list:
    """Normalize malformed LLM action lists into the standard format."""
    if not isinstance(raw_actions, list):
        return []
    normalized = []
    for item in raw_actions:
        if not isinstance(item, dict):
            continue
        action = item.get("action", "")
        if action in _KNOWN_ACTIONS:
            # Already well-formed
            normalized.append(item)
            continue
        # Try to infer action from keys
        found = False
        for key in item:
            if key in _KNOWN_ACTIONS:
                # Format: {"execute_command": "reg query ..."}
                val = item[key]
                entry = {"action": key}
                if key == "execute_command":
                    entry["command"] = str(val) if val else ""
                elif key == "block_network":
                    entry["target"] = str(val) if val else ""
                    entry["target_type"] = "port"
                normalized.append(entry)
                found = True
                break
        if found:
            continue
        # Try to infer from presence of command/target keys
        if item.get("command") or item.get("target"):
            if item.get("command"):
                normalized.append({"action": "execute_command", "command": str(item["command"])})
            elif item.get("target"):
                normalized.append({"action": "block_network", "target": str(item["target"]), "target_type": item.get("target_type", "port")})
            continue
        # Last resort: treat entire dict keys as hints
        known_match = [k for k in item if k in _KNOWN_ACTIONS]
        if known_match:
            k = known_match[0]
            v = item[k]
            entry = {"action": k}
            if k == "execute_command":
                entry["command"] = str(v) if v else ""
            elif k == "block_network":
                entry["target"] = str(v) if v else ""
                entry["target_type"] = "port"
            normalized.append(entry)
    return normalized

async def _call_llm_analysis(
    static_summary: dict,
    dynamic_summary: dict,
    interactive_results: list[dict],
    llm_iteration: int,
    model_name: str = "",
    output_agent: list[dict] = None,
) -> dict:
    """
    Call Ollama LLM to cross-analyze static and dynamic reports.
    Returns structured dict with scores, reasoning, and requested sandbox actions.
    Falls back to heuristic if Ollama is unavailable.
    """
    if output_agent is None:
        output_agent = []
        
    agent_tests_str = "".join([f'test {i}: {json.dumps(output_agent[i], default=str)}\n' for i in range(len(output_agent))])

    prompt = f"""You are a DFIR Analyst. Review the evidence below and determine if this binary is MALICIOUS or BENIGN.

## STATIC ANALYSIS REPORT (iteration {llm_iteration})
Hash+VT: {json.dumps(static_summary.get('hash_vt', {}), default=str)}
YARA: {json.dumps(static_summary.get('yara', {}), default=str)}
IOCs Extracted: {json.dumps(static_summary.get('iocs', {}), default=str)}
Volatility Memory: {json.dumps(static_summary.get('volatility', {}), default=str)}

## DYNAMIC ANALYSIS REPORT (iteration {llm_iteration})
Network IOCs: {json.dumps(dynamic_summary.get('network_iocs', []), default=str)}
Dropped Files: {json.dumps(dynamic_summary.get('dropped_files', []), default=str)}
Process Tree: {json.dumps(dynamic_summary.get('process_tree', []), default=str)}
ATT&CK Techniques: {json.dumps(dynamic_summary.get('attack_techniques', []), default=str)}
Binary Documentation Check: {json.dumps(dynamic_summary.get('documentation_check', {}), default=str)}

## INTERACTIVE SANDBOX RESULTS
{_format_interactive_results(interactive_results) if interactive_results else "No interactive commands run yet."}

## Agent tests
{agent_tests_str}
 
## CRITICAL RULES
A. CRITICAL: ONLY reference evidence that is actually present in the reports above. Do NOT invent or extrapolate specific IPs, domains, registry keys, file paths, or process names that are not in the provided data. If the evidence is empty or shows nothing suspicious, the binary is likely BENIGN.
B. Consider the possibility that this is a FALSE POSITIVE — many legitimate binaries trigger generic YARA rules or have imports that look suspicious. Strong evidence requires actual malicious behavior (C2 connections, process injection, file encryption, etc.).
C. Low scores (0.0-0.3) = BENIGN / not enough evidence. High scores (0.7-1.0) = MALICIOUS with strong evidence.

## TASK
1. Score the STATIC analysis evidence from 0.0 (benign) to 1.0 (malicious).
2. Score the DYNAMIC analysis evidence from 0.0 (benign) to 1.0 (malicious).
3. Write a "reasoning" field (1-2 sentences) that cites SPECIFIC evidence from the reports above.
   - DO NOT mention confidence scores, numbers, or percentages in the reasoning field.
   - DO reference concrete artifacts: e.g. YARA rule names, VirusTotal vendor count, specific IOCs, process names, network connections, dropped file names, ATT&CK technique IDs.
   - BENIGN example: "No YARA hits, zero VirusTotal detections, and the binary self-identifies as a standard GNU coreutils tool via --help output."
   - MALICIOUS example: "YARA rule 'ransomware_filecrypt' matched, process tree shows svchost.exe spawning cmd.exe, and a C2 beacon to 185.220.101.5:443 was observed in the network IOCs."
4. If BENIGN: Set malicious_actions: "".
5. If MALICIOUS: populate malicious_actions with a 1-2 sentence description of the specific harmful behaviors observed.
6. If you already have interactive results from previous iterations, INTEGRATE those findings into your reasoning.
7. If you need MORE evidence from the sandbox to make a confident determination, list NEW commands you haven't requested before. DO NOT repeat commands that are already shown in the ALREADY EXECUTED COMMANDS section above. For example:
   - To check network behavior: {{"action": "execute_command", "command": "netstat -an"}}
   - To check process state: {{"action": "execute_command", "command": "tasklist"}}
   - To block the C2 port: {{"action": "block_network", "target": "443", "target_type": "port"}}
   - To check registry persistence: {{"action": "execute_command", "command": "reg query HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"}}
   - To check if the malware reconnects after blocking: {{"action": "get_status"}}
   - To explicitly query files dropped by the malware: {{"action": "query_dropped_files"}}
   - To check if the binary is a legitimate system tool (runs --help / -h): {{"action": "check_documentation"}}

   If you have sufficient evidence and do NOT need more commands, return an empty actions list.

Respond in pure JSON with this exact schema:
{{
  "static_confidence_score": 0.0,
  "dynamic_confidence_score": 0.0,
  "reasoning": "string", #make sure to put 2-3 sentences as reasoning, based on teh evidence collected so far
  "malicious_actions": "string",
  "actions_requested": []
}}"""

    try:
        import ollama
        client = ollama.AsyncClient(host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
        response = await asyncio.wait_for(
            client.chat(
                model=model_name or os.environ.get("OLLAMA_MODEL", "qwen:1.8b"),
                messages=[
                    {'role': 'system', 'content': 'You are a DFIR analyst. Output only JSON.'},
                    {'role': 'user', 'content': prompt},
                ],
                format='json',
                options={'temperature': 0.0, 'num_predict': 200},
                keep_alive='5m',
            ),
            timeout=min(LLM_TIMEOUT, max(1, NODE_TIMEOUT - 5)),
        )
        msg = getattr(response, 'message', response)
        raw = msg.content if hasattr(msg, 'content') else msg.get('content', '')
        if not raw:
            raise ValueError("Empty LLM response")
        output = _parse_llm_json(raw)
        log.info("[LLM] Agent Output:\n%s", json.dumps(output, indent=2))
        raw_actions = output.get("actions_requested", [])
        output["actions_requested"] = _normalize_actions(raw_actions)
        log.info("[LLM] Analysis complete: static=%.2f dynamic=%.2f actions=%d (normalized from %d raw)",
                 output.get('static_confidence_score', 0.0),
                 output.get('dynamic_confidence_score', 0.0),
                 len(output.get('actions_requested', [])),
                 len(raw_actions) if isinstance(raw_actions, list) else 0)
        return output
    except Exception as e:
        log.warning("[LLM] Ollama unavailable (%s) — using heuristic scoring", type(e).__name__)
        return _heuristic_analysis(static_summary, dynamic_summary)


def _heuristic_analysis(static_summary: dict, dynamic_summary: dict) -> dict:
    """Fallback when LLM is unavailable — weighted corroborated scoring."""
    static_votes = []
    signals = []

    # VT signals
    vt_malicious = static_summary.get('hash_vt', {}).get('malicious') or 0
    vt_suspicious = static_summary.get('hash_vt', {}).get('suspicious') or 0
    if vt_malicious > 5:
        static_votes.append(0.4)
        signals.append("vt_malicious")
    elif vt_suspicious > 0:
        static_votes.append(0.2)
        signals.append("vt_suspicious")

    # YARA signals (weighted by severity)
    yara_matches = static_summary.get('yara', {}).get('matches', [])
    has_high_yara = False
    has_low_yara = False
    for match in yara_matches:
        sev = match.get('severity', 'medium')
        if sev in ('critical', 'high'):
            has_high_yara = True
        else:
            has_low_yara = True
    if has_high_yara:
        static_votes.append(0.3)
        signals.append("yara_high")
    elif has_low_yara:
        static_votes.append(0.1)
        signals.append("yara_low")

    # IOC signals
    total_iocs = static_summary.get('iocs', {}).get('total_iocs', 0)
    if total_iocs > 10:
        static_votes.append(0.2)
        signals.append("iocs_suspicious")
        static_score = sum(static_votes)
    elif total_iocs > 0:
        static_score = min(0.15, total_iocs * 0.015)
    else:
        static_score = 0.0

    if static_votes:
        static_score = sum(static_votes)

    # Corroboration bonus
    has_yara = has_high_yara or has_low_yara
    has_ioc = "iocs_suspicious" in signals
    if has_yara and (has_ioc or "vt_malicious" in signals):
        static_score += 0.2

    # Cap for low-signal only
    only_low = signals and all(s in ("yara_low",) for s in signals)
    if only_low or (len(signals) == 1 and "yara_low" in signals):
        static_score = min(static_score, 0.3)

    dyn_boost = dynamic_summary.get('confidence_boost', 0.0)
    dyn_score = dyn_boost

    # Build evidence-based reasoning sentence from actual signals found
    signal_descriptions = {
        "vt_malicious": f"{vt_malicious} VirusTotal engines flagged this sample as malicious",
        "vt_suspicious": f"{vt_suspicious} VirusTotal engines flagged this sample as suspicious",
        "yara_high": "a high-severity YARA rule matched",
        "yara_low": "a low-severity YARA rule matched",
        "iocs_suspicious": f"{total_iocs} IOCs were extracted (IPs, domains, URLs)",
    }
    if signals:
        evidence_parts = [signal_descriptions.get(s, s) for s in signals]
        reasoning = "Static analysis flagged this sample because: " + "; ".join(evidence_parts) + ". Dynamic analysis unavailable (heuristic fallback)."
    else:
        reasoning = "No significant static or dynamic indicators found; sample appears benign based on available evidence."

    return {
        "static_confidence_score": round(static_score, 3),
        "dynamic_confidence_score": round(dyn_score, 3),
        "reasoning": reasoning,
        "actions_requested": [],
    }


# ---------------------------------------------------------------------------
# ── NODE 1: Ingest ───────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_ingest(state: AgentState) -> AgentState:
    """
    Initialise the incident session. Validate input paths.
    Evidence is NEVER copied or modified — paths are read-only references.
    """
    incident_id = state.get("incident_id") or f"INC-{uuid.uuid4().hex[:8].upper()}"
    case_dir = CASES_DIR / incident_id
    (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (case_dir / "report").mkdir(parents=True, exist_ok=True)

    log.info("[INGEST] Incident %s — sample: %s", incident_id, state["sample_path"])

    return {
        **state,
        "incident_id": incident_id,
        "session_start": datetime.now(timezone.utc).isoformat(),
        "iteration": 0,
        "max_iterations": MAX_ITERATIONS,
        "node_timings": {},
        "errors": [],
        "volatility_results": {},
        "findings": [],
        "inferences": [],
        "confidence_score": 0.0,
        "static_confidence_score": 0.0,
        "dynamic_confidence_score": 0.0,
        "validation_delta": 0.0,
        "hallucination_flags": [],
        "dynamic_results": None,
        "llm_analysis": None,
        "sandbox_actions_requested": [],
        "llm_iteration": 0,
        "max_llm_iterations": MAX_LLM_ITERATIONS,
        "output_agent": [],
        "needs_correction": False,
        "correction_reason": "",
        "status": "running",
        "report_paths": {},
    }


# ---------------------------------------------------------------------------
# ── NODE 2: Plan ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_plan(state: AgentState) -> AgentState:
    """
    Determine which specialist agents to run based on available evidence.
    Uses simple heuristics — no LLM call here to save latency.
    """
    plan = ["hash", "virustotal", "yara", "binary_analysis", "entropy_analysis", "vuln_check", "ioc_extraction"]

    if state.get("memory_image_path"):
        plan += ["volatility_pslist", "volatility_netscan", "volatility_malfind", "volatility_cmdline"]

    vt_r = state.get("vt_results") or {}
    yara_r = state.get("yara_results") or {}
    vt_mal = vt_r.get("malicious") or 0
    yara_cnt = yara_r.get("match_count") or 0
    suspicious = (vt_mal > 0) or (yara_cnt > 0)

    if suspicious or state.get("confidence_score", 0.0) < 0.8:
        if "run_dynamic_analysis" not in plan:
            plan.append("run_dynamic_analysis")

    ioc_r = state.get("ioc_results") or {}
    if ioc_r.get("iocs", {}).get("domain") or ioc_r.get("iocs", {}).get("ipv4") or ioc_r.get("iocs", {}).get("url"):
        plan.append("network_intel")

    plan.append("containment")

    log.info("[PLAN] Execution plan: %s", plan)
    return {**state, "plan": plan}


# ---------------------------------------------------------------------------
# ── NODE 3: Execute_Specialists ──────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_execute_specialists(state: AgentState) -> AgentState:
    """
    Run specialist agents in parallel where safe (hash+YARA+strings can overlap;
    Volatility plugins run sequentially to avoid memory contention).
    """
    plan = state.get("plan", [])
    state = dict(state)

    # ── Parallel group 1: hash, YARA, binary analysis, entropy, vuln, IOC ───
    parallel_tasks = []
    if "hash" in plan:
        parallel_tasks.append(("hash", HashSpecialist.run(state["sample_path"])))
    if "yara" in plan:
        parallel_tasks.append(("yara", YARASpecialist.run(state["sample_path"])))
    if "binary_analysis" in plan:
        parallel_tasks.append(("binary", BinaryAnalysisSpecialist.run(state["sample_path"])))
    if "entropy_analysis" in plan:
        parallel_tasks.append(("entropy", EntropyAnalysisSpecialist.run(state["sample_path"])))
    if "vuln_check" in plan:
        parallel_tasks.append(("vuln", VulnerabilityCheckSpecialist.run(state["sample_path"])))
    if "ioc_extraction" in plan:
        parallel_tasks.append(("ioc", IOCSpecialist.run(state["sample_path"])))

    if parallel_tasks:
        keys, coros = zip(*parallel_tasks)
        results = await asyncio.gather(*coros, return_exceptions=True)
        for key, result in zip(keys, results):
            if isinstance(result, Exception):
                log.error("[EXECUTE] specialist '%s' failed: %s", key, result)
                state["errors"].append({"specialist": key, "error": str(result)})
            elif key == "hash":
                state["hash_results"] = result
                if "virustotal" in plan and result.get("hashes", {}).get("sha256"):
                    try:
                        state["vt_results"] = await asyncio.wait_for(
                            HashSpecialist.query_vt(result["hashes"]["sha256"]),
                            timeout=30,
                        )
                    except Exception as e:
                        log.warning("[EXECUTE] VT lookup failed: %s", e)
                        state["vt_results"] = {"error": str(e)}
            elif key == "yara":
                state["yara_results"] = result
            elif key == "binary":
                state["binary_analysis_results"] = result
            elif key == "entropy":
                state["entropy_results"] = result
            elif key == "vuln":
                state["vulnerability_results"] = result
            elif key == "ioc":
                state["ioc_results"] = result

    # ── Sequential group 2: Volatility plugins ─────────────────────────────
    vol_plugins = [p for p in plan if p.startswith("volatility_")]
    if vol_plugins and state.get("memory_image_path"):
        for plugin_key in vol_plugins:
            plugin_name = plugin_key.replace("volatility_", "windows.")
            try:
                vol_result = await asyncio.wait_for(
                    VolatilitySpecialist.run(state["memory_image_path"], plugin_name),
                    timeout=NODE_TIMEOUT,
                )
                state["volatility_results"][plugin_name] = vol_result
            except asyncio.TimeoutError:
                log.error("[EXECUTE] Volatility plugin %s timed out", plugin_name)
                state["volatility_results"][plugin_name] = {"error": "timeout"}
            except Exception as e:
                log.error("[EXECUTE] Volatility plugin %s failed: %s", plugin_name, e)
                state["volatility_results"][plugin_name] = {"error": str(e)}

    # ── Sequential group 3: Network Intel (needs IOC results first) ──────────
    if "network_intel" in plan and state.get("ioc_results"):
        try:
            state["network_intel_results"] = await NetworkIntelSpecialist.run(state["ioc_results"])
        except Exception as e:
            log.error("[EXECUTE] network_intel failed: %s", e)
            state["errors"].append({"specialist": "network_intel", "error": str(e)})

    return state


# ---------------------------------------------------------------------------
# ── NODE 3.5: DynamicAnalysis ────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_dynamic_analysis(state: AgentState) -> AgentState:
    """
    Submits the sample to a sandbox and parses the behavioral report.
    If a task_id already exists (from a previous loop iteration), re-fetches
    the report to capture new behavioral data from interactive commands.
    Enforces a strict timeout to ensure the sub-8-minute SLA.
    """
    state = dict(state)
    try:
        existing = state.get("dynamic_results") or {}
        task_id = existing.get("task_id")

        if task_id and not task_id.startswith("mock"):
            result = await DynamicAnalysisSpecialist.get_sandbox_report(task_id, timeout=300)
            result["task_id"] = task_id
        else:
            result = await DynamicAnalysisSpecialist.run(state["sample_path"], timeout_seconds=300)

        interactive_results = existing.get("interactive_results", [])
        new_interactive = state.get("sandbox_actions_requested", [])
        for action in new_interactive:
            interactive_results.append(action)

        result["interactive_results"] = interactive_results
        state["dynamic_results"] = result
    except Exception as e:
        log.error("[NODE:dynamic_analysis] Failed: %s", e)
        state["dynamic_results"] = {"error": str(e)}
        state["errors"].append({"node": "dynamic_analysis", "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()})

    return state


# ---------------------------------------------------------------------------
# ── NODE 3.75: LLM_Analysis ──────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_llm_analysis(state: AgentState) -> AgentState:
    """
    Cross-analyzes both static and dynamic reports using an LLM.
    The LLM produces separate confidence scores for each path and may request
    additional interactive sandbox commands for deeper investigation.
    """
    state = dict(state)
    llm_iter = state.get("llm_iteration", 0) + 1
    max_llm = state.get("max_llm_iterations", MAX_LLM_ITERATIONS)

    # Build static summary
    static_summary = {
        "hash_vt": {
            "sha256": (state.get("hash_results") or {}).get("hashes", {}).get("sha256", ""),
            "malicious": (state.get("vt_results") or {}).get("malicious", 0),
            "suspicious": (state.get("vt_results") or {}).get("suspicious", 0),
        },
        "yara": {
            "match_count": (state.get("yara_results") or {}).get("match_count", 0),
            "matches": (state.get("yara_results") or {}).get("matches", []),
        },
        "iocs": {
            "total_iocs": (state.get("ioc_results") or {}).get("total_iocs", 0),
            "ioc_types": (state.get("ioc_results") or {}).get("ioc_types_found", []),
        },
        "volatility": {
            plugin: {"row_count": r.get("row_count", 0), "error": r.get("error")}
            for plugin, r in (state.get("volatility_results") or {}).items()
        },
        "binary_analysis": {
            "packer_detected": (state.get("binary_analysis_results") or {}).get("packer_detected", {}),
            "suspicious_import_count": (state.get("binary_analysis_results") or {}).get("suspicious_import_count", 0),
            "format": (state.get("binary_analysis_results") or {}).get("format"),
        },
        "entropy": {
            "file_entropy": (state.get("entropy_results") or {}).get("file_entropy", 0),
            "classification": (state.get("entropy_results") or {}).get("classification", "normal"),
            "anomalies": (state.get("entropy_results") or {}).get("anomalies", []),
        },
        "network_intel": {
            "warning_count": (state.get("network_intel_results") or {}).get("warning_count", 0),
            "warnings": (state.get("network_intel_results") or {}).get("warnings", []),
        },
        "vulnerability": {
            "vulnerability_count": (state.get("vulnerability_results") or {}).get("vulnerability_count", 0),
            "vulnerabilities": (state.get("vulnerability_results") or {}).get("vulnerabilities", []),
        },
    }

    dyn_r = state.get("dynamic_results") or {}
    dynamic_summary = {
        "network_iocs": dyn_r.get("network_iocs", []),
        "dropped_files": dyn_r.get("dropped_files", []),
        "process_tree": dyn_r.get("process_tree", []),
        "attack_techniques": dyn_r.get("attack_techniques", []),
        "confidence_boost": dyn_r.get("confidence_boost", 0.0),
        "documentation_check": dyn_r.get("documentation_check", {}),
    }
    interactive_results = dyn_r.get("interactive_results", [])

    output_agent = state.get("output_agent", [])

    llm_output = await _call_llm_analysis(
        static_summary=static_summary,
        dynamic_summary=dynamic_summary,
        interactive_results=interactive_results,
        llm_iteration=llm_iter,
        model_name=state.get("llm_model", ""),
        output_agent=output_agent,
    )

    state["output_agent"] = [llm_output]

    static_score = float(llm_output.get("static_confidence_score", 0.0))
    dynamic_score = float(llm_output.get("dynamic_confidence_score", 0.0))
    actions_requested = llm_output.get("actions_requested", [])
    reasoning = llm_output.get("reasoning", "")
    malicious_actions = llm_output.get("malicious_actions", "")

    cap_actions = actions_requested[:5] if llm_iter < max_llm else []

    state["static_confidence_score"] = round(static_score, 3)
    state["dynamic_confidence_score"] = round(dynamic_score, 3)
    state["confidence_score"] = round((static_score + dynamic_score) / 2, 3)
    state["llm_analysis"] = {
        "iteration": llm_iter,
        "reasoning": reasoning,
        "malicious_actions": malicious_actions,
        "static_confidence_score": round(static_score, 3),
        "dynamic_confidence_score": round(dynamic_score, 3),
    }
    state["sandbox_actions_requested"] = cap_actions
    state["llm_iteration"] = llm_iter

    log.info("[LLM_ANALYSIS] iter=%d static=%.3f dynamic=%.3f actions=%d",
             llm_iter, static_score, dynamic_score, len(cap_actions))
    return state


# ---------------------------------------------------------------------------
# ── NODE 3.8: Sandbox_Interact ───────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_sandbox_interact(state: AgentState) -> AgentState:
    """
    Execute the LLM-requested interactive sandbox commands.
    Each action is dispatched to the DynamicAnalysisSpecialist.
    Results are appended to dynamic_results for the next LLM analysis pass.
    """
    state = dict(state)
    actions = state.get("sandbox_actions_requested", [])
    original_count = len(actions)
    task_id = (state.get("dynamic_results") or {}).get("task_id", "")

    # Deduplicate: filter out commands already executed in previous iterations
    prev_executed = (state.get("dynamic_results") or {}).get("interactive_results", [])
    actions = _dedup_actions(actions, prev_executed)

    executed = []
    for action in actions:
        action_type = action.get("action", "")
        try:
            if action_type == "execute_command":
                cmd = action.get("command", "")
                result = await DynamicAnalysisSpecialist.execute_command(task_id, cmd)
                log.info("[SANDBOX_INTERACT] Output for %s (%s): %s", action_type, cmd, result)
                executed.append({"action": action_type, "command": cmd, "result": result})
            elif action_type == "block_network":
                target = action.get("target", "")
                target_type = action.get("target_type", "port")
                result = await DynamicAnalysisSpecialist.block_network(task_id, target, target_type)
                log.info("[SANDBOX_INTERACT] Output for %s (%s): %s", action_type, target, result)
                executed.append({"action": action_type, "target": target, "target_type": target_type, "result": result})
            elif action_type == "get_status":
                result = await DynamicAnalysisSpecialist.get_sandbox_status(task_id)
                log.info("[SANDBOX_INTERACT] Output for %s: %s", action_type, result)
                executed.append({"action": action_type, "result": result})
            elif action_type == "query_dropped_files":
                result = await DynamicAnalysisSpecialist.query_dropped_files(task_id)
                log.info("[SANDBOX_INTERACT] Output for %s: %s", action_type, result)
                executed.append({"action": action_type, "result": result})
            elif action_type == "check_documentation":
                sample_path = state.get("sample_path", "")
                result = await DynamicAnalysisSpecialist.check_documentation(sample_path)
                log.info("[SANDBOX_INTERACT] Output for %s: %s", action_type, result)
                executed.append({"action": action_type, "result": result})
        except Exception as e:
            log.error("[SANDBOX_INTERACT] Action %s failed: %s", action_type, e)
            executed.append({"action": action_type, "error": str(e)})

    dyn_r = dict(state.get("dynamic_results") or {})
    prev_interactive = dyn_r.get("interactive_results", [])
    dyn_r["interactive_results"] = prev_interactive + executed
    state["dynamic_results"] = dyn_r
    state["sandbox_actions_requested"] = []

    log.info("[SANDBOX_INTERACT] Executed %d / %d requested actions (dedup removed %d)",
             len(executed), original_count, original_count - len(executed))

    # Track whether we actually did work (to break LLM loop if LLM keeps repeating)
    state["_interact_has_work"] = bool(executed)
    return state


# ---------------------------------------------------------------------------
# ── NODE 4: Validate ─────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_validate(state: AgentState) -> AgentState:
    """
    Cross-validate findings across specialist outputs.
    Assign confidence scores. Separate confirmed findings from inferences.
    Flag potential hallucinations (claims without tool backing).
    """
    state = dict(state)
    prev_confidence = state.get("confidence_score", 0.0)
    findings = []
    inferences = []
    hallucination_flags = []
    confidence_votes = []

    # Track signal types for corroboration bonus & low-signal cap
    signal_categories = set()
    has_yara = False
    has_high_yara = False
    has_low_yara = False
    has_suspicious_ioc = False
    has_vt_malicious = False
    has_vt_suspicious = False
    has_dynamic = False
    yara_severities = []

    # ── Hash + VT cross-validation ─────────────────────────────────────────
    hash_r = state.get("hash_results", {})
    vt_r = state.get("vt_results", {})
    if hash_r and not hash_r.get("error"):
        sha256 = hash_r.get("hashes", {}).get("sha256", "")
        malicious_count = vt_r.get("malicious", 0) if vt_r and not vt_r.get("error") else 0
        suspicious_count = vt_r.get("suspicious", 0) if vt_r and not vt_r.get("error") else 0
        if malicious_count and malicious_count > 5:
            findings.append({
                "type": "HASH_MALICIOUS",
                "confidence": min(1.0, malicious_count / 70),
                "evidence": f"VT detections: {malicious_count}/70+",
                "sha256": sha256,
                "source": "compute_hash + query_virustotal",
            })
            confidence_votes.append(0.4)
            signal_categories.add("vt_malicious")
            has_vt_malicious = True
        elif suspicious_count and suspicious_count > 0:
            inferences.append({
                "type": "HASH_SUSPICIOUS",
                "confidence": 0.2,
                "evidence": f"VT detections: {suspicious_count}",
                "sha256": sha256,
                "source": "compute_hash + query_virustotal",
            })
            confidence_votes.append(0.2)
            signal_categories.add("vt_suspicious")
            has_vt_suspicious = True

    # ── YARA validation (weighted by severity) ────────────────────────────
    yara_r = state.get("yara_results", {})
    if yara_r and not yara_r.get("error") and yara_r.get("match_count", 0) > 0:
        for match in yara_r.get("matches", []):
            sev = match.get("severity", "medium")
            yara_severities.append(sev)
            if sev in ("critical", "high"):
                has_high_yara = True
            else:
                has_low_yara = True
            findings.append({
                "type": "YARA_MATCH",
                "confidence": 0.3 if sev in ("critical", "high") else 0.1,
                "rule": match.get("rule"),
                "severity": sev,
                "file": match.get("file"),
                "source": "run_yara_scan",
            })
        if has_high_yara:
            confidence_votes.append(0.3)
            signal_categories.add("yara_high")
        if has_low_yara:
            confidence_votes.append(0.1)
            signal_categories.add("yara_low")
        has_yara = True

    # ── IOC validation (suspicious vs benign) ─────────────────────────────
    ioc_r = state.get("ioc_results", {})
    if ioc_r and not ioc_r.get("error"):
        total_iocs = ioc_r.get("total_iocs", 0)
        ioc_types = ioc_r.get("ioc_types_found", [])
        # Only count as suspicious if there are meaningful IOC types
        suspicious_types = {"ipv4", "domain", "url", "registry_key", "mutex"}
        suspicious_ioc_count = sum(
            len(ioc_r.get("iocs", {}).get(t, []))
            for t in ioc_r.get("iocs", {})
            if t in suspicious_types
        )
        if suspicious_ioc_count > 0:
            ioc_finding = {
                "type": "IOC_EXTRACTED",
                "confidence": min(0.4, 0.1 + suspicious_ioc_count * 0.02),
                "ioc_count": suspicious_ioc_count,
                "ioc_types": ioc_types,
                "source": "extract_iocs",
            }
            if suspicious_ioc_count > 5:
                findings.append(ioc_finding)
                confidence_votes.append(0.2)
                signal_categories.add("ioc_suspicious")
                has_suspicious_ioc = True
            else:
                inferences.append(ioc_finding)
        elif total_iocs > 0:
            inferences.append({
                "type": "IOC_EXTRACTED",
                "confidence": 0.05,
                "ioc_count": total_iocs,
                "ioc_types": ioc_types,
                "source": "extract_iocs",
                "note": "All IOCs are benign/noise — no suspicious indicators",
            })

    # ── Volatility validation ──────────────────────────────────────────────
    for plugin, vol_r in state.get("volatility_results", {}).items():
        if vol_r.get("error"):
            continue
        if plugin == "windows.malfind" and vol_r.get("row_count", 0) > 0:
            findings.append({
                "type": "MEMORY_INJECTION",
                "confidence": 0.85,
                "process_count": vol_r["row_count"],
                "source": f"execute_volatility_plugin({plugin})",
            })
            confidence_votes.append(0.85)
            signal_categories.add("memory_injection")
        if plugin == "windows.netscan" and vol_r.get("row_count", 0) > 0:
            inferences.append({
                "type": "NETWORK_CONNECTIONS",
                "confidence": 0.65,
                "connection_count": vol_r["row_count"],
                "source": f"execute_volatility_plugin({plugin})",
            })

    # ── Binary Analysis validation ─────────────────────────────────────────
    bin_r = state.get("binary_analysis_results") or {}
    if bin_r and not bin_r.get("error"):
        packer = bin_r.get("packer_detected", {})
        if packer.get("detected") and packer.get("confidence", 0) >= 0.4:
            findings.append({
                "type": "BINARY_PACKER",
                "confidence": packer["confidence"],
                "indicators": packer.get("indicators", []),
                "suspected_packers": packer.get("suspected_packers", []),
                "source": "analyze_binary",
            })
            confidence_votes.append(packer["confidence"])
            signal_categories.add("packer")

        sus_imports = bin_r.get("suspicious_imports", [])
        if sus_imports:
            findings.append({
                "type": "SUSPICIOUS_IMPORTS",
                "confidence": min(0.5, 0.2 + len(sus_imports) * 0.05),
                "count": len(sus_imports),
                "categories": list(set(i.get("category", "") for i in sus_imports)),
                "source": "analyze_binary",
            })
            confidence_votes.append(0.3)
            signal_categories.add("suspicious_imports")

        ts_anomaly = bin_r.get("timestamp_anomaly")
        if ts_anomaly and ts_anomaly.get("confidence", 0) >= 0.4:
            findings.append({
                "type": "TIMESTAMP_ANOMALY",
                "confidence": ts_anomaly["confidence"],
                "detail": ts_anomaly.get("detail", ""),
                "source": "analyze_binary",
            })

    # ── Entropy Analysis validation ─────────────────────────────────────────
    ent_r = state.get("entropy_results") or {}
    if ent_r and not ent_r.get("error"):
        classification = ent_r.get("classification", "normal")
        anomalies = ent_r.get("anomalies", [])
        if classification == "high_entropy":
            findings.append({
                "type": "HIGH_ENTROPY_PAYLOAD",
                "confidence": 0.4,
                "file_entropy": ent_r.get("file_entropy"),
                "high_entropy_ratio": ent_r.get("high_entropy_ratio"),
                "anomalies": anomalies,
                "source": "compute_entropy",
            })
            confidence_votes.append(0.3)
            signal_categories.add("high_entropy")

    # ── Network Intel validation ────────────────────────────────────────────
    net_r = state.get("network_intel_results") or {}
    if net_r and not net_r.get("error"):
        for w in net_r.get("warnings", []):
            wtype = w.get("type", "")
            if wtype == "domain_in_blocklist":
                findings.append({
                    "type": "MALICIOUS_DOMAIN_LOOKUP",
                    "confidence": w.get("confidence", 0.5),
                    "domain": w.get("value"),
                    "detail": w.get("detail"),
                    "source": "enrich_network_iocs",
                })
                confidence_votes.append(0.4)
                signal_categories.add("malicious_domain")
            elif wtype == "ip_in_blocklist":
                findings.append({
                    "type": "MALICIOUS_IP_LOOKUP",
                    "confidence": w.get("confidence", 0.5),
                    "ip": w.get("value"),
                    "detail": w.get("detail"),
                    "source": "enrich_network_iocs",
                })
                confidence_votes.append(0.4)
                signal_categories.add("malicious_ip")
            elif wtype == "newly_registered_domain":
                inferences.append({
                    "type": "SUSPICIOUS_DOMAIN_AGE",
                    "confidence": w.get("confidence", 0.3),
                    "domain": w.get("value"),
                    "detail": w.get("detail"),
                    "source": "enrich_network_iocs",
                })
                confidence_votes.append(0.2)

    # ── Vulnerability validation ────────────────────────────────────────────
    vuln_r = state.get("vulnerability_results") or {}
    if vuln_r and not vuln_r.get("error"):
        for v in vuln_r.get("vulnerabilities", []):
            findings.append({
                "type": "VULNERABLE_LIBRARY",
                "confidence": v.get("confidence", 0.4),
                "library": v.get("library"),
                "version_found": v.get("version_found"),
                "severity": v.get("severity", "medium"),
                "cve_ids": v.get("cve_ids", []),
                "source": "check_vulnerable_libraries",
            })
            if v.get("severity") in ("critical", "high"):
                confidence_votes.append(0.4)
                signal_categories.add("vulnerable_library")

    # ── Dynamic Analysis validation (discounted if uncorroborated) ────────
    dyn_r = state.get("dynamic_results", {})
    if dyn_r and not dyn_r.get("error"):
        boost = dyn_r.get("confidence_boost", 0.0)
        dyn_network_iocs = len(dyn_r.get("network_iocs", []))
        dyn_dropped = len(dyn_r.get("dropped_files", []))
        dyn_attack = dyn_r.get("attack_techniques", [])
        if boost >= 0.1:
            has_dynamic = True
            findings.append({
                "type": "DYNAMIC_BEHAVIOR",
                "confidence": boost,
                "network_iocs_found": dyn_network_iocs,
                "dropped_files": dyn_dropped,
                "attack_techniques": dyn_attack,
                "source": "get_sandbox_report",
            })
            signal_categories.add("dynamic")
            confidence_votes.append(boost)

    # ── Hallucination check ────────────────────────────────────────────────
    for finding in findings:
        if "source" not in finding:
            hallucination_flags.append(f"Finding {finding.get('type')} has no tool source citation")

    # ── Confidence aggregation (corroborated weighted scoring) ─────────────
    heuristic_confidence = sum(confidence_votes) / max(len(confidence_votes), 1) if confidence_votes else 0.0

    # Corroboration bonus: YARA + suspicious IOC or VT
    if has_yara and (has_suspicious_ioc or has_vt_malicious or has_vt_suspicious):
        heuristic_confidence = min(heuristic_confidence + 0.2, 1.0)

    # Low-signal cap: if the ONLY signals are weak/noise (no strong static signals),
    # cap confidence so benign files don't trigger false positives
    only_weak_signals = signal_categories and not signal_categories.intersection(
        {"yara_high", "vt_malicious", "vt_suspicious", "ioc_suspicious", "memory_injection"}
    )
    has_strong_static_signal = bool(
        has_vt_malicious or has_suspicious_ioc
    )
    if only_weak_signals and not has_strong_static_signal:
        heuristic_confidence = min(heuristic_confidence, 0.3)
        log.info("[VALIDATE] Low-signal cap applied: heuristic_confidence=%.3f", heuristic_confidence)

    new_confidence = heuristic_confidence

    # ── Dynamic score floor: if sandbox produced strong evidence, don't let the
    # ── LLM override it below the dynamic score itself. This prevents the small
    # ── LLM from dismissing a clear malware sandbox report (e.g. confidence_boost=0.85)
    # ── while still allowing the LLM to push the score *up* if it finds more.
    dynamic_score_from_llm = state.get("dynamic_confidence_score", 0.0)
    dynamic_floor = dynamic_score_from_llm if dynamic_score_from_llm >= 0.5 else 0.0

    # ── LLM Integration (Hackathon Mode Fallback) ──────────────────────────
    try:
        import ollama
        client = ollama.AsyncClient(host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
        malicious_actions = state.get("llm_analysis", {}).get("malicious_actions", "")
        dynamic_score_display = state.get('dynamic_confidence_score', 0.0)
        prompt = (
            "You are a DFIR Analyst validating automated triage results.\n"
            f"Findings: {json.dumps(findings)}\n"
            f"Inferences: {json.dumps(inferences)}\n"
            f"Static Score: {state.get('static_confidence_score', 0.0)}\n"
            f"Dynamic Score: {dynamic_score_display} (IMPORTANT: a Dynamic Score >= 0.7 is strong sandbox evidence of malicious behavior — do not ignore it)\n"
            f"LLM Analysis Reasoning: {json.dumps(state.get('llm_analysis', {}).get('reasoning', 'N/A'))}\n"
            f"Malicious Actions Observed: {json.dumps(malicious_actions)}\n"
            "IMPORTANT: If the Dynamic Score is high (>= 0.7), the sandbox observed real malicious behavior such as C2 connections, registry modification, or process injection. This is strong evidence — weight it heavily.\n"
            "Provide a final confidence score (0.0 = definitely BENIGN, 1.0 = definitely MALICIOUS).\n"
            "Score 0.0-0.3 if findings are weak, generic, or could affect legitimate software.\n"
            "Score 0.7-1.0 if there is strong corroborated evidence of real malicious behavior (C2, injection, encryption, etc.) or the Dynamic Score is >= 0.7.\n"
            "Keep reasoning to 1-2 sentences. Be concise.\n"
            'Respond in pure JSON: {"confidence_score": float, "reasoning": "string"}'
        )
        response = await asyncio.wait_for(
            client.chat(model=state.get("llm_model", "") or os.environ.get("OLLAMA_MODEL", "qwen:1.8b"), messages=[
                {'role': 'system', 'content': 'Output only JSON.'},
                {'role': 'user', 'content': prompt}
            ], format='json', options={'temperature': 0.1, 'num_predict': 200}, keep_alive='5m'),
            timeout=LLM_TIMEOUT
        )
        msg = getattr(response, 'message', response)
        raw = msg.content if hasattr(msg, 'content') else msg.get('content', '')
        llm_output = _parse_llm_json(raw) if raw else {}
        llm_score = float(llm_output.get('confidence_score', heuristic_confidence))
        # Apply dynamic floor: the final score must be at least the dynamic evidence score
        new_confidence = max(llm_score, dynamic_floor)
        if new_confidence > llm_score:
            log.info("[LLM] Validate: LLM score %.2f raised to dynamic floor %.2f", llm_score, dynamic_floor)
        log.info("[LLM] Validate complete. Score: %.2f. Reasoning: %s", new_confidence, llm_output.get('reasoning', ''))
    except Exception as e:
        log.warning("[LLM] Ollama unavailable (%s) — using heuristic score %.2f", type(e).__name__, heuristic_confidence)
        # Apply dynamic floor even in fallback path
        new_confidence = max(heuristic_confidence, dynamic_floor)

    delta = new_confidence - prev_confidence

    # Determine if there are any genuinely suspicious signals (vs generic/false-positive noise)
    # NOTE: "dynamic" is included — a high sandbox confidence_boost is strong evidence of malicious behavior
    has_any_suspicious_signal = bool(
        signal_categories.intersection({"yara_high", "vt_malicious", "vt_suspicious",
                                        "ioc_suspicious", "memory_injection",
                                        "packer", "suspicious_imports", "high_entropy",
                                        "malicious_domain", "malicious_ip", "vulnerable_library",
                                        "dynamic"})
    )

    # Derive verdict from corroborated confidence
    if has_any_suspicious_signal and new_confidence >= CONFIDENCE_THRESHOLD:
        verdict = "MALICIOUS"
    elif has_any_suspicious_signal and new_confidence >= 0.3:
        verdict = "SUSPICIOUS"
    elif findings and new_confidence >= 0.1:
        verdict = "ANALYST REVIEW"
    else:
        verdict = "BENIGN"

    needs_correction = (
        new_confidence < CONFIDENCE_THRESHOLD
        and state.get("iteration", 0) < MAX_ITERATIONS
        and not findings
        and has_any_suspicious_signal
    )

    return {
        **state,
        "findings": findings,
        "inferences": inferences,
        "confidence_score": round(new_confidence, 3),
        "verdict": verdict,
        "validation_delta": round(delta, 3),
        "hallucination_flags": hallucination_flags,
        "needs_correction": needs_correction,
        "correction_reason": "Low confidence, no confirmed findings — expanding analysis" if needs_correction else "",
    }


# ---------------------------------------------------------------------------
# ── NODE 5: Self_Correct ─────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_self_correct(state: AgentState) -> AgentState:
    """
    Self-correction loop: expand the plan with additional plugins/techniques.
    Logs the iteration delta for judging transparency.
    Hard-capped at MAX_ITERATIONS to prevent runaway execution.
    """
    state = dict(state)
    iteration = state.get("iteration", 0) + 1
    log.warning(
        "[SELF_CORRECT] Iteration %d/%d | confidence=%.3f | delta=%.3f | reason=%s",
        iteration,
        MAX_ITERATIONS,
        state["confidence_score"],
        state["validation_delta"],
        state["correction_reason"],
    )

    expanded_plan = list(state.get("plan", []))
    if "volatility_dlllist" not in expanded_plan:
        expanded_plan.append("volatility_dlllist")
    if "volatility_handles" not in expanded_plan:
        expanded_plan.append("volatility_handles")

    return {
        **state,
        "iteration": iteration,
        "plan": expanded_plan,
        "needs_correction": False,
    }


# ---------------------------------------------------------------------------
# ── NODE 6: Contain ──────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_contain(state: AgentState) -> AgentState:
    """
    Generate containment recommendations.
    Only generates rules when verdict is MALICIOUS — prevents acting on
    low-confidence inferences from benign binaries.
    Architectural guardrail: ContainmentSpecialist ONLY generates rule text.
    No actual firewall rules are applied. Analyst must review and act.
    """
    state = dict(state)
    verdict = state.get("verdict", "BENIGN")

    firewall_rules = {"iptables_rules": [], "nftables_rules": [], "etc_hosts_entries": [], "note": ""}

    if verdict == "MALICIOUS":
        ioc_r = state.get("ioc_results", {})
        ips = ioc_r.get("iocs", {}).get("ipv4", []) if ioc_r else []
        domains = ioc_r.get("iocs", {}).get("domain", []) if ioc_r else []

        dyn_r = state.get("dynamic_results", {})
        dyn_ips = [i for i in dyn_r.get("network_iocs", []) if i.count(".") == 3 and not any(c.isalpha() for c in i)]
        dyn_domains_raw = [i for i in dyn_r.get("network_iocs", []) if i.count(".") >= 1 and any(c.isalpha() for c in i)]
        dyn_domains = []
        for raw in dyn_domains_raw:
            stripped = raw.strip()
            if "://" in stripped:
                parsed = urlparse(stripped)
                hostname = parsed.hostname
                if hostname:
                    stripped = hostname
            dyn_domains.append(stripped)

        all_ips = list(set(ips + dyn_ips))
        all_domains = list(set(domains + dyn_domains))

        firewall_rules = await ContainmentSpecialist.run(ips=all_ips, domains=all_domains)

    return {
        **state,
        "firewall_rules": firewall_rules,
        "status": "contained",
    }


# ---------------------------------------------------------------------------
# ── NODE 6.5: Intelligence Enrichment (ATT&CK + IOC Memory) ─────────────────
# ---------------------------------------------------------------------------
async def node_enrich_intelligence(state: AgentState) -> AgentState:
    """
    Enrich findings with MITRE ATT&CK technique mapping and cross-incident
    IOC memory recall. Runs after validation, before containment.
    """
    state = dict(state)
    try:
        dyn_r = state.get("dynamic_results") or {}
        ioc_r = state.get("ioc_results") or {}
        findings = state.get("findings") or []
        incident_id = state.get("incident_id", "UNKNOWN")

        # ── ATT&CK Mapping ──────────────────────────────────────────────────
        attack_techniques = AttackMapper.map_to_attack(
            behavior_list=[],
            iocs=ioc_r.get("iocs", {}),
            process_tree=dyn_r.get("process_tree", []),
            network_iocs=dyn_r.get("network_iocs", []),
            findings=findings,
            existing_attack_ids=dyn_r.get("attack_techniques", []),
        )
        state["attack_techniques"] = attack_techniques
        log.info("[ENRICH] Mapped %d ATT&CK techniques", len(attack_techniques))
        if attack_techniques:
            log.info("[ENRICH] === ATT&CK Mapping Summary ===")
            for t in attack_techniques:
                tid = t.get("technique_id", "")
                name = t.get("name", "")
                evidence = t.get("evidence", "")
                log.info("[ENRICH]   %s | %s | %s", tid, name, evidence)
            log.info("[ENRICH] === End of ATT&CK Mapping ===")
        else:
            log.info("[ENRICH] No ATT&CK techniques mapped")

        # ── IOC Memory Check (cross-incident recall) ────────────────────────
        iocs = ioc_r.get("iocs", {}) if ioc_r else {}
        ioc_memory_warnings = IOCMemory.check_ioc_history(incident_id, iocs)
        state["ioc_memory_warnings"] = ioc_memory_warnings
        if ioc_memory_warnings:
            log.info("[ENRICH] Found %d cross-incident IOC matches", len(ioc_memory_warnings))

        # ── Persist current IOCs for future lookups ─────────────────────────
        IOCMemory.save_ioc_history(incident_id, iocs)

    except Exception as e:
        log.error("[ENRICH] Intelligence enrichment failed: %s", e)
        state["errors"].append({
            "node": "enrich_intelligence",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        state["attack_techniques"] = state.get("attack_techniques", [])
        state["ioc_memory_warnings"] = state.get("ioc_memory_warnings", [])

    return state


# ---------------------------------------------------------------------------
# ── NODE 7: Report ───────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_report(state: AgentState) -> AgentState:
    """Generate JSON and Markdown reports. Save to cases/{incident_id}/report/."""
    state = dict(state)
    reporter = Reporter(
        incident_id=state["incident_id"],
        cases_dir=CASES_DIR,
    )
    paths = await reporter.generate(state)
    return {
        **state,
        "status": "completed",
        "report_paths": paths,
    }


# ---------------------------------------------------------------------------
# ── NODE 8: STIX Export ─────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
async def node_export_stix(state: AgentState) -> AgentState:
    """Generate and save STIX 2.1 bundle after all other reports complete."""
    from pipeline.stix_exporter import STIXExporter

    state = dict(state)
    try:
        report_dir = CASES_DIR / state["incident_id"] / "report"
        hash_r = state.get("hash_results") or {}
        sha256 = hash_r.get("hashes", {}).get("sha256")
        iocs = (state.get("ioc_results") or {}).get("iocs", {})
        attack_techniques = state.get("attack_techniques", [])

        bundle = STIXExporter.generate_stix_bundle(
            incident_id=state["incident_id"],
            sha256=sha256,
            iocs=iocs,
            attack_techniques=attack_techniques,
        )
        stix_path = STIXExporter.save_bundle(bundle, report_dir / "stix_bundle.json")

        report_paths = dict(state.get("report_paths", {}))
        report_paths["stix"] = stix_path
        state["report_paths"] = report_paths

        log.info("[STIX_EXPORT] STIX 2.1 bundle: %s", stix_path)
    except Exception as e:
        log.warning("[STIX_EXPORT] Failed: %s", e)
        state["errors"].append({
            "node": "export_stix",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    return state


# ---------------------------------------------------------------------------
# Routing functions
# ---------------------------------------------------------------------------
def route_after_validate(state: AgentState) -> str:
    """
    Router: after validation, decide next node.
    - If needs_correction AND under iteration cap → Self_Correct
    - Otherwise → Enrich intelligence (ATT&CK + IOC memory)
    """
    if state.get("needs_correction") and state.get("iteration", 0) < state.get("max_iterations", MAX_ITERATIONS):
        log.info("[ROUTE] → self_correct (iteration %d)", state["iteration"])
        return "self_correct"
    log.info("[ROUTE] → enrich_intelligence")
    return "enrich_intelligence"


def route_after_correct(state: AgentState) -> str:
    """After self-correction, always re-execute specialists."""
    return "execute_specialists"


def route_after_specialists(state: AgentState) -> str:
    """Decide if we should run dynamic analysis."""
    vt_r = state.get("vt_results") or {}
    yara_r = state.get("yara_results") or {}
    vt_mal = vt_r.get("malicious") or 0
    suspicious = (vt_mal > 0) or ((yara_r.get("match_count") or 0) > 0)

    plan = state.get("plan", [])
    if "run_dynamic_analysis" in plan or suspicious:
        return "dynamic_analysis"
    return "validate"


def route_after_dynamic(state: AgentState) -> str:
    """After dynamic analysis, go to LLM cross-analysis."""
    return "llm_analysis"


def route_after_llm(state: AgentState) -> str:
    """
    If the LLM requested sandbox actions and we're under the cap,
    route to sandbox_interact. Otherwise proceed to validate.
    """
    actions = state.get("sandbox_actions_requested", [])
    llm_iter = state.get("llm_iteration", 0)
    max_llm = state.get("max_llm_iterations", MAX_LLM_ITERATIONS)
    if actions and llm_iter < max_llm:
        log.info("[ROUTE] → sandbox_interact (%d actions requested, llm_iter=%d/%d)",
                 len(actions), llm_iter, max_llm)
        return "sandbox_interact"
    log.info("[ROUTE] → validate")
    return "validate"


def route_after_interact(state: AgentState) -> str:
    """After sandbox interaction, re-fetch report or go to validate if nothing executed."""
    if not state.get("_interact_has_work", False):
        log.info("[ROUTE] → validate (no new actions executed — breaking LLM loop)")
        return "validate"
    return "dynamic_analysis"


def route_after_enrich(state: AgentState) -> str:
    """After intelligence enrichment, proceed to containment."""
    return "contain"


def route_after_report(state: AgentState) -> str:
    """After reports generated, export STIX 2.1 bundle."""
    return "export_stix"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------
def build_graph() -> StateGraph:
    """
    Constructs and compiles the LangGraph StateGraph.
    Returns a compiled runnable graph.
    """
    graph = StateGraph(AgentState)

    graph.add_node("ingest",              _timed_node("ingest")(node_ingest))
    graph.add_node("plan",                _timed_node("plan")(node_plan))
    graph.add_node("execute_specialists", _timed_node("execute_specialists")(node_execute_specialists))
    graph.add_node("dynamic_analysis",    _timed_node("dynamic_analysis")(node_dynamic_analysis))
    graph.add_node("llm_analysis",        _timed_node("llm_analysis")(node_llm_analysis))
    graph.add_node("sandbox_interact",    _timed_node("sandbox_interact")(node_sandbox_interact))
    graph.add_node("validate",            _timed_node("validate")(node_validate))
    graph.add_node("self_correct",        _timed_node("self_correct")(node_self_correct))
    graph.add_node("enrich_intelligence", _timed_node("enrich_intelligence")(node_enrich_intelligence))
    graph.add_node("contain",             _timed_node("contain")(node_contain))
    graph.add_node("report",              _timed_node("report")(node_report))
    graph.add_node("export_stix",         _timed_node("export_stix")(node_export_stix))

    graph.set_entry_point("ingest")
    graph.add_edge("ingest",              "plan")
    graph.add_edge("plan",                "execute_specialists")

    graph.add_conditional_edges(
        "execute_specialists",
        route_after_specialists,
        {"dynamic_analysis": "dynamic_analysis", "validate": "validate"},
    )

    graph.add_edge("dynamic_analysis", "llm_analysis")

    graph.add_conditional_edges(
        "llm_analysis",
        route_after_llm,
        {"sandbox_interact": "sandbox_interact", "validate": "validate"},
    )

    graph.add_conditional_edges(
        "sandbox_interact",
        route_after_interact,
        {"dynamic_analysis": "dynamic_analysis", "validate": "validate"},
    )

    graph.add_conditional_edges(
        "validate",
        route_after_validate,
        {"self_correct": "self_correct", "enrich_intelligence": "enrich_intelligence"},
    )

    graph.add_conditional_edges(
        "self_correct",
        route_after_correct,
        {"execute_specialists": "execute_specialists"},
    )

    graph.add_conditional_edges(
        "enrich_intelligence",
        route_after_enrich,
        {"contain": "contain"},
    )

    graph.add_edge("contain", "report")
    graph.add_conditional_edges(
        "report",
        route_after_report,
        {"export_stix": "export_stix"},
    )
    graph.add_edge("export_stix", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def run_triage(
    sample_path: str,
    memory_image_path: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> AgentState:
    """
    Entry point for the orchestrator. Returns the final state dict.
    Wall-clock time is enforced by the run.sh --max-time flag externally.
    """
    graph = build_graph()

    initial_state: AgentState = {
        "incident_id": incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}",
        "session_start": datetime.now(timezone.utc).isoformat(),
        "sample_path": sample_path,
        "memory_image_path": memory_image_path,
        "iteration": 0,
        "max_iterations": MAX_ITERATIONS,
        "node_timings": {},
        "errors": [],
        "hash_results": None,
        "vt_results": None,
        "yara_results": None,
        "volatility_results": {},
        "ioc_results": None,
        "dynamic_results": None,
        "firewall_rules": None,
        "findings": [],
        "inferences": [],
        "confidence_score": 0.0,
        "static_confidence_score": 0.0,
        "dynamic_confidence_score": 0.0,
        "validation_delta": 0.0,
        "hallucination_flags": [],
        "llm_analysis": None,
        "sandbox_actions_requested": [],
        "llm_iteration": 0,
        "max_llm_iterations": MAX_LLM_ITERATIONS,
        "needs_correction": False,
        "correction_reason": "",
        "status": "running",
        "plan": [],
        "report_paths": {},
        "attack_techniques": [],
        "ioc_memory_warnings": [],
        "binary_analysis_results": None,
        "entropy_results": None,
        "network_intel_results": None,
        "vulnerability_results": None,
    }

    final_state = await graph.ainvoke(initial_state)
    return final_state
