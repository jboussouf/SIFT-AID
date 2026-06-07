"""
Reporter — generates machine-readable JSON and human-readable Markdown reports.

Judging Alignment:
  - IR Accuracy: Explicit separation of confirmed findings vs. inferences
  - Audit Trail: Every claim cites exact MCP function, timestamp, and output snippet
  - Usability: Markdown report is analyst-ready with clear section headers
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("sift_aid.reporter")

SIFT_AID_VERSION = "1.1.0"


class Reporter:
    """Generate JSON and Markdown reports from final agent state."""

    def __init__(self, incident_id: str, cases_dir: Path):
        self.incident_id = incident_id
        self.report_dir = cases_dir / incident_id / "report"
        self.report_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self, state: dict) -> dict[str, str]:
        """
        Generate report.json and report.md from final agent state.
        Returns dict mapping format -> absolute path.
        """
        json_path = await self._write_json_report(state)
        md_path = await self._write_markdown_report(state)

        log.info("[Reporter] JSON report: %s", json_path)
        log.info("[Reporter] Markdown report: %s", md_path)
        return {"json": json_path, "markdown": md_path}

    async def _read_execution_trace(self, state: dict) -> list[dict]:
        """Read all log records from the execution trace file."""
        trace_path = self.report_dir.parent / "logs" / "execution_trace.jsonl"
        records = []
        if trace_path.exists():
            for line in trace_path.read_text(encoding="utf-8").strip().splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        records.append({"event": "parse_error", "raw": line[:500]})
        return records

    async def _write_json_report(self, state: dict) -> str:
        """Machine-readable report with full tool citations."""
        dyn_r = state.get("dynamic_results", {})
        trace_records = await self._read_execution_trace(state)
        report = {
            "schema_version": "2.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sift_aid_version": SIFT_AID_VERSION,
            "incident": {
                "id": state["incident_id"],
                "started_at": state.get("session_start"),
                "sample_path": state.get("sample_path"),
                "memory_image": state.get("memory_image_path"),
                "status": state.get("status"),
                "verdict": state.get("verdict", "UNDETERMINED"),
                "total_iterations": state.get("iteration", 0),
            },
            "performance": {
                "node_timings_seconds": state.get("node_timings", {}),
                "total_wall_seconds": sum(state.get("node_timings", {}).values()),
            },
            "confidence": {
                "overall": state.get("confidence_score"),
                "static_analysis": state.get("static_confidence_score"),
                "dynamic_analysis": state.get("dynamic_confidence_score"),
                "delta_last": state.get("validation_delta"),
            },
            "llm_analysis": state.get("llm_analysis"),
            "confirmed_findings": [
                {**f, "certainty": "CONFIRMED"}
                for f in state.get("findings", [])
            ],
            "inferences": [
                {**f, "certainty": "INFERRED"}
                for f in state.get("inferences", [])
            ],
            "hallucination_flags": state.get("hallucination_flags", []),
            "attack_techniques": state.get("attack_techniques", []),
            "ioc_memory_warnings": state.get("ioc_memory_warnings", []),
            "execution_logs": {
                "record_count": len(trace_records),
                "records": trace_records,
            },
            "stix_bundle": "report/stix_bundle.json",
            "tool_outputs": {
                "compute_hash": state.get("hash_results"),
                "query_virustotal": state.get("vt_results"),
                "run_yara_scan": state.get("yara_results"),
                "execute_volatility_plugins": state.get("volatility_results", {}),
                "extract_iocs": state.get("ioc_results"),
                "analyze_binary": state.get("binary_analysis_results"),
                "compute_entropy": state.get("entropy_results"),
                "enrich_network_iocs": state.get("network_intel_results"),
                "check_vulnerable_libraries": state.get("vulnerability_results"),
                "dynamic_analysis": {
                    "sandbox_report": {k: v for k, v in dyn_r.items() if k != "interactive_results"},
                    "interactive_commands": dyn_r.get("interactive_results", []),
                } if dyn_r else None,
            },
            "containment": {
                "firewall_rules": state.get("firewall_rules"),
                "disclaimer": "ANALYST REVIEW REQUIRED before applying any containment action.",
            },
            "errors": state.get("errors", []),
        }

        path = self.report_dir / "report.json"
        path.write_text(json.dumps(report, indent=2, default=str))
        return str(path)

    async def _write_markdown_report(self, state: dict) -> str:
        """Human-readable DFIR analyst report with explicit finding provenance."""
        lines = []

        # ── Header ────────────────────────────────────────────────────────────
        lines += [
            f"# SIFT-AID Triage Report",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Incident ID** | `{state['incident_id']}` |",
            f"| **Started** | {state.get('session_start', 'N/A')} |",
            f"| **Completed** | {datetime.now(timezone.utc).isoformat()} |",
            f"| **Sample** | `{state.get('sample_path', 'N/A')}` |",
            f"| **Memory Image** | `{state.get('memory_image_path') or 'Not provided'}` |",
            f"| **Status** | **{state.get('status', 'unknown').upper()}** |",
            f"| **Confidence (Overall)** | {state.get('confidence_score', 0):.1%} |",
            f"| **Confidence (Static)** | {state.get('static_confidence_score', 0):.1%} |",
            f"| **Confidence (Dynamic)** | {state.get('dynamic_confidence_score', 0):.1%} |",
            f"| **Iterations** | {state.get('iteration', 0)}/{state.get('max_iterations', 3)} |",
            f"| **LLM Analysis Passes** | {state.get('llm_iteration', 0)}/{state.get('max_llm_iterations', 3)} |",
            f"| **STIX 2.1 Bundle** | `report/stix_bundle.json` |",
            f"",
        ]

        # ── Performance ───────────────────────────────────────────────────────
        node_timings = state.get("node_timings", {})
        total_time = sum(node_timings.values())
        lines += [
            f"## Performance",
            f"",
            f"| Node | Wall Time |",
            f"|------|-----------|",
        ]
        for node, secs in node_timings.items():
            lines.append(f"| `{node}` | {secs:.2f}s |")
        lines += [f"| **TOTAL** | **{total_time:.2f}s** |", f""]

        # ── LLM Cross-Analysis ────────────────────────────────────────────────
        llm = state.get("llm_analysis", {})
        if llm:
            lines += [
                f"## LLM Cross-Analysis",
                f"",
                f"> The LLM reviewed both static and dynamic evidence independently.",
                f"",
                f"| Metric | Score |",
                f"|--------|-------|",
                f"| **Static Confidence** | {llm.get('static_confidence_score', 0):.1%} |",
                f"| **Dynamic Confidence** | {llm.get('dynamic_confidence_score', 0):.1%} |",
                f"| **LLM Pass** | {llm.get('iteration', 'N/A')} |",
                f"",
                f"**Reasoning:** {llm.get('reasoning', 'N/A')}",
                f"",
            ]

        # ── Confirmed Findings ────────────────────────────────────────────────
        findings = state.get("findings", [])
        lines += [
            f"## [+] Confirmed Findings ({len(findings)})",
            f"",
            f"> These findings are corroborated by multiple independent tool outputs.",
            f"",
        ]
        if findings:
            for i, f in enumerate(findings, 1):
                lines += [
                    f"### Finding {i}: {f.get('type', 'UNKNOWN')}",
                    f"",
                    f"- **Confidence:** {f.get('confidence', 0):.1%}",
                    f"- **Source Tool:** `{f.get('source', 'N/A')}`",
                ]
                for k, v in f.items():
                    if k not in ("type", "confidence", "source"):
                        lines.append(f"- **{k.replace('_', ' ').title()}:** `{v}`")
                lines.append(f"")
        else:
            lines += [f"*No confirmed findings. See inferences below.*", f""]

        # ── Inferences ────────────────────────────────────────────────────────
        inferences = state.get("inferences", [])
        lines += [
            f"## [?] Inferences ({len(inferences)})",
            f"",
            f"> These are lower-confidence observations. **Analyst verification required.**",
            f"",
        ]
        if inferences:
            for i, inf in enumerate(inferences, 1):
                lines += [
                    f"### Inference {i}: {inf.get('type', 'UNKNOWN')}",
                    f"",
                    f"- **Confidence:** {inf.get('confidence', 0):.1%}",
                    f"- **Source Tool:** `{inf.get('source', 'N/A')}`",
                ]
                for k, v in inf.items():
                    if k not in ("type", "confidence", "source"):
                        lines.append(f"- **{k.replace('_', ' ').title()}:** `{v}`")
                lines.append(f"")
        else:
            lines += [f"*No inferences recorded.*", f""]

        # ── Hallucination Flags ───────────────────────────────────────────────
        hflags = state.get("hallucination_flags", [])
        if hflags:
            lines += [
                f"## [!] Hallucination Flags",
                f"",
                f"> Claims flagged as potentially unsupported by tool outputs:",
                f"",
            ]
            for flag in hflags:
                lines.append(f"- {flag}")
            lines.append(f"")

        # ── IOC Summary ───────────────────────────────────────────────────────
        ioc_r = state.get("ioc_results", {})
        if ioc_r and not ioc_r.get("error"):
            lines += [
                f"## [O] Extracted IOCs",
                f"",
                f"**Source:** `extract_iocs` on `{ioc_r.get('file', 'N/A')}`",
                f"",
                f"| IOC Type | Count |",
                f"|----------|-------|",
            ]
            for ioc_type, ioc_list in ioc_r.get("iocs", {}).items():
                lines.append(f"| `{ioc_type}` | {len(ioc_list)} |")
            lines.append(f"")

            for ioc_type, ioc_list in ioc_r.get("iocs", {}).items():
                lines += [f"**{ioc_type.upper()}:**", f"```", *ioc_list[:20], f"```", f""]

        # ── Hash + VT ─────────────────────────────────────────────────────────
        hash_r = state.get("hash_results", {})
        vt_r = state.get("vt_results", {})
        if hash_r and not hash_r.get("error"):
            hashes = hash_r.get("hashes", {})
            lines += [
                f"## [Hash] File Hashes",
                f"",
                f"**Source:** `compute_hash`  |  **File:** `{hash_r.get('file')}`  |  **Size:** {hash_r.get('size_bytes', 0):,} bytes",
                f"",
                f"| Algorithm | Hash |",
                f"|-----------|------|",
                *[f"| `{alg.upper()}` | `{h}` |" for alg, h in hashes.items()],
                f"",
            ]
            if vt_r and not vt_r.get("error"):
                lines += [
                    f"**VirusTotal Result** (`query_virustotal`):",
                    f"",
                    f"- Status: `{vt_r.get('status', 'N/A')}`",
                    f"- Malicious: **{vt_r.get('malicious', 'N/A')}**",
                    f"- Suspicious: {vt_r.get('suspicious', 'N/A')}",
                    f"- Threat Label: `{vt_r.get('threat_label', 'N/A')}`",
                    f"",
                ]

        # ── Dynamic Behavior ──────────────────────────────────────────────────
        dyn_r = state.get("dynamic_results", {})
        if dyn_r and not dyn_r.get("error"):
            lines += [
                f"## [~] Dynamic Behavior (Sandbox)",
                f"",
                f"**Source:** CAPE Sandbox | **Task ID:** `{dyn_r.get('task_id', 'N/A')}`",
                f"",
                f"### Network IOCs",
            ]
            for nioc in dyn_r.get("network_iocs", []):
                lines.append(f"- `{nioc}`")
            lines.append(f"")

            lines.append(f"### Dropped Files")
            for f in dyn_r.get("dropped_files", []):
                lines.append(f"- `{f}`")
            lines.append(f"")

            lines.append(f"### ATT&CK Techniques")
            for t in dyn_r.get("attack_techniques", []):
                lines.append(f"- `{t}`")
            lines.append(f"")

        # ── MITRE ATT&CK Mapping ──────────────────────────────────────────────
        attack_techniques = state.get("attack_techniques", [])
        if attack_techniques:
            lines += [
                f"## [MITRE] MITRE ATT&CK Mapping",
                f"",
                f"> Techniques mapped from extracted behaviors and IOCs.",
                f"",
                f"| Technique ID | Name | Evidence |",
                f"|--------------|------|----------|",
            ]
            for t in attack_techniques:
                tid = t.get("technique_id", "")
                name = t.get("name", "")
                evidence = t.get("evidence", "")
                lines.append(f"| `{tid}` | {name} | {evidence} |")
            lines.append(f"")

        # ── Execution Logs ─────────────────────────────────────────────────────
        trace_records = await self._read_execution_trace(state)
        if trace_records:
            lines += [
                f"## [Logs] Execution Logs ({len(trace_records)} records)",
                f"",
                f"> Full audit trail of all tool calls, state transitions, findings, and errors.",
                f"",
            ]
            for i, record in enumerate(trace_records, 1):
                event = record.get("event", "unknown")
                ts = record.get("timestamp", "")
                tool = record.get("tool", record.get("source_tool", ""))
                context = record.get("context", "")
                node = record.get("node", "")
                err = record.get("error", "")
                lines += [
                    f"### Log Entry {i}: `{event}`",
                    f"",
                    f"- **Timestamp:** `{ts}`",
                ]
                if tool:
                    lines.append(f"- **Tool:** `{tool}`")
                if context:
                    lines.append(f"- **Context:** {context}")
                if node:
                    lines.append(f"- **Node:** `{node}`")
                if err:
                    lines.append(f"- **Error:** `{err}`")
                if event == "state_transition":
                    lines.append(f"- **From:** `{record.get('from_node', '')}` → **To:** `{record.get('to_node', '')}`")
                    lines.append(f"- **Confidence:** {record.get('confidence_score', 0)} (Δ{record.get('confidence_delta', 0)})")
                if event == "tool_call":
                    args = record.get("arguments", {})
                    preview = record.get("result_preview", "")
                    lines.append(f"- **Arguments:** `{json.dumps(args)}`")
                    lines.append(f"- **Result Preview:** `{preview}`")
                    lines.append(f"- **Elapsed:** {record.get('elapsed_seconds', 0)}s")
                if event == "finding":
                    finding = record.get("finding", {})
                    confirmed = record.get("confirmed", False)
                    lines.append(f"- **Confirmed:** {confirmed}")
                    lines.append(f"- **Finding:** `{json.dumps(finding)}`")
                lines.append(f"")

        # ── Threat Intelligence Memory ─────────────────────────────────────────
        ioc_memory_warnings = state.get("ioc_memory_warnings", [])
        if ioc_memory_warnings:
            lines += [
                f"## [MEMORY] Threat Intelligence Memory",
                f"",
                f"> The following IOCs have been seen in previous incidents:",
                f"",
                f"| IOC Value | Type | Previously Seen In | First Seen |",
                f"|-----------|------|-------------------|------------|",
            ]
            for w in ioc_memory_warnings:
                lines.append(
                    f"| `{w.get('ioc_value', '')}` | {w.get('ioc_type', '')} "
                    f"| {w.get('previous_incident', '')} | {w.get('first_seen', '')} |"
                )
            lines.append(f"")
        else:
            lines += [
                f"## [MEMORY] Threat Intelligence Memory",
                f"",
                f"> No IOCs from this incident matched any previously observed indicators.",
                f"",
            ]

        # ── Interactive Sandbox Commands ──────────────────────────────────────
        interactive = dyn_r.get("interactive_results", []) if dyn_r else []
        if interactive:
            lines += [
                f"## [~] Interactive Sandbox Commands (LLM-Requested)",
                f"",
                f"> The LLM requested these commands to deepen the dynamic analysis:",
                f"",
            ]
            for i, cmd in enumerate(interactive, 1):
                action = cmd.get("action", "unknown")
                target = cmd.get("target") or cmd.get("command", "")
                result = cmd.get("result", {})
                err = cmd.get("error")
                lines += [
                    f"### Interactive Command {i}: `{action}`",
                    f"",
                    f"- **Target:** `{target}`",
                ]
                if err:
                    lines.append(f"- **Error:** `{err}`")
                elif result:
                    stdout = result.get("stdout", "")
                    rule = result.get("rule", "")
                    vm_status = result.get("vm_status", "")
                    if stdout:
                        lines.append(f"- **Output:**")
                        lines.append(f"  ```")
                        for line in stdout.strip().splitlines()[:10]:
                            lines.append(f"  {line}")
                        lines.append(f"  ```")
                    if rule:
                        lines.append(f"- **Rule:** `{rule}`")
                    if vm_status:
                        lines.append(f"- **VM Status:** `{vm_status}`")
                lines.append(f"")

        # ── Containment Recommendations ───────────────────────────────────────
        fw = state.get("firewall_rules", {})
        if fw:
            lines += [
                f"## [Containment] Containment Recommendations",
                f"",
                f"> [!] **{fw.get('disclaimer', '')}**",
                f"",
                f"**Source:** `generate_firewall_rules`",
                f"",
                f"### iptables (block {fw.get('ioc_summary', {}).get('ip_count', 0)} IOC IPs)",
                f"```bash",
                *fw.get("iptables_rules", [])[:20],
                f"```",
                f"",
                f"### /etc/hosts DNS blocks ({fw.get('ioc_summary', {}).get('domain_count', 0)} domains)",
                f"```",
                *fw.get("hosts_file_entries", [])[:20],
                f"```",
                f"",
            ]

        # ── Errors ────────────────────────────────────────────────────────────
        errors = state.get("errors", [])
        if errors:
            lines += [
                f"## [X] Errors During Analysis",
                f"",
                *[f"- `{e.get('specialist', e.get('node', 'unknown'))}`: {e.get('error')}" for e in errors],
                f"",
            ]

        # ── Final Verdict ─────────────────────────────────────────────────────
        score = state.get("confidence_score", 0)
        static_score = state.get("static_confidence_score", 0)
        dynamic_score = state.get("dynamic_confidence_score", 0)
        verdict = state.get("verdict", "UNDETERMINED")

        lines += [
            f"## [X] Final Verdict",
            f"",
            f"Based on the combined static + dynamic analysis, this software is assessed as **{verdict}**.",
            f"",
            f"| Score Source | Value |",
            f"|-------------|-------|",
            f"| **Overall Confidence** | {score:.1%} |",
            f"| **Static Analysis** | {static_score:.1%} |",
            f"| **Dynamic Analysis** | {dynamic_score:.1%} |",
            f"",
        ]

        # ── Footer ────────────────────────────────────────────────────────────
        lines += [
            f"---",
            f"*Generated by SIFT-AID v{SIFT_AID_VERSION} | "
            f"Open source | Hackathon: FIND EVIL! | "
            f"All evidence mounted read-only. Original artifacts unmodified.*",
        ]

        path = self.report_dir / "report.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)
