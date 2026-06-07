"""
AuditLogger — structured JSON audit trail for every tool call and state transition.

Judging Alignment:
  - Audit Trail: Every finding traceable to exact tool call, timestamp, command, output
  - Token/latency tracking per node
  - Immutable append-only JSON Lines file
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sift_aid.audit")


class AuditLogger:
    """
    Thread-safe, append-only structured audit logger.
    Writes JSON Lines format to logs/execution_trace.jsonl.
    Each record maps a finding back to its exact tool invocation.
    """

    def __init__(self, incident_id: str, cases_dir: Path):
        self.incident_id = incident_id
        self.cases_dir = cases_dir
        self._lock = threading.Lock()

        log_dir = cases_dir / incident_id / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        self._trace_path = log_dir / "execution_trace.jsonl"
        self._summary_path = log_dir / "session_summary.json"
        self._session_start = time.monotonic()

        # Write session header
        self._append({
            "event": "session_start",
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        result: Any,
        elapsed_seconds: float,
        error: Optional[str] = None,
    ) -> None:
        """
        Record a tool invocation with full args, result preview, and timing.
        This is the core audit evidence link.
        """
        record = {
            "event": "tool_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool_name,
            "arguments": arguments,
            "elapsed_seconds": round(elapsed_seconds, 3),
            "error": error,
            "result_type": type(result).__name__,
            "result_preview": _safe_preview(result, 1024),
        }
        self._append(record)

    def log_state_transition(
        self,
        from_node: str,
        to_node: str,
        iteration: int,
        confidence: float,
        delta: float,
    ) -> None:
        """Record state machine transitions for graph audit trail."""
        record = {
            "event": "state_transition",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "from_node": from_node,
            "to_node": to_node,
            "iteration": iteration,
            "confidence_score": confidence,
            "confidence_delta": delta,
            "session_wall_time": round(time.monotonic() - self._session_start, 2),
        }
        self._append(record)

    def log_finding(
        self,
        finding: dict,
        confirmed: bool,
        source_tool: str,
    ) -> None:
        """
        Record a finding with its tool source citation.
        confirmed=True means multiple tools corroborate it.
        """
        record = {
            "event": "finding",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "confirmed": confirmed,
            "finding": finding,
            "source_tool": source_tool,
        }
        self._append(record)

    def log_error(self, context: str, error: str, node: Optional[str] = None) -> None:
        """Record errors without losing audit continuity."""
        record = {
            "event": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "context": context,
            "error": error,
            "node": node,
        }
        self._append(record)

    def finalize(self, final_state: dict) -> str:
        """Write session summary JSON and return path to trace file."""
        summary = {
            "incident_id": self.incident_id,
            "session_start": final_state.get("session_start"),
            "session_end": datetime.now(timezone.utc).isoformat(),
            "total_wall_seconds": round(time.monotonic() - self._session_start, 2),
            "node_timings": final_state.get("node_timings", {}),
            "dynamic_analysis_trace": {
                "task_id": final_state.get("dynamic_results", {}).get("task_id", "N/A"),
                "polling_duration": final_state.get("dynamic_results", {}).get("elapsed_seconds", 0.0),
                "parsed_json": final_state.get("dynamic_results", {}),
                "interactive_commands_executed": len(final_state.get("dynamic_results", {}).get("interactive_results", [])),
            } if final_state.get("dynamic_results") else None,
            "llm_analysis": {
                "passes": final_state.get("llm_iteration", 0),
                "reasoning": (final_state.get("llm_analysis") or {}).get("reasoning", ""),
                "static_score": final_state.get("static_confidence_score"),
                "dynamic_score": final_state.get("dynamic_confidence_score"),
            } if final_state.get("llm_analysis") else None,
            "iterations": final_state.get("iteration", 0),
            "confidence_score": final_state.get("confidence_score"),
            "static_confidence_score": final_state.get("static_confidence_score"),
            "dynamic_confidence_score": final_state.get("dynamic_confidence_score"),
            "confirmed_findings": len(final_state.get("findings", [])),
            "inferences": len(final_state.get("inferences", [])),
            "hallucination_flags": final_state.get("hallucination_flags", []),
            "errors": final_state.get("errors", []),
            "status": final_state.get("status"),
            "trace_file": str(self._trace_path),
        }
        with self._lock:
            self._summary_path.write_text(json.dumps(summary, indent=2))

        self._append({"event": "session_end", "summary": summary})
        return str(self._trace_path)

    def _append(self, record: dict) -> None:
        """Append a JSON record to the trace file (thread-safe)."""
        with self._lock:
            with self._trace_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")


def _safe_preview(obj: Any, max_chars: int) -> str:
    """Safely serialise any object to a preview string."""
    try:
        s = json.dumps(obj, default=str)
    except Exception:
        s = str(obj)
    return s[:max_chars] + ("…" if len(s) > max_chars else "")
