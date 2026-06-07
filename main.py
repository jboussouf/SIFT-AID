#!/usr/bin/env python3
"""
SIFT-AID — Main Entrypoint
================================
Usage:
    python main.py --sample /cases/evidence/sample.exe [--memory /cases/evidence/mem.raw] [--incident-id INC-001]

Enforces the --max-time wall-clock limit externally via signal alarm.
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Structured logging for the entire session
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/sift_aid_session.log"),
    ],
)
log = logging.getLogger("sift_aid.main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SIFT-AID: Autonomous Malware Triage & Containment Agent"
    )
    parser.add_argument(
        "--sample", required=True,
        help="Absolute path to the malware sample (read-only)"
    )
    parser.add_argument(
        "--memory",
        help="Absolute path to memory image/dump (optional, read-only)"
    )
    parser.add_argument(
        "--incident-id",
        help="Custom incident ID (auto-generated if omitted)"
    )
    parser.add_argument(
        "--max-time", type=int, default=480,
        help="Maximum wall-clock seconds (default: 480 = 8 minutes)"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    parser.add_argument(
        "--cases-dir", default=os.environ.get("CASES_DIR", "/cases"),
        help="Directory to write case artifacts"
    )
    return parser.parse_args()


def enforce_time_limit(max_seconds: int) -> None:
    """
    Install a SIGALRM handler to hard-kill the process if wall clock exceeded.
    Ensures sub-8-minute constraint is enforced architecturally.
    """
    def _timeout_handler(signum, frame):
        log.error(
            "WALL-CLOCK LIMIT of %ds exceeded. Forcing exit. "
            "Partial results may be available in the cases directory.",
            max_seconds,
        )
        sys.exit(124)  # Standard timeout exit code

    if hasattr(signal, "SIGALRM"):   # Linux only
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(max_seconds)
        log.info("Wall-clock timer set: %ds", max_seconds)
    else:
        log.warning("SIGALRM not available on this platform — time limit not enforced at OS level")


async def main() -> None:
    args = parse_args()

    # Update log level from flag
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Set env vars before importing orchestrator (it reads them at module level)
    os.environ["CASES_DIR"] = args.cases_dir
    os.environ["LOG_LEVEL"] = args.log_level

    # Hard wall-clock enforcement
    enforce_time_limit(args.max_time)

    t_start = time.monotonic()
    log.info("=" * 70)
    log.info("SIFT-AID v1.0.0 — FIND EVIL! Hackathon Submission")
    log.info("=" * 70)
    log.info("Sample: %s", args.sample)
    log.info("Memory: %s", args.memory or "Not provided")
    log.info("Max time: %ds", args.max_time)
    log.info("Cases dir: %s", args.cases_dir)

    # Validate sample exists
    sample_path = Path(args.sample)
    if not sample_path.exists():
        log.error("Sample file not found: %s", args.sample)
        sys.exit(1)

    # Late import to respect env var changes above
    from agents.orchestrator import run_triage

    try:
        log.info("Starting triage orchestration...")
        final_state = await run_triage(
            sample_path=str(sample_path),
            memory_image_path=args.memory,
            incident_id=args.incident_id,
        )

        wall_time = time.monotonic() - t_start

        log.info("=" * 70)
        log.info("TRIAGE COMPLETE")
        log.info("  Incident ID:       %s", final_state["incident_id"])
        log.info("  Status:            %s", final_state.get("verdict", final_state.get("status", "unknown")).upper())
        log.info("  Wall time:         %.2fs (limit: %ds)", wall_time, args.max_time)
        log.info("  Confidence score:  %.1f%%", final_state.get("confidence_score", 0) * 100)
        log.info("  Confirmed findings:%d", len(final_state.get("findings", [])))
        log.info("  Inferences:        %d", len(final_state.get("inferences", [])))
        log.info("  Iterations:        %d/%d", final_state.get("iteration", 0), final_state.get("max_iterations", 3))
        log.info("  Reports:")
        for fmt, path in final_state.get("report_paths", {}).items():
            log.info("    %-10s → %s", fmt, path)
        log.info("=" * 70)

        # Print final summary to stdout for CI/CD consumption
        summary = {
            "incident_id": final_state["incident_id"],
            "status": final_state.get("verdict", final_state.get("status")),
            "wall_time_seconds": round(wall_time, 2),
            "confidence_score": final_state.get("confidence_score"),
            "confirmed_findings": len(final_state.get("findings", [])),
            "inferences": len(final_state.get("inferences", [])),
            "report_paths": final_state.get("report_paths", {}),
        }
        print("\n--- SIFT-AID SUMMARY ---")
        print(json.dumps(summary, indent=2))

    except Exception as exc:
        log.exception("Fatal orchestration error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
