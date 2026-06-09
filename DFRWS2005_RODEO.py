#!/usr/bin/env python3
"""
DFRWS2005_RODEO.py
==================
Test script to run SIFT-AID on the DFRWS2005-RODEO RHINOUSB.dd forensic image.
Sets up the necessary environment variables, runs the orchestration pipeline,
and outputs the triage results and report locations.
"""

import asyncio
import os
import sys
import time
from pathlib import Path

# Ensure absolute paths for SIFT-AID environment variables
current_dir = Path(__file__).parent.resolve()
os.environ["CASES_DIR"] = str(current_dir / "output/cases")
os.environ["YARA_RULES_DIR"] = str(current_dir / "yara_rules")
os.environ["EVIDENCE_ROOT"] = str(current_dir / "vf_datasets")
os.environ["LOG_LEVEL"] = "INFO"
# VT_API_KEY will be automatically fetched from environment or .env file by HashSpecialist
# Set a generous timeout (300 seconds) because the image is ~247MB
os.environ["TOOL_TIMEOUT"] = "300"

# Use mock sandbox by default (no real CAPE server needed)
os.environ.setdefault("USE_MOCK_SANDBOX", "True")

# Inject current directory into python path to find local modules
sys.path.insert(0, str(current_dir))

try:
    from agents.orchestrator import run_triage
except ImportError as e:
    print(f"Error importing SIFT-AID orchestration modules: {e}")
    print("Please make sure you are running in the virtual environment.")
    sys.exit(1)


async def main():
    sample_path = current_dir / "vf_datasets/RHINOUSB.dd"
    if not sample_path.exists():
        print(f"[-] Error: Dataset file not found at {sample_path}")
        sys.exit(1)

    print("=" * 80)
    print("   SIFT-AID — DFRWS2005-RODEO (RHINOUSB.dd) Case Triage")
    print("=" * 80)
    print(f"[+] Sample Path: {sample_path}")
    print(f"[+] File Size:   {sample_path.stat().st_size / (1024*1024):.2f} MB")
    print("[+] Status:      Starting triage orchestration (timeout 300s)...")
    print("-" * 80)

    t_start = time.monotonic()

    try:
        # Execute the triage pipeline asynchronously
        final_state = await run_triage(
            sample_path=str(sample_path),
            incident_id="INC-DFRWS2005RODEO"
        )

        elapsed = time.monotonic() - t_start

        print("-" * 80)
        print("[+] TRIAGE COMPLETE")
        print(f"  Incident ID:       {final_state['incident_id']}")
        print(f"  Status:            {final_state.get('status', 'unknown').upper()}")
        print(f"  Wall time:         {elapsed:.2f}s")
        print(f"  Confidence score:  {final_state.get('confidence_score', 0) * 100:.1f}%")
        print(f"  Confirmed findings:{len(final_state.get('findings', []))}")
        print(f"  Inferences:        {len(final_state.get('inferences', []))}")
        print("  Reports:")
        for fmt, path in final_state.get("report_paths", {}).items():
            print(f"    {fmt:<10} → {path}")
        print("=" * 80)

        # Print findings detail
        if final_state.get("findings"):
            print("\nConfirmed Findings:")
            for idx, finding in enumerate(final_state["findings"], 1):
                print(f"  {idx}. [{finding.get('type')}] Confidence: {finding.get('confidence', 0)*100:.1f}%")
                print(f"     Source: {finding.get('source')}")
                if finding.get("evidence"):
                    print(f"     Evidence: {finding.get('evidence')}")
                if finding.get("rule"):
                    print(f"     YARA Rule: {finding.get('rule')}")

        if final_state.get("inferences"):
            print("\nInferences:")
            for idx, inf in enumerate(final_state["inferences"], 1):
                print(f"  {idx}. [{inf.get('type')}] Confidence: {inf.get('confidence', 0)*100:.1f}%")
                print(f"     Source: {inf.get('source')}")
                if inf.get("evidence"):
                    print(f"     Evidence: {inf.get('evidence')}")

    except Exception as exc:
        print(f"[-] Orchestration failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
