#!/usr/bin/env python3
"""
run_demo.py — SIFT-AID Full Demo Runner (Python)
=====================================================
Runs all forensic dataset triage tests and/or clean software validation.

Usage:
    # Run only forensic datasets (requires vf_datasets/):
    python run_demo.py

    # Run only clean software validation (no datasets needed):
    python run_demo.py --clean

    # Run both:
    python run_demo.py --all

    # Custom clean binaries directory:
    python run_demo.py --clean --clean-dir /path/to/clean/binaries

    python run_demo.py --log-level DEBUG

Modes:
  1. Forensic datasets — SCHARDT.005, 2020JimmyWilson, cfreds_2015, RHINOUSB.dd
  2. Clean software validation — runs pipeline on known benign binaries
     and checks that confidence stays low (no false positives).
"""

import argparse
import asyncio
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).parent.resolve()
VF_DIR = SCRIPT_DIR / "vf_datasets"
RESULTS_DIR = SCRIPT_DIR / "output/demo_results"
PYTHON = SCRIPT_DIR / "venv/bin/python"


def load_env():
    env_file = SCRIPT_DIR / ".env"
    if env_file.exists():
        print(f"[*] Loading environment variables from .env...")
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                val = val.strip("\"'")
                if key not in os.environ:
                    os.environ[key] = val


def green(s): return f"\033[0;32m{s}\033[0m"
def red(s):   return f"\033[0;31m{s}\033[0m"
def yellow(s): return f"\033[1;33m{s}\033[0m"
def cyan(s):  return f"\033[0;36m{s}\033[0m"
def bold(s):  return f"\033[1m{s}\033[0m"


def banner(text: str):
    line = "═" * 74
    print(f"\n{bold(cyan(line))}")
    print(f"{bold(cyan(f'  {text}'))}")
    print(f"{bold(cyan(line))}\n")


DATASETS: list[dict] = [
    {
        "name": "SCHARDT.005",
        "script": "SCHARDT.py",
        "dataset": "vf_datasets/SCHARDT.005",
    },
    {
        "name": "2020JimmyWilson.E01",
        "script": "2020JimmyWilson.py",
        "dataset": "vf_datasets/2020JimmyWilson.E01",
    },
    {
        "name": "cfreds_2015_data_leakage_rm2.E01",
        "script": "cfreds_2015_data_leakage_rm#2.py",
        "dataset": "vf_datasets/cfreds_2015_data_leakage_rm#2.E01",
    },
    {
        "name": "RHINOUSB.dd",
        "script": "DFRWS2005_RODEO.py",
        "dataset": "vf_datasets/RHINOUSB.dd",
    },
]


class TestResult:
    def __init__(self, name: str, status: str, wall_time: str,
                 confidence: str, findings: str, incident: str,
                 is_clean_test: bool = False, verdict: str = ""):
        self.name = name
        self.status = status
        self.wall_time = wall_time
        self.confidence = confidence
        self.findings = findings
        self.incident = incident
        self.is_clean_test = is_clean_test
        self.verdict = verdict


CLEAN_BINARIES = [
    "ls", "cat", "echo", "touch", "mkdir", "rm", "cp", "mv",
    "grep", "find", "sort", "wc", "date", "whoami", "id",
]


def parse_log(log_path: Path) -> dict:
    text = log_path.read_text() if log_path.exists() else ""
    confidence = "N/A"
    findings = "N/A"
    incident = "N/A"
    status = "N/A"

    m = re.search(r"Confidence score:\s+([0-9.]+%)", text)
    if m:
        confidence = m.group(1)

    m = re.search(r"Confirmed findings:\s*([0-9]+)", text)
    if m:
        findings = m.group(1)

    m = re.search(r"Incident ID:\s+(INC-\S+)", text)
    if m:
        incident = m.group(1)

    m = re.search(r"Status:\s+(\S+)", text)
    if m:
        status = m.group(1)

    return {"confidence": confidence, "findings": findings, "incident": incident, "status": status}


def check_false_positive(log_path: Path) -> tuple[bool, str]:
    """Verify clean binary wasn't flagged as malicious."""
    text = log_path.read_text() if log_path.exists() else ""
    if not text:
        return False, "no log output"

    confidence = "N/A"
    findings = "N/A"
    status = "N/A"

    m = re.search(r"Confidence score:\s+([0-9.]+%)", text)
    if m:
        confidence = m.group(1)

    m = re.search(r"Confirmed findings:\s*([0-9]+)", text)
    if m:
        findings = m.group(1)

    m = re.search(r"Status:\s+(\S+)", text)
    if m:
        status = m.group(1)

    # Parse confidence as float
    conf_val = 0.0
    if confidence != "N/A":
        conf_val = float(confidence.strip("%"))

    findings_val = 0
    if findings != "N/A":
        findings_val = int(findings)

    issues = []
    if findings_val > 0:
        issues.append(f"found {findings_val} finding(s)")
    if conf_val >= 50.0:
        issues.append(f"confidence {confidence} ({conf_val:.0f}%) >= 50% — possible FP")
    if status == "MALICIOUS":
        issues.append("classified as MALICIOUS")

    if issues:
        return False, "; ".join(issues)

    return True, f"clean (conf={confidence}, findings={findings})"


async def run_clean_test(binary_name: str, binary_path: Path) -> TestResult:
    """Run SIFT-AID on a known clean binary and check for false positives."""
    safe_name = f"clean_{binary_name}"
    log_file = RESULTS_DIR / f"{safe_name}.log"

    print(f"{bold('▶  Testing clean binary:')} {binary_name} ({binary_path})")
    print(f"   Log : {log_file}\n")

    if not binary_path.exists():
        print(f"   {yellow('[-] Binary not found — SKIPPED')}\n")
        return TestResult(safe_name, "SKIPPED", "N/A",
                          "N/A", "N/A", "N/A", is_clean_test=True)

    t_start = time.monotonic()

    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(SCRIPT_DIR / "main.py"),
        "--sample", str(binary_path),
        "--log-level", os.environ.get("LOG_LEVEL", "INFO"),
        "--max-time", "300",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ,
             "PYTHONPATH": str(SCRIPT_DIR),
             "CASES_DIR": str(SCRIPT_DIR / "output/clean_cases"),
             "USE_MOCK_SANDBOX": "False"},
    )

    stdout, _ = await proc.communicate()
    t_end = time.monotonic()
    wall_time = t_end - t_start
    output = stdout.decode()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_file.write_text(output)

    parsed = parse_log(log_file)
    exit_code = proc.returncode

    fp_ok, fp_msg = check_false_positive(log_file)

    if fp_ok and exit_code == 0:
        status = "PASSED"
        status_colour = green(status)
    elif not fp_ok:
        status = f"FP_DETECTED ({fp_msg})"
        status_colour = red(status)
    else:
        status = f"FAILED (exit {exit_code})"
        status_colour = red(status)

    print(f"   Status     : {status_colour}")
    print(f"   Wall time  : {wall_time:.1f}s")
    print(f"   Confidence : {parsed['confidence']}")
    print(f"   Findings   : {parsed['findings']} confirmed")
    print(f"   FP check   : {fp_msg}\n")

    return TestResult(
        name=safe_name,
        status=status,
        wall_time=f"{wall_time:.0f}s",
        confidence=parsed["confidence"],
        findings=parsed["findings"],
        incident=parsed["incident"],
        is_clean_test=True,
    )


async def run_test(dataset: dict) -> TestResult:
    name = dataset["name"]
    script_path = SCRIPT_DIR / dataset["script"]
    dataset_path = SCRIPT_DIR / dataset["dataset"]

    safe_name = name.replace("/", "_")
    log_file = RESULTS_DIR / f"{safe_name}.log"

    print(f"{bold('▶  Running:')} {name}")
    print(f"   Dataset : {dataset_path}")
    print(f"   Script  : {script_path}")
    print(f"   Log     : {log_file}\n")

    if not dataset_path.exists():
        print(f"   {yellow('[-] Dataset not found — SKIPPED')}\n")
        return TestResult(name, "SKIPPED", "N/A", "N/A", "N/A", "N/A", verdict="N/A")

    t_start = time.monotonic()

    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(script_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "PYTHONPATH": str(SCRIPT_DIR)},
    )

    stdout, _ = await proc.communicate()

    t_end = time.monotonic()
    wall_time = t_end - t_start
    output = stdout.decode()

    # Write log
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_file.write_text(output)

    # Parse
    parsed = parse_log(log_file)
    exit_code = proc.returncode

    if exit_code == 0:
        status = "PASSED"
        status_colour = green(status)
    else:
        status = f"FAILED (exit {exit_code})"
        status_colour = red(status)

    print(f"   Status     : {status_colour}")
    print(f"   Wall time  : {wall_time:.1f}s")
    print(f"   Confidence : {parsed['confidence']}")
    print(f"   Findings   : {parsed['findings']} confirmed")
    print(f"   Incident   : {parsed['incident']}\n")

    return TestResult(
        name=name,
        status=status,
        wall_time=f"{wall_time:.0f}s",
        confidence=parsed["confidence"],
        findings=parsed["findings"],
        incident=parsed["incident"],
        verdict=parsed.get("status", ""),
    )


def print_summary(results: list[TestResult]):
    # Split results into forensic and clean test groups
    forensic = [r for r in results if not r.is_clean_test]
    clean = [r for r in results if r.is_clean_test]

    if forensic:
        banner("FORENSIC DATASET RESULTS")

        header = f"{'TEST':<45} {'STATUS':<10} {'TIME':<10} {'CONFIDENCE':<12} {'FINDINGS':<12} {'INCIDENT ID'}"
        sep = f"{'─' * 45} {'─' * 10} {'─' * 10} {'─' * 12} {'─' * 12} {'─' * 20}"
        print(header)
        print(sep)

        for r in forensic:
            if r.status == "PASSED":
                colour = green
            elif r.status == "FAILED" or r.status.startswith("FAILED"):
                colour = red
            elif r.status == "SKIPPED":
                colour = yellow
            else:
                colour = lambda x: x

            print(colour(
                f"{r.name:<45} {r.status:<10} {r.wall_time:<10} {r.confidence:<12} {r.findings:<12} {r.incident}"
            ))

    if clean:
        banner("CLEAN SOFTWARE VALIDATION RESULTS (FALSE POSITIVE CHECK)")

        header = f"{'TEST':<45} {'STATUS':<25} {'TIME':<10} {'CONFIDENCE':<12} {'FINDINGS':<12}"
        sep = f"{'─' * 45} {'─' * 25} {'─' * 10} {'─' * 12} {'─' * 12}"
        print(header)
        print(sep)

        fp_count = 0
        for r in clean:
            if r.status == "PASSED":
                colour = green
            elif r.status.startswith("FP_DETECTED"):
                colour = red
                fp_count += 1
            elif r.status == "FAILED" or r.status.startswith("FAILED"):
                colour = red
            elif r.status == "SKIPPED":
                colour = yellow
            else:
                colour = lambda x: x

            print(colour(
                f"{r.name:<45} {r.status:<25} {r.wall_time:<10} {r.confidence:<12} {r.findings:<12}"
            ))

        if fp_count == 0:
            print(f"\n{green('✓ All clean binaries passed — no false positives detected.')}")
        else:
            print(f"\n{red(f'✗ {fp_count} clean binary/bineries triggered false positive flags — review logs above.')}")

    print(f"\n{bold('Reports are saved under:')} {SCRIPT_DIR / 'output/cases/'} and {SCRIPT_DIR / 'output/clean_cases/'}")
    print(f"{bold('Full demo logs:')}         {RESULTS_DIR}/\n")

    # Write plain-text summary
    summary_file = RESULTS_DIR / f"demo_summary_{datetime.now():%Y%m%d_%H%M%S}.txt"
    with open(summary_file, "w") as f:
        f.write(f"SIFT-AID Demo Summary — {datetime.now()}\n")
        f.write("=" * 50 + "\n")
        for r in results:
            f.write(f"\nDataset   : {r.name}\n")
            f.write(f"Status    : {r.status}\n")
            f.write(f"Wall time : {r.wall_time}\n")
            f.write(f"Confidence: {r.confidence}\n")
            f.write(f"Findings  : {r.findings}\n")
            f.write(f"Incident  : {r.incident}\n")
    print(f"{green('[+]')} Summary written to: {summary_file}")


async def find_clean_binaries(clean_dir: Path) -> list[tuple[str, Path]]:
    """Discover clean binaries from a directory or use default system paths."""
    if clean_dir:
        if not clean_dir.exists():
            print(f"{yellow('[!]')} Clean binaries directory not found: {clean_dir}")
            return []
        binaries = []
        for fpath in clean_dir.iterdir():
            if fpath.is_file() and fpath.stat().st_mode & 0o111:
                binaries.append((fpath.name, fpath))
        return sorted(binaries[:30])

    # Default: search common system paths (deduped by name)
    found = []
    seen = set()
    for sysdir in ["/bin", "/usr/bin", "/usr/local/bin"]:
        for name in CLEAN_BINARIES:
            if name in seen:
                continue
            path = Path(sysdir) / name
            if path.exists():
                found.append((name, path))
                seen.add(name)
    return found


async def main():
    parser = argparse.ArgumentParser(
        description="SIFT-AID Full Demo Runner — forensic datasets & clean software validation"
    )
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--clean", action="store_true",
                        help="Run clean software false-positive validation")
    parser.add_argument("--all", action="store_true",
                        help="Run both forensic datasets and clean software validation")
    parser.add_argument("--clean-dir", type=Path, default=None,
                        help="Directory of clean binaries to test (default: /bin, /usr/bin)")
    args = parser.parse_args()

    load_env()
    os.environ.setdefault("LOG_LEVEL", args.log_level)
    os.environ.setdefault("PYTHONPATH", str(SCRIPT_DIR))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    banner("SIFT-AID — Full Demo Runner")

    venv_python = PYTHON if PYTHON.exists() else None
    if not venv_python:
        print(f"{yellow('[!]')} Virtual environment not found at {PYTHON}")
        print("    Falling back to system python.\n")

    results = []
    run_forensic = args.all or not (args.clean and not args.all)
    do_clean_test = args.clean or args.all

    if run_forensic:
        for ds in DATASETS:
            result = await run_test(ds)
            results.append(result)

    if do_clean_test:
        banner("CLEAN SOFTWARE FALSE-POSITIVE VALIDATION")
        clean_bins = await find_clean_binaries(args.clean_dir)
        if not clean_bins:
            print(f"{yellow('[!]')} No clean binaries found to test.\n")
        else:
            print(f"Found {len(clean_bins)} clean binaries to validate.\n")
            for name, path in clean_bins:
                result = await run_clean_test(name, path)
                results.append(result)

    if results:
        print_summary(results)
    else:
        print("No tests were run. Use --clean, --all, or no flags for forensic datasets.")


if __name__ == "__main__":
    asyncio.run(main())
