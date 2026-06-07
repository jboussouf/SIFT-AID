"""
test_clean_elf.py — False-positive validation on clean ELF binaries
===================================================================
Tests that the pipeline correctly classifies known-clean binaries as
BENIGN or ANALYST REVIEW with near-0 findings.

Uses /bin/ls (or a compiled "Hello World" C program) as the test sample.
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault("USE_MOCK_SANDBOX", "True")
os.environ.setdefault("CASES_DIR", "/tmp/test_clean_cases")
os.environ.setdefault("YARA_RULES_DIR", str(Path(__file__).parent.parent / "yara_rules"))
os.environ.setdefault("VT_API_KEY", "")
os.environ.setdefault("TOOL_TIMEOUT", "30")
os.environ.setdefault("NODE_TIMEOUT", "30")
os.environ.setdefault("PYTHONPATH", str(Path(__file__).parent.parent))


@pytest.fixture(scope="module")
def clean_elf_path() -> Path:
    """Use /bin/ls as a known-clean ELF binary, or compile a minimal one."""
    ls_path = Path("/bin/ls")
    if ls_path.exists():
        return ls_path
    # Fallback: compile a minimal "Hello World" C program
    c_code = (
        '#include <stdio.h>\n'
        'int main() { printf("Hello, World!\\n"); return 0; }\n'
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "test_clean.c"
        src.write_text(c_code)
        out = Path(tmp) / "test_clean"
        subprocess.run(
            ["gcc", "-o", str(out), str(src)],
            capture_output=True, check=True,
        )
        return out


@pytest.fixture(scope="module")
def clean_results(clean_elf_path) -> dict:
    """Run the full orchestrator pipeline on the clean ELF binary."""
    from agents.orchestrator import run_triage

    result = asyncio.run(run_triage(
        sample_path=str(clean_elf_path),
        incident_id="CLEAN_ELF_TEST",
    ))
    return result


class TestCleanELFValidation:
    """Verify clean ELF binaries are not falsely flagged as malicious."""

    def test_pipeline_completes(self, clean_results):
        assert "errors" in clean_results
        assert "findings" in clean_results
        assert "confidence_score" in clean_results

    def test_no_confirmed_findings(self, clean_results):
        findings = clean_results.get("findings", [])
        assert len(findings) == 0, (
            f"Expected 0 confirmed findings on clean ELF, got {len(findings)}: "
            + json.dumps(findings, indent=2)
        )

    def test_verdict_is_not_malicious(self, clean_results):
        verdict = clean_results.get("verdict", clean_results.get("status", ""))
        assert verdict in ("BENIGN", "ANALYST REVIEW", "SUSPICIOUS"), (
            f"Clean ELF should not be MALICIOUS. Got verdict: {verdict}"
        )

    def test_confidence_below_threshold(self, clean_results):
        confidence = clean_results.get("confidence_score", 1.0)
        assert confidence < 0.4, (
            f"Confidence on clean ELF should be < 0.4, got {confidence:.3f}"
        )

    def test_no_high_severity_yara_matches(self, clean_results):
        yara_r = clean_results.get("yara_results", {})
        for match in yara_r.get("matches", []):
            severity = match.get("severity", match.get("meta", {}).get("severity", "unknown"))
            assert severity not in ("critical", "high"), (
                f"Clean ELF triggered high-severity YARA rule: {match.get('rule')}"
            )


class TestCleanIOCFiltering:
    """Verify IOC specialist filters benign noise from clean ELF binaries."""

    @pytest.mark.asyncio
    async def test_ioc_filter_benign_domains(self, tmp_path):
        from agents.specialists.ioc_specialist import IOCSpecialist

        f = tmp_path / "test_elf.txt"
        f.write_text(
            "GLIBC_2.2.5 http://www.w3.org/1999/xhtml 192.168.1.1 "
            "/lib/x86_64-linux-gnu/libc.so.6 iana.org __libc_start_main"
        )
        result = await IOCSpecialist.run(str(f))
        total = result.get("total_iocs", 0)
        assert total == 0, (
            f"Expected 0 IOCs from benign noise, got {total}: {result.get('iocs', {})}"
        )

    @pytest.mark.asyncio
    async def test_ioc_keeps_suspicious_indicators(self, tmp_path):
        from agents.specialists.ioc_specialist import IOCSpecialist

        f = tmp_path / "test_malicious.txt"
        f.write_text(
            "http://evil-c2.example.com/checkin 198.51.100.2 "
            "malware.example.com 5.6.7.8"
        )
        result = await IOCSpecialist.run(str(f))
        ips = result.get("iocs", {}).get("ipv4", [])
        domains = result.get("iocs", {}).get("domain", [])
        assert any("198.51.100.2" in ip for ip in ips), (
            f"Public IP 198.51.100.2 should be present. Got IPs: {ips}"
        )
        assert any("evil-c2.example.com" in d for d in domains), (
            f"Suspicious domain should be present. Got domains: {domains}"
        )


class TestCleanOrchestratorConfidence:
    """Verify the recalibrated confidence scoring on clean results."""

    def test_heuristic_low_signal_cap(self):
        from agents.orchestrator import _heuristic_analysis

        # Only low-severity YARA signal — should be capped at 0.3
        static = {
            "hash_vt": {"malicious": 0, "suspicious": 0},
            "yara": {
                "match_count": 1,
                "matches": [{"rule": "Generic_Test", "severity": "low"}],
            },
            "iocs": {"total_iocs": 0},
            "volatility": {},
        }
        dynamic = {"confidence_boost": 0.0, "network_iocs": [], "dropped_files": []}

        result = _heuristic_analysis(static, dynamic)
        assert result["static_confidence_score"] <= 0.3, (
            f"Low-signal heuristic should be capped at 0.3, got {result['static_confidence_score']}"
        )

    def test_corroboration_bonus(self):
        from agents.orchestrator import _heuristic_analysis

        # YARA high + suspicious IOCs = corroboration bonus
        static = {
            "hash_vt": {"malicious": 10, "suspicious": 0},
            "yara": {
                "match_count": 1,
                "matches": [{"rule": "Malicious_Rule", "severity": "high"}],
            },
            "iocs": {"total_iocs": 15},
            "volatility": {},
        }
        dynamic = {"confidence_boost": 0.0, "network_iocs": [], "dropped_files": []}

        result = _heuristic_analysis(static, dynamic)
        assert result["static_confidence_score"] > 0.3, (
            f"Corroborated signals should exceed 0.3, got {result['static_confidence_score']}"
        )
