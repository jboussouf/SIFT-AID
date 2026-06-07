"""
Test suite for SIFT-AID
============================
Tests run against synthetic evidence to avoid requiring real malware samples.
All tests are deterministic and offline (no VT API needed).
"""

import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

# Set test environment before any imports
os.environ.setdefault("EVIDENCE_ROOT", "/tmp/test_evidence")
os.environ.setdefault("CASES_DIR", "/tmp/test_cases")
os.environ.setdefault("YARA_RULES_DIR", str(Path(__file__).parent.parent / "yara_rules"))
os.environ.setdefault("VT_API_KEY", "")
os.environ.setdefault("TOOL_TIMEOUT", "30")


# ── Fixtures ──────────────────────────────────────────────────────────────────
@pytest.fixture
def sample_pe_bytes() -> bytes:
    """Minimal fake PE with MZ header for testing (not a real executable)."""
    mz = b"MZ" + b"\x00" * 60 + b"\x40" + b"\x00" * 3  # MZ + e_lfanew = 0x40
    pe_sig = b"PE\x00\x00"
    fake_payload = b"IsDebuggerPresent\x00WriteProcessMemory\x00VirtualAlloc\x00"
    fake_payload += b"https://evil.example.com/payload.exe\x00"
    fake_payload += b"YOUR FILES HAVE BEEN ENCRYPTED\x00"
    return mz + b"\x00" * 56 + pe_sig + b"\x00" * 256 + fake_payload


@pytest.fixture
def tmp_evidence_dir(tmp_path, sample_pe_bytes):
    """Temp directory with a fake malware sample."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    sample_file = evidence_dir / "test_sample.bin"
    sample_file.write_bytes(sample_pe_bytes)
    return evidence_dir, sample_file


# ── Hash Specialist tests ──────────────────────────────────────────────────────
class TestHashSpecialist:
    @pytest.mark.asyncio
    async def test_compute_hash_returns_sha256(self, tmp_evidence_dir):
        from agents.specialists.hash_specialist import HashSpecialist
        _, sample_file = tmp_evidence_dir
        result = await HashSpecialist.run(str(sample_file))

        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert "hashes" in result
        assert "sha256" in result["hashes"]
        assert len(result["hashes"]["sha256"]) == 64  # hex SHA-256

    @pytest.mark.asyncio
    async def test_hash_sha256_is_correct(self, tmp_evidence_dir, sample_pe_bytes):
        from agents.specialists.hash_specialist import HashSpecialist
        _, sample_file = tmp_evidence_dir
        result = await HashSpecialist.run(str(sample_file))

        expected = hashlib.sha256(sample_pe_bytes).hexdigest()
        assert result["hashes"]["sha256"] == expected

    @pytest.mark.asyncio
    async def test_hash_missing_file_returns_error(self):
        from agents.specialists.hash_specialist import HashSpecialist
        result = await HashSpecialist.run("/nonexistent/path/file.exe")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_vt_offline_mode(self):
        from agents.specialists.hash_specialist import HashSpecialist
        result = await HashSpecialist.query_vt("a" * 64)
        # With no API key, should return offline_mode gracefully
        assert result.get("status") in ("offline_mode", "not_found", "found") or "error" in result


# ── YARA Specialist tests ──────────────────────────────────────────────────────
class TestYARASpecialist:
    @pytest.mark.asyncio
    async def test_yara_returns_structured_result(self, tmp_evidence_dir):
        from agents.specialists.yara_specialist import YARASpecialist
        _, sample_file = tmp_evidence_dir
        rules_dir = str(Path(__file__).parent.parent / "yara_rules")

        result = await YARASpecialist.run(str(sample_file), rules_dir=rules_dir)

        assert "match_count" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)

    @pytest.mark.asyncio
    async def test_yara_missing_target_returns_error(self):
        from agents.specialists.yara_specialist import YARASpecialist
        result = await YARASpecialist.run("/nonexistent/file.bin")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_yara_missing_rules_dir_returns_warning(self, tmp_evidence_dir):
        from agents.specialists.yara_specialist import YARASpecialist
        _, sample_file = tmp_evidence_dir
        result = await YARASpecialist.run(str(sample_file), rules_dir="/nonexistent_rules")
        assert "warning" in result or "error" in result


# ── IOC Specialist tests ───────────────────────────────────────────────────────
class TestIOCSpecialist:
    @pytest.mark.asyncio
    async def test_extracts_url_from_file(self, tmp_evidence_dir, sample_pe_bytes):
        from agents.specialists.ioc_specialist import IOCSpecialist
        _, sample_file = tmp_evidence_dir
        result = await IOCSpecialist.run(str(sample_file))

        assert "total_iocs" in result
        assert "iocs" in result
        # Our fake PE has a URL in it
        urls = result["iocs"].get("url", [])
        assert any("evil.example.com" in u for u in urls), f"Expected URL not found. Got: {urls}"

    @pytest.mark.asyncio
    async def test_ioc_missing_file_returns_error(self):
        from agents.specialists.ioc_specialist import IOCSpecialist
        result = await IOCSpecialist.run("/nonexistent/file.bin")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_ioc_filters_private_ips(self, tmp_path):
        from agents.specialists.ioc_specialist import IOCSpecialist
        f = tmp_path / "test.txt"
        f.write_text("192.168.1.1 10.0.0.1 8.8.8.8 1.2.3.4")
        result = await IOCSpecialist.run(str(f))
        ips = result["iocs"].get("ipv4", [])
        assert "192.168.1.1" not in ips, "Private IP should be filtered"
        assert "10.0.0.1" not in ips, "Private IP should be filtered"
        assert "8.8.8.8" in ips or "1.2.3.4" in ips, "Public IPs should be present"


# ── Containment Specialist tests ───────────────────────────────────────────────
class TestContainmentSpecialist:
    @pytest.mark.asyncio
    async def test_generates_iptables_rules(self):
        from agents.specialists.containment_specialist import ContainmentSpecialist
        result = await ContainmentSpecialist.run(
            ips=["1.2.3.4", "5.6.7.8"],
            domains=["evil.example.com"],
        )

        assert "iptables_rules" in result
        assert len(result["iptables_rules"]) > 0
        assert any("1.2.3.4" in r for r in result["iptables_rules"])
        assert "disclaimer" in result

    @pytest.mark.asyncio
    async def test_never_applies_rules(self):
        """
        Architectural constraint: ContainmentSpecialist must ONLY return text.
        It must not call subprocess or any system interface.
        Verify by checking the function has no subprocess calls in its source.
        """
        import inspect
        from agents.specialists import containment_specialist
        source = inspect.getsource(containment_specialist)
        assert "subprocess" not in source, "ContainmentSpecialist must not use subprocess"
        assert "os.system" not in source, "ContainmentSpecialist must not use os.system"
        assert "iptables" not in source.lower() or "iptables_rules" in source, \
            "iptables should only appear in output dict keys, not as a command"

    @pytest.mark.asyncio
    async def test_caps_ip_list(self):
        from agents.specialists.containment_specialist import ContainmentSpecialist
        ips = [f"1.2.3.{i}" for i in range(200)]  # 200 IPs
        result = await ContainmentSpecialist.run(ips=ips, domains=[])
        # Rules should be capped at 100 IPs × 2 rules = 200 rules max
        assert len(result["iptables_rules"]) <= 200


# ── Orchestrator state schema tests ───────────────────────────────────────────
class TestOrchestratorState:
    def test_run_triage_function_exists(self):
        from agents.orchestrator import run_triage
        assert callable(run_triage)

    def test_build_graph_produces_compiled_graph(self):
        from agents.orchestrator import build_graph
        graph = build_graph()
        assert graph is not None

    def test_agent_state_keys(self):
        from agents.orchestrator import AgentState
        expected_keys = {
            "incident_id", "session_start", "sample_path", "memory_image_path",
            "iteration", "max_iterations", "node_timings", "errors",
            "hash_results", "vt_results", "yara_results", "volatility_results",
            "ioc_results", "dynamic_results", "firewall_rules",
            "findings", "inferences",
            "confidence_score", "static_confidence_score", "dynamic_confidence_score",
            "validation_delta", "hallucination_flags", "verdict",
            "needs_correction", "correction_reason", "status", "plan", "report_paths",
            "llm_analysis", "sandbox_actions_requested", "llm_iteration", "max_llm_iterations",
            "attack_techniques", "ioc_memory_warnings",
            "network_intel_results", "output_agent", "llm_model",
            "binary_analysis_results", "vulnerability_results", "entropy_results"
        }
        # AgentState is a TypedDict — check annotations
        assert expected_keys == set(AgentState.__annotations__.keys())


# ── Reporter tests ─────────────────────────────────────────────────────────────
class TestReporter:
    @pytest.mark.asyncio
    async def test_report_generates_both_outputs(self, tmp_path):
        from pipeline.reporter import Reporter

        reporter = Reporter(incident_id="TEST-001", cases_dir=tmp_path)
        fake_state = {
            "incident_id": "TEST-001",
            "session_start": "2024-01-01T00:00:00Z",
            "sample_path": "/cases/test.exe",
            "memory_image_path": None,
            "status": "completed",
            "iteration": 1,
            "max_iterations": 3,
            "node_timings": {"ingest": 0.1, "validate": 0.5},
            "confidence_score": 0.85,
            "validation_delta": 0.15,
            "findings": [{"type": "YARA_MATCH", "confidence": 0.90, "rule": "Test_Rule", "source": "run_yara_scan"}],
            "inferences": [],
            "hallucination_flags": [],
            "hash_results": {"file": "/cases/test.exe", "size_bytes": 1024, "hashes": {"sha256": "abc123"}},
            "vt_results": {"status": "offline_mode"},
            "yara_results": {"match_count": 1, "matches": []},
            "volatility_results": {},
            "ioc_results": {"total_iocs": 3, "ioc_types_found": ["url"], "iocs": {"url": ["http://evil.com"]}},
            "firewall_rules": {"disclaimer": "REVIEW BEFORE APPLYING", "iptables_rules": [], "hosts_file_entries": [],
                               "ioc_summary": {"ip_count": 0, "domain_count": 0}},
            "errors": [],
        }

        paths = await reporter.generate(fake_state)

        assert "json" in paths
        assert "markdown" in paths
        assert Path(paths["json"]).exists()
        assert Path(paths["markdown"]).exists()

        # Verify JSON is valid
        with open(paths["json"]) as f:
            data = json.load(f)
        assert data["incident"]["id"] == "TEST-001"
        assert "confirmed_findings" in data
        assert "inferences" in data

        # Verify MD has key sections
        md_content = Path(paths["markdown"]).read_text()
        assert "Confirmed Findings" in md_content
        assert "Inferences" in md_content
        assert "REVIEW BEFORE APPLYING" in md_content


# ── Audit Logger tests ─────────────────────────────────────────────────────────
class TestAuditLogger:
    def test_creates_trace_file(self, tmp_path):
        from pipeline.audit_logger import AuditLogger
        logger = AuditLogger(incident_id="AUDIT-001", cases_dir=tmp_path)
        trace = tmp_path / "AUDIT-001" / "logs" / "execution_trace.jsonl"
        assert trace.exists()

    def test_appends_records(self, tmp_path):
        from pipeline.audit_logger import AuditLogger
        logger = AuditLogger(incident_id="AUDIT-002", cases_dir=tmp_path)
        logger.log_tool_call("test_tool", {"arg": "val"}, {"result": "ok"}, 0.5)
        logger.log_finding({"type": "TEST"}, confirmed=True, source_tool="test_tool")

        trace = tmp_path / "AUDIT-002" / "logs" / "execution_trace.jsonl"
        lines = trace.read_text().strip().splitlines()
        records = [json.loads(l) for l in lines]
        events = [r["event"] for r in records]

        assert "session_start" in events
        assert "tool_call" in events
        assert "finding" in events
