"""
MITRE ATT&CK Mapper — local, lightweight mapping of extracted DFIR artifacts
to ATT&CK technique IDs. No external API calls; uses an embedded dictionary.

Usage:
    from agents.specialists.attack_mapper import AttackMapper
    techniques = AttackMapper.map_to_attack(
        findings=state["findings"],
        iocs=state.get("ioc_results", {}).get("iocs", {}),
        process_tree=state.get("dynamic_results", {}).get("process_tree", []),
        network_iocs=state.get("dynamic_results", {}).get("network_iocs", []),
        existing_attack_ids=state.get("dynamic_results", {}).get("attack_techniques", []),
    )
"""

import logging
import re

log = logging.getLogger("sift_aid.attack_mapper")


class AttackMapper:

    TECHNIQUE_NAMES: dict[str, str] = {
        "T1055": "Process Injection",
        "T1055.012": "Process Injection: Process Hollowing",
        "T1056.001": "Input Capture: Keylogging",
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "Command and Scripting Interpreter: PowerShell",
        "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
        "T1059.005": "Command and Scripting Interpreter: Visual Basic",
        "T1059.006": "Command and Scripting Interpreter: Python",
        "T1059.007": "Command and Scripting Interpreter: JavaScript",
        "T1053.005": "Scheduled Task/Job: Scheduled Task",
        "T1069": "Permission Groups Discovery",
        "T1071": "Application Layer Protocol",
        "T1071.001": "Application Layer Protocol: Web Protocols",
        "T1071.004": "Application Layer Protocol: DNS",
        "T1071.005": "Application Layer Protocol: File Transfer Protocols",
        "T1082": "System Information Discovery",
        "T1087.001": "Account Discovery: Local Account",
        "T1003.001": "OS Credential Dumping: LSASS Memory",
        "T1033": "System Owner/User Discovery",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1095": "Non-Application Layer Protocol",
        "T1112": "Modify Registry",
        "T1189": "Drive-by Compromise",
        "T1190": "Exploit Public-Facing Application",
        "T1204.002": "User Execution: Malicious File",
        "T1218.005": "System Binary Proxy Execution: Mshta",
        "T1218.010": "System Binary Proxy Execution: Regsvr32",
        "T1218.011": "System Binary Proxy Execution: Rundll32",
        "T1543.003": "Create or Modify System Process: Windows Service",
        "T1546": "Event Triggered Execution",
        "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "T1547.009": "Boot or Logon Autostart Execution: Shortcut Modification",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1562.001": "Impair Defenses: Disable or Modify Tools",
        "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
        "T1566": "Phishing",
        "T1574.002": "Hijack Execution Flow: DLL Side-Loading",
    }

    PROCESS_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"powershell(_ise)?\.exe", re.I), "T1059.001"),
        (re.compile(r"cmd\.exe", re.I), "T1059.003"),
        (re.compile(r"wscript\.exe", re.I), "T1059.005"),
        (re.compile(r"cscript\.exe", re.I), "T1059.005"),
        (re.compile(r"mshta\.exe", re.I), "T1218.005"),
        (re.compile(r"regsvr32\.exe", re.I), "T1218.010"),
        (re.compile(r"rundll32\.exe", re.I), "T1218.011"),
        (re.compile(r"python\.exe", re.I), "T1059.006"),
        (re.compile(r"node\.exe", re.I), "T1059.007"),
        (re.compile(r"svchost\.exe", re.I), "T1055"),
    ]

    REGISTRY_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"CurrentVersion\\\\Run", re.I), "T1547.001"),
        (re.compile(r"CurrentVersion\\\\RunOnce", re.I), "T1547.001"),
        (re.compile(r"CurrentVersion\\\\RunServices", re.I), "T1547.001"),
        (re.compile(r"SYSTEM\\\\CurrentControlSet\\\\Services", re.I), "T1543.003"),
        (re.compile(r"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies", re.I), "T1112"),
        (re.compile(r"CurrentVersion\\\\Explorer\\\\User Shell Folders", re.I), "T1547.001"),
        (re.compile(r"CurrentVersion\\\\Explorer\\\\Shell Folders", re.I), "T1547.001"),
    ]

    FINDING_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"MEMORY_INJECTION", re.I), "T1055"),
        (re.compile(r"DYNAMIC_BEHAVIOR", re.I), "T1204.002"),
        (re.compile(r"HASH_MALICIOUS", re.I), "T1204.002"),
        (re.compile(r"HASH_SUSPICIOUS", re.I), "T1204.002"),
        (re.compile(r"BINARY_PACKER", re.I), "T1027"),
        (re.compile(r"HIGH_ENTROPY_PAYLOAD", re.I), "T1027.002"),
        (re.compile(r"SUSPICIOUS_IMPORTS", re.I), "T1055"),
        (re.compile(r"VULNERABLE_LIBRARY", re.I), "T1195.002"),
        (re.compile(r"MALICIOUS_DOMAIN_LOOKUP", re.I), "T1071.001"),
        (re.compile(r"MALICIOUS_IP_LOOKUP", re.I), "T1071.001"),
        (re.compile(r"SUSPICIOUS_DOMAIN_AGE", re.I), "T1071.001"),
    ]

    IOC_TYPE_MAP: dict[str, str] = {
        "ipv4": "T1071.001",
        "domain": "T1071.001",
        "url": "T1071.001",
        "registry_key": "T1112",
        "mutex": "T1055",
    }

    SIGNATURE_KEYWORDS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"mimikatz", re.I), "T1003.001"),
        (re.compile(r"key.log", re.I), "T1056.001"),
        (re.compile(r"injection", re.I), "T1055"),
        (re.compile(r"hollowing", re.I), "T1055.012"),
        (re.compile(r"modif(y|ies).*(proxy|registry)", re.I), "T1112"),
        (re.compile(r"disab.*(firewall|defender|tool)", re.I), "T1562.001"),
        (re.compile(r"creat.*service", re.I), "T1543.003"),
        (re.compile(r"scheduled.?task", re.I), "T1053.005"),
        (re.compile(r"dll.?side.?load", re.I), "T1574.002"),
        (re.compile(r"uac.?bypass", re.I), "T1548"),
        (re.compile(r"ftp", re.I), "T1048"),
        (re.compile(r"systeminfo", re.I), "T1082"),
        (re.compile(r"whoami", re.I), "T1033"),
        (re.compile(r"net\s+(user|group)", re.I), "T1087.001"),
    ]

    @staticmethod
    def _name(technique_id: str) -> str:
        return AttackMapper.TECHNIQUE_NAMES.get(technique_id, technique_id)

    @staticmethod
    def map_to_attack(
        behavior_list: list | None = None,
        iocs: dict | None = None,
        process_tree: list | None = None,
        network_iocs: list | None = None,
        findings: list | None = None,
        existing_attack_ids: list | None = None,
    ) -> list[dict]:
        """
        Map DFIR artifacts to MITRE ATT&CK techniques.

        Args:
            behavior_list: Generic list of behavior strings (fallback).
            iocs: Dict of IOC types to values, e.g. {"ipv4": [...], "registry_key": [...]}.
            process_tree: List of process dicts with "process_name" key.
            network_iocs: List of network indicators (IPs, domains, URLs).
            findings: List of finding dicts from the orchestrator.
            existing_attack_ids: Already-mapped technique ID strings from sandbox.

        Returns:
            List of deduplicated dicts:
            [{"technique_id": "T1547.001", "name": "...", "evidence": "..."}]
        """
        seen: dict[str, dict] = {}
        evidence_notes: list[str] = []

        # ── 1. Map process names ──────────────────────────────────────────
        if process_tree:
            for proc in process_tree:
                pname = (proc.get("process_name") or "").strip()
                if not pname:
                    continue
                for pattern, tech_id in AttackMapper.PROCESS_PATTERNS:
                    if pattern.search(pname):
                        if tech_id not in seen:
                            seen[tech_id] = {
                                "technique_id": tech_id,
                                "name": AttackMapper._name(tech_id),
                                "evidence": f"Process: {pname}",
                            }
                        else:
                            seen[tech_id]["evidence"] += f", {pname}"
                        break

        # ── 2. Map registry key IOCs ──────────────────────────────────────
        if iocs:
            for ioc_type, values in iocs.items():
                if ioc_type == "registry_key" and values:
                    for val in values:
                        for pattern, tech_id in AttackMapper.REGISTRY_PATTERNS:
                            if pattern.search(val):
                                entry = AttackMapper._ensure_entry(seen, tech_id)
                                entry["evidence"] += f", {val}"
                                break

        # ── 3. Map IOC types → default techniques ─────────────────────────
        if iocs:
            for ioc_type, tech_id in AttackMapper.IOC_TYPE_MAP.items():
                values = iocs.get(ioc_type, [])
                if values:
                    entry = AttackMapper._ensure_entry(seen, tech_id)
                    entry["evidence"] += f" ({len(values)} {ioc_type} IOCs)"

        # ── 4. Map network indicators ─────────────────────────────────────
        if network_iocs:
            for nioc in network_iocs:
                nioc_lower = nioc.lower().strip()
                if nioc_lower.startswith("http://") or nioc_lower.startswith("https://"):
                    AttackMapper._ensure_entry(seen, "T1071.001")["evidence"] += f", {nioc}"
                elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", nioc_lower):
                    AttackMapper._ensure_entry(seen, "T1071.001")["evidence"] += f", {nioc}"
                elif "." in nioc_lower and not nioc_lower.startswith("http"):
                    AttackMapper._ensure_entry(seen, "T1071.001")["evidence"] += f", {nioc}"

        # ── 5. Map findings ───────────────────────────────────────────────
        if findings:
            for finding in findings:
                finding_type = (finding.get("type") or "").strip()
                for pattern, tech_id in AttackMapper.FINDING_PATTERNS:
                    if pattern.search(finding_type):
                        entry = AttackMapper._ensure_entry(seen, tech_id)
                        entry["evidence"] += f" ({finding_type})"
                        break

        # ── 6. Map from behavior list (fallback strings) ──────────────────
        if behavior_list:
            for item in behavior_list:
                item_str = str(item)
                for pattern, tech_id in AttackMapper.SIGNATURE_KEYWORDS:
                    if pattern.search(item_str):
                        AttackMapper._ensure_entry(seen, tech_id)["evidence"] += f", {item_str[:80]}"
                        break

        # ── 7. Preserve already-known attack IDs from sandbox ─────────────
        if existing_attack_ids:
            for tech_id in existing_attack_ids:
                if tech_id not in seen:
                    seen[tech_id] = {
                        "technique_id": tech_id,
                        "name": AttackMapper._name(tech_id),
                        "evidence": "CAPE sandbox signature match",
                    }

        # ── Clean up evidence strings ─────────────────────────────────────
        result = []
        for entry in seen.values():
            evidence = entry["evidence"].lstrip(", ").strip()
            if not evidence:
                evidence = "Automated mapping"
            result.append({
                "technique_id": entry["technique_id"],
                "name": entry["name"],
                "evidence": evidence,
            })

        return sorted(result, key=lambda x: x["technique_id"])

    @staticmethod
    def _ensure_entry(seen: dict[str, dict], tech_id: str) -> dict:
        if tech_id not in seen:
            seen[tech_id] = {
                "technique_id": tech_id,
                "name": AttackMapper._name(tech_id),
                "evidence": "",
            }
        return seen[tech_id]
