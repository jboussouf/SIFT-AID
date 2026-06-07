"""
STIX 2.1 Bundle Generator — produces a valid STIX 2.1 JSON bundle for SOC ingestion.

Objects generated:
  - Malware (the analyzed sample)
  - Indicator (each unique IOC: file hash, IPv4, domain)
  - Attack-Pattern (each MITRE ATT&CK technique found)
  - Relationship (malware → indicators, malware → attack-patterns)

Usage:
    from pipeline.stix_exporter import STIXExporter
    bundle = STIXExporter.generate_stix_bundle(
        incident_id="INC-1234",
        sha256="abcd...",
        iocs={"ipv4": ["1.2.3.4"], "domain": ["evil.com"]},
        attack_techniques=[{"technique_id": "T1547.001", ...}],
    )
    STIXExporter.save_bundle(bundle, "/output/cases/INC-1234/report/stix_bundle.json")
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("sift_aid.stix_exporter")


class STIXExporter:
    """Generate and serialize STIX 2.1 bundles for SOC consumption."""

    STIX_VERSION = "2.1"

    @staticmethod
    def _make_id(prefix: str) -> str:
        return f"{prefix}--{uuid.uuid4().hex}"

    @staticmethod
    def _ts() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    @staticmethod
    def _make_malware(incident_id: str, sha256: str | None) -> dict:
        return {
            "type": "malware",
            "id": STIXExporter._make_id("malware"),
            "created": STIXExporter._ts(),
            "modified": STIXExporter._ts(),
            "name": f"Analyzed Sample [{incident_id}]",
            "description": f"Sample analyzed during incident {incident_id}",
            "malware_family": "Unknown/Suspected",
            "is_family": False,
            "external_references": [
                {
                    "source_name": "incident",
                    "external_id": incident_id,
                }
            ],
        }

    @staticmethod
    def _make_indicator(
        ioc_type: str, value: str, malware_id: str
    ) -> dict:
        if ioc_type == "sha256":
            pattern = f"[file:hashes.sha256 = '{value}']"
            name = f"File SHA-256: {value[:16]}..."
        elif ioc_type == "md5":
            pattern = f"[file:hashes.md5 = '{value}']"
            name = f"File MD5: {value[:16]}..."
        elif ioc_type == "ipv4":
            pattern = f"[ipv4-addr:value = '{value}']"
            name = f"IPv4: {value}"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{value}']"
            name = f"Domain: {value}"
        elif ioc_type == "url":
            pattern = f"[url:value = '{value}']"
            name = f"URL: {value[:60]}"
        elif ioc_type == "registry_key":
            # Escape backslashes for STIX pattern
            escaped = value.replace("\\", "\\\\")
            pattern = f"[windows-registry-key:key = '{escaped}']"
            name = f"Registry Key: {value}"
        else:
            pattern = f"[x-custom:ioc = '{value}']"
            name = f"IOC: {value[:60]}"

        return {
            "type": "indicator",
            "id": STIXExporter._make_id("indicator"),
            "created": STIXExporter._ts(),
            "modified": STIXExporter._ts(),
            "name": name,
            "description": f"IOC extracted during dynamic/static analysis: {value}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": STIXExporter._ts(),
        }

    @staticmethod
    def _make_attack_pattern(technique_id: str, name: str) -> dict:
        return {
            "type": "attack-pattern",
            "id": STIXExporter._make_id("attack-pattern"),
            "created": STIXExporter._ts(),
            "modified": STIXExporter._ts(),
            "name": name,
            "description": f"MITRE ATT&CK technique {technique_id}",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                }
            ],
        }

    @staticmethod
    def _make_relationship(
        source_ref: str, target_ref: str, rel_type: str
    ) -> dict:
        return {
            "type": "relationship",
            "id": STIXExporter._make_id("relationship"),
            "created": STIXExporter._ts(),
            "modified": STIXExporter._ts(),
            "relationship_type": rel_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
        }

    @staticmethod
    def generate_stix_bundle(
        incident_id: str,
        sha256: str | None = None,
        iocs: dict[str, list[str]] | None = None,
        attack_techniques: list[dict] | None = None,
    ) -> dict[str, Any]:
        """
        Build a complete STIX 2.1 bundle.

        Args:
            incident_id: Incident identifier (e.g. "INC-ABCD1234").
            sha256: SHA-256 hash of the sample (optional).
            iocs: Dict of IOC type -> list of values.
            attack_techniques: List of mapping dicts from AttackMapper.

        Returns:
            STIX 2.1 bundle dict ready for JSON serialization.
        """
        objects: list[dict] = []
        iocs = iocs or {}
        attack_techniques = attack_techniques or []

        # ── Malware object ────────────────────────────────────────────────
        malware = STIXExporter._make_malware(incident_id, sha256)
        malware_id = malware["id"]
        objects.append(malware)

        # ── Indicator objects ─────────────────────────────────────────────
        used_values: set[str] = set()
        indicator_ids: list[str] = []

        for ioc_type, values in iocs.items():
            for val in values:
                if val in used_values:
                    continue
                used_values.add(val)
                try:
                    indicator = STIXExporter._make_indicator(ioc_type, val, malware_id)
                    objects.append(indicator)
                    indicator_ids.append(indicator["id"])
                except Exception as e:
                    log.warning("[STIX] Skipping indicator %s=%s: %s", ioc_type, val, e)

        # Also add SHA-256 as an indicator if provided
        if sha256 and sha256 not in used_values:
            used_values.add(sha256)
            try:
                indicator = STIXExporter._make_indicator("sha256", sha256, malware_id)
                objects.append(indicator)
                indicator_ids.append(indicator["id"])
            except Exception as e:
                log.warning("[STIX] Skipping SHA-256 indicator: %s", e)

        # ── Relationship: malware → indicator ─────────────────────────────
        for ind_id in indicator_ids:
            objects.append(
                STIXExporter._make_relationship(
                    source_ref=malware_id,
                    target_ref=ind_id,
                    rel_type="indicates",
                )
            )

        # ── Attack-Pattern objects ────────────────────────────────────────
        seen_tech_ids: set[str] = set()
        pattern_ids: list[str] = []

        for tech in attack_techniques:
            tech_id = tech.get("technique_id", "")
            if tech_id in seen_tech_ids:
                continue
            seen_tech_ids.add(tech_id)

            try:
                ap = STIXExporter._make_attack_pattern(
                    tech_id, tech.get("name", tech_id)
                )
                objects.append(ap)
                pattern_ids.append(ap["id"])
            except Exception as e:
                log.warning("[STIX] Skipping attack-pattern %s: %s", tech_id, e)

        # ── Relationship: malware → attack-pattern ────────────────────────
        for ap_id in pattern_ids:
            objects.append(
                STIXExporter._make_relationship(
                    source_ref=malware_id,
                    target_ref=ap_id,
                    rel_type="uses",
                )
            )

        bundle = {
            "type": "bundle",
            "id": STIXExporter._make_id("bundle"),
            "spec_version": STIXExporter.STIX_VERSION,
            "created": STIXExporter._ts(),
            "modified": STIXExporter._ts(),
            "objects": objects,
        }

        log.info(
            "[STIX] Bundle generated: %d objects (%d indicators, %d attack-patterns, %d malware, %d relationships)",
            len(objects),
            len(indicator_ids),
            len(pattern_ids),
            1,
            len(indicator_ids) + len(pattern_ids),
        )
        return bundle

    @staticmethod
    def save_bundle(bundle: dict, output_path: str | Path) -> str:
        """Serialize and save the STIX bundle to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
        log.info("[STIX] Bundle saved to %s", path)
        return str(path)
