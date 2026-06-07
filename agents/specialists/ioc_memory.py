"""
IOC Memory — persistent LanceDB-backed IOC history across incidents.

Uses LanceDB (disk-based, zero-server vector store) to store and query
IOC values seen in previous triage runs. Enables "seen before" signals
that inform analysts of cross-incident IOC overlap.

Schema:
    ioc_value     (str)  — the raw IOC string
    ioc_type      (str)  — e.g. "ipv4", "domain", "registry_key", "sha256"
    incident_id   (str)  — originating incident
    timestamp     (str)  — ISO-8601 when first seen

Usage:
    from agents.specialists.ioc_memory import IOCMemory

    # Check for previously seen IOCs
    warnings = IOCMemory.check_ioc_history(incident_id, iocs)

    # Save current incident's IOCs for future lookups
    IOCMemory.save_ioc_history(incident_id, iocs)
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("sift_aid.ioc_memory")

IOC_DB_PATH = Path(os.environ.get("IOC_DB_PATH", "output/ioc_history.lance"))


class IOCMemory:

    TABLE_NAME = "ioc_history"

    @staticmethod
    def _connect():
        """Open or create the LanceDB database and return the table."""
        import lancedb

        db_path = IOC_DB_PATH
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db = lancedb.connect(str(db_path))

        try:
            table = db.open_table(IOCMemory.TABLE_NAME)
        except Exception:
            from lancedb.pydantic import LanceModel, Vector
            from pydantic import Field

            class IOCRecord(LanceModel):
                ioc_value: str = Field(...)
                ioc_type: str = Field(...)
                incident_id: str = Field(...)
                timestamp: str = Field(...)

            table = db.create_table(IOCMemory.TABLE_NAME, schema=IOCRecord, mode="create")
            log.info("[IOCMemory] Created new table '%s' at %s", IOCMemory.TABLE_NAME, db_path)

        return table

    @staticmethod
    def check_ioc_history(
        incident_id: str,
        iocs: dict[str, list[str]] | None = None,
    ) -> list[dict]:
        """
        Query LanceDB for any IOCs that appeared in previous incidents.

        Args:
            incident_id: Current incident ID (excluded from results).
            iocs: Dict of IOC type -> list of values (same structure as ioc_results.iocs).

        Returns:
            List of warning dicts:
            [{"ioc_value": "1.2.3.4", "ioc_type": "ipv4",
              "previous_incident": "INC-ABCD1234", "first_seen": "..."}]
        """
        if not iocs:
            return []

        warnings: list[dict] = []
        seen_values: set[str] = set()

        # Flatten current IOCs into a set for quick lookup
        current_values: set[str] = set()
        for values in iocs.values():
            for v in values:
                current_values.add(v)

        if not current_values:
            return []

        try:
            table = IOCMemory._connect()
            if table.count_rows() == 0:
                return []

            data = table.to_pandas()
            if data.empty:
                return []

            # Filter: rows where ioc_value is in our current set AND incident_id differs
            mask = data["ioc_value"].isin(current_values) & (data["incident_id"] != incident_id)
            matches = data[mask]

            for _, row in matches.iterrows():
                key = f"{row['ioc_value']}@{row['incident_id']}"
                if key in seen_values:
                    continue
                seen_values.add(key)
                warnings.append({
                    "ioc_value": row["ioc_value"],
                    "ioc_type": row["ioc_type"],
                    "previous_incident": row["incident_id"],
                    "first_seen": row["timestamp"],
                })

            if warnings:
                log.info("[IOCMemory] Found %d IOC matches across incidents", len(warnings))

        except Exception as e:
            log.warning("[IOCMemory] check_ioc_history failed: %s", e)

        return warnings

    @staticmethod
    def save_ioc_history(
        incident_id: str,
        iocs: dict[str, list[str]] | None = None,
    ) -> None:
        """
        Persist the current incident's IOCs to LanceDB for future lookups.

        Args:
            incident_id: Current incident identifier.
            iocs: Dict of IOC type -> list of values.
        """
        if not iocs:
            return

        records: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        for ioc_type, values in iocs.items():
            for val in values:
                if not val or not val.strip():
                    continue
                records.append({
                    "ioc_value": val.strip(),
                    "ioc_type": ioc_type,
                    "incident_id": incident_id,
                    "timestamp": now,
                })

        if not records:
            return

        try:
            table = IOCMemory._connect()
            table.add(records)
            log.info("[IOCMemory] Saved %d IOC records for incident %s", len(records), incident_id)
        except Exception as e:
            log.warning("[IOCMemory] save_ioc_history failed: %s", e)
