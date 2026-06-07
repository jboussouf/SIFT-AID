"""
EntropyAnalysisSpecialist — Shannon entropy analysis for packing/obfuscation detection.

Computes whole-file and per-block Shannon entropy to detect:
  - Packed/encrypted payloads (high entropy regions)
  - Obfuscated code (abnormally low entropy in code sections)
  - Suspicious entropy distributions

Pure Python — no external dependencies.
"""

import asyncio
import logging
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("sift_aid.specialists.entropy")

BLOCK_SIZE = 256


class EntropyAnalysisSpecialist:
    """Compute Shannon entropy metrics for a file. Fully read-only."""

    @staticmethod
    async def run(sample_path: str) -> dict:
        def _analyze():
            t0 = time.monotonic()
            p = Path(sample_path)

            if not p.exists():
                return {"error": f"File not found: {sample_path}"}

            data = p.read_bytes()
            file_size = len(data)

            if file_size == 0:
                return {
                    "file": str(p),
                    "file_entropy": 0.0,
                    "file_size": 0,
                    "note": "Empty file",
                    "elapsed_seconds": round(time.monotonic() - t0, 3),
                }
    
            file_entropy = EntropyAnalysisSpecialist._shannon_entropy(data)
    
            blocks = []
            high_entropy_blocks = 0
            low_entropy_blocks = 0
            for offset in range(0, file_size, BLOCK_SIZE):
                block = data[offset:offset + BLOCK_SIZE]
                if not block:
                    continue
                e = EntropyAnalysisSpecialist._shannon_entropy(block)
                blocks.append({
                    "offset": offset,
                    "size": len(block),
                    "entropy": round(e, 4),
                })
                if e > 0.85:
                    high_entropy_blocks += 1
                elif e < 0.2:
                    low_entropy_blocks += 1
    
            total_blocks = len(blocks)
            high_ratio = high_entropy_blocks / max(total_blocks, 1)
            low_ratio = low_entropy_blocks / max(total_blocks, 1)
    
            anomalies = []
    
            if file_entropy > 0.75:
                anomalies.append({
                    "type": "high_overall_entropy",
                    "detail": f"Overall file entropy {file_entropy:.3f} — suggests packed/encrypted payload",
                    "severity": "high",
                })
    
            if high_ratio > 0.3:
                anomalies.append({
                    "type": "many_high_entropy_blocks",
                    "detail": f"{high_entropy_blocks}/{total_blocks} blocks have entropy > 0.85 ({high_ratio:.1%})",
                    "severity": "high",
                })
    
            if file_entropy < 0.2 and file_size > 1024:
                anomalies.append({
                    "type": "very_low_entropy",
                    "detail": f"Overall entropy {file_entropy:.3f} is suspiciously low for a {file_size}-byte file",
                    "severity": "medium",
                })
    
            classification = "normal"
            if file_entropy > 0.75 or high_ratio > 0.3:
                classification = "high_entropy"
            elif file_entropy < 0.3 and file_size > 512:
                classification = "low_entropy"
    
            result: dict[str, Any] = {
                "file": str(p),
                "file_size": file_size,
                "file_entropy": round(file_entropy, 4),
                "block_count": total_blocks,
                "high_entropy_blocks": high_entropy_blocks,
                "low_entropy_blocks": low_entropy_blocks,
                "high_entropy_ratio": round(high_ratio, 4),
                "classification": classification,
                "anomalies": anomalies,
                "sample_blocks": blocks[:50] if len(blocks) <= 100 else blocks[:25] + blocks[-25:],
                "elapsed_seconds": round(time.monotonic() - t0, 3),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            log.info(
                "[EntropyAnalysisSpecialist] %s entropy=%.3f high_blocks=%d/%d class=%s",
                p.name, file_entropy, high_entropy_blocks, total_blocks, classification,
            )
            return result
            
        return await asyncio.to_thread(_analyze)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy / 8.0
