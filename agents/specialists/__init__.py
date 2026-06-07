"""
Specialist agents package.
Each specialist wraps exactly one MCP tool family.
"""

from agents.specialists.hash_specialist import HashSpecialist
from agents.specialists.yara_specialist import YARASpecialist
from agents.specialists.volatility_specialist import VolatilitySpecialist
from agents.specialists.ioc_specialist import IOCSpecialist
from agents.specialists.containment_specialist import ContainmentSpecialist
from agents.specialists.binary_analysis_specialist import BinaryAnalysisSpecialist
from agents.specialists.entropy_analysis_specialist import EntropyAnalysisSpecialist
from agents.specialists.network_intel_specialist import NetworkIntelSpecialist
from agents.specialists.vulnerability_check_specialist import VulnerabilityCheckSpecialist

__all__ = [
    "HashSpecialist",
    "YARASpecialist",
    "VolatilitySpecialist",
    "IOCSpecialist",
    "ContainmentSpecialist",
    "BinaryAnalysisSpecialist",
    "EntropyAnalysisSpecialist",
    "NetworkIntelSpecialist",
    "VulnerabilityCheckSpecialist",
]