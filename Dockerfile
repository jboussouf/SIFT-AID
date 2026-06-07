# SIFT-AID Dockerfile
# Base: python:3.11-slim — smaller, faster build, no apt Python needed
# Evidence is mounted READ-ONLY at /cases — container can never modify originals.

FROM python:3.11-slim

LABEL maintainer="SIFT-AID Team"
LABEL description="Autonomous Malware Triage & Containment Agent — FIND EVIL! Hackathon"
LABEL version="1.0.0"

# ── System packages ─────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    yara \
    binutils \
    file \
    bsdmainutils \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ── uv for fast dependency management ───────────────────────────────────────
RUN pip install --no-cache-dir uv

# ── Working directory ────────────────────────────────────────────────────────
WORKDIR /sift-aid

# ── Install Python dependencies via uv ──────────────────────────────────────
COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

# ── Volatility 3 (installed from pip) ───────────────────────────────────────
RUN uv pip install --system --no-cache volatility3

# ── Copy application source ──────────────────────────────────────────────────
COPY . .

# ── Create directories ────────────────────────────────────────────────────────
RUN mkdir -p /cases /yara_rules /logs

# ── Copy bundled YARA rules ───────────────────────────────────────────────────
COPY yara_rules/ /yara_rules/

# ── Ollama config ─────────────────────────────────────────────────────────────
ENV OLLAMA_HOST=http://ollama:11434
ENV OLLAMA_MODEL=qwen:1.8b

# ── Environment defaults ─────────────────────────────────────────────────────
ENV EVIDENCE_ROOT=/cases
ENV CASES_DIR=/cases
ENV YARA_RULES_DIR=/yara_rules
ENV TOOL_TIMEOUT=60
ENV NODE_TIMEOUT=120
ENV MAX_ITERATIONS=3
ENV CONFIDENCE_THRESHOLD=0.70
ENV LOG_LEVEL=INFO
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/sift-aid

# ── Non-root user for security ────────────────────────────────────────────────
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel && \
    chown -R sentinel:sentinel /sift-aid /logs /yara_rules

USER sentinel

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
