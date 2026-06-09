"""
Sandbox Orchestrator — Per-sample sandbox lifecycle management.

Three modes:
  - 'mock':    In-process mock (no Docker, no network). Default fallback.
  - 'docker':  Ephemeral Docker container with :ro evidence mount.
  - 'remote':  Use an existing sandbox API (e.g. docker-compose sandbox service).

Mode detection (auto):
  1. If SANDBOX_MODE env var is set → use that
  2. If DOCKER_HOST or /var/run/docker.sock exists → try 'docker'
  3. If CAPE_API_URL is set → 'remote'
  4. Otherwise → 'mock'
"""

import asyncio
import logging
import os
import socket
import subprocess
import time
from pathlib import Path

import httpx

log = logging.getLogger("sift_aid.sandbox_orchestrator")

SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "sift-aid:1.0.0")
SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "auto")
REMOTE_API_URL = os.environ.get("CAPE_API_URL", "")


def _docker_available() -> bool:
    try:
        subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class SandboxOrchestrator:
    """Create and destroy sandbox environments per triage sample."""

    def __init__(self, mode: str | None = None):
        self.mode = (mode or SANDBOX_MODE).lower()
        self.container_name: str | None = None
        self.api_url: str | None = None
        self._process: subprocess.Popen | None = None
        self._resolved_mode: str | None = None

    async def prepare(self, sample_path: str, incident_id: str | None = None) -> dict[str, str]:
        """Prepare a sandbox for the given sample.

        Returns a dict of environment variables to set before running triage.
        """
        sample_abs = str(Path(sample_path).resolve())

        if self.mode == "mock":
            return await self._prepare_mock(sample_abs)

        if self.mode == "remote" and REMOTE_API_URL:
            return await self._prepare_remote(sample_abs)

        if self.mode == "docker" or (self.mode == "auto" and _docker_available()):
            return await self._prepare_docker(sample_abs, incident_id)

        log.info("Docker not available — falling back to mock sandbox")
        return await self._prepare_mock(sample_abs)

    async def _prepare_mock(self, sample_path: str) -> dict[str, str]:
        self._resolved_mode = "mock"
        self.api_url = None
        log.info("[Sandbox] Mock mode — no container needed")
        return {
            "USE_MOCK_SANDBOX": "True",
            "CAPE_API_URL": "",
        }

    async def _prepare_remote(self, sample_path: str) -> dict[str, str]:
        self._resolved_mode = "remote"
        self.api_url = REMOTE_API_URL
        log.info("[Sandbox] Remote mode — using %s", REMOTE_API_URL)

        if not await self._check_remote_healthy(REMOTE_API_URL):
            log.warning("[Sandbox] Remote sandbox %s not reachable — falling back to mock", REMOTE_API_URL)
            return await self._prepare_mock(sample_path)

        return {
            "USE_MOCK_SANDBOX": "False",
            "CAPE_API_URL": REMOTE_API_URL,
        }

    async def _check_remote_healthy(self, api_url: str) -> bool:
        """Check if the remote sandbox API is reachable (any response = alive)."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.get(api_url.rstrip("/") + "/tasks/status/health/")
            return True
        except (httpx.RequestError, httpx.TimeoutException):
            return False

    async def _prepare_docker(self, sample_path: str, incident_id: str | None) -> dict[str, str]:
        self._resolved_mode = "docker"
        cid = (incident_id or f"sample-{int(time.time())}").lower().replace("_", "-")
        self.container_name = f"sift-sandbox-{cid}"

        evidence_dir = Path(sample_path).parent.resolve()
        sample_name = Path(sample_path).name
        host_port = _find_free_port()
        container_port = 8000

        log.info(
            "[Sandbox] Spinning up ephemeral container '%s' "
            "(evidence: %s → /evidence:ro, port %d)",
            self.container_name, evidence_dir, host_port,
        )

        try:
            # Dockerfile has ENTRYPOINT ["python3", "main.py"] — must override
            # with --entrypoint so the CMD runs uvicorn, not main.py
            subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", self.container_name,
                    "--rm",
                    "--entrypoint", "uvicorn",
                    "-v", f"{evidence_dir}:/evidence:ro",
                    "-p", f"{host_port}:{container_port}",
                    SANDBOX_IMAGE,
                    "sandbox_api:app",
                    "--host", "0.0.0.0",
                    "--port", str(container_port),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            log.error("[Sandbox] Docker run failed: %s", exc.stderr)
            log.warning("[Sandbox] Falling back to mock mode")
            return await self._prepare_mock(sample_path)
        except FileNotFoundError:
            log.warning("[Sandbox] Docker not found — falling back to mock mode")
            return await self._prepare_mock(sample_path)

        self.api_url = f"http://localhost:{host_port}/apiv2"

        ready = await self._wait_ready(host_port, timeout=30)
        if not ready:
            log.warning("[Sandbox] Container never became healthy — falling back to mock")
            await self.cleanup()
            return await self._prepare_mock(sample_path)

        log.info("[Sandbox] Container ready at %s", self.api_url)
        return {
            "USE_MOCK_SANDBOX": "False",
            "CAPE_API_URL": self.api_url,
        }

    async def _wait_ready(self, port: int, timeout: int = 30) -> bool:
        t0 = time.monotonic()
        # Phase 1: wait for TCP port to be open
        while time.monotonic() - t0 < timeout:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection("localhost", port),
                    timeout=3,
                )
                writer.close()
                await writer.wait_closed()
                break
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                await asyncio.sleep(1)
        else:
            log.warning("[Sandbox] Port %d not open within %ds — falling back to mock", port, timeout)
            return False

        # Phase 2: verify API responds (small grace period)
        url = f"http://localhost:{port}/apiv2/tasks/status/health/"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                async with httpx.AsyncClient(timeout=3) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        return True
            except (httpx.RequestError, httpx.TimeoutException):
                pass
            await asyncio.sleep(0.5)

        log.warning("[Sandbox] API not responding within 10s of port open — proceeding anyway")
        return True

    async def cleanup(self) -> None:
        """Destroy the sandbox. Safe to call even if none was created."""
        if self.container_name:
            log.info("[Sandbox] Cleaning up container '%s'", self.container_name)
            try:
                subprocess.run(
                    ["docker", "stop", self.container_name],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            except FileNotFoundError:
                pass
            self.container_name = None
            self.api_url = None

    @property
    def resolved_mode(self) -> str:
        return self._resolved_mode or "unknown"
