import asyncio
import json
import logging
import os
import time
from pathlib import Path

import httpx

log = logging.getLogger("sift_aid.specialists.dynamic_analysis")

USE_MOCK_SANDBOX = os.environ.get("USE_MOCK_SANDBOX", "True").lower() in ("true", "1", "yes")
CAPE_API_URL = os.environ.get("CAPE_API_URL", "http://localhost:8000/apiv2")


class DynamicAnalysisSpecialist:
    """Submit files to CAPE sandbox, poll for behavioral reports, and run interactive commands."""

    @staticmethod
    async def run(file_path: str, timeout_seconds: int = 300) -> dict:
        """Helper to run the full submit + poll cycle."""
        t0 = time.monotonic()
        try:
            task_id = await DynamicAnalysisSpecialist.submit_to_sandbox(file_path)
            report = await DynamicAnalysisSpecialist.get_sandbox_report(task_id, timeout_seconds, file_path)
            report["elapsed_seconds"] = round(time.monotonic() - t0, 3)
            report["task_id"] = task_id
            return report
        except Exception as e:
            log.error("[DynamicAnalysis] Failed: %s", e)
            return {"error": str(e), "elapsed_seconds": round(time.monotonic() - t0, 3)}

    @staticmethod
    async def submit_to_sandbox(file_path: str) -> str:
        """Submits the file to the sandbox and returns task_id."""
        if USE_MOCK_SANDBOX:
            log.info("[DynamicAnalysis] Mock submit: %s", file_path)
            return "mock_task_123"

        url = f"{CAPE_API_URL}/tasks/create/file/"
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        async with httpx.AsyncClient() as client:
            with open(p, "rb") as f:
                resp = await client.post(url, files={"file": f}, timeout=10.0)
                resp.raise_for_status()
                data = resp.json()
                task_id = data.get("data", {}).get("task_ids", [""])[0]
                return str(task_id)

    @staticmethod
    async def get_sandbox_report(task_id: str, timeout: int, file_path: str = "") -> dict:
        """Polls the API until completion or timeout, returns parsed summary."""
        t0 = time.monotonic()

        if USE_MOCK_SANDBOX:
            await asyncio.sleep(2)
            mock_path = Path(__file__).resolve().parents[2] / "sample_data" / "mock_cape_report.json"
            if mock_path.exists():
                report_data = json.loads(mock_path.read_text(encoding="utf-8"))
            else:
                report_data = {}
            return DynamicAnalysisSpecialist._parse_report(report_data, file_path)

        url = f"{CAPE_API_URL}/tasks/get/report/{task_id}/"
        delay = 2.0
        async with httpx.AsyncClient(timeout=10.0) as client:
            while True:
                if time.monotonic() - t0 > timeout:
                    raise asyncio.TimeoutError(f"Sandbox polling timed out after {timeout}s")
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("error"):
                            raise Exception(f"API Error: {data.get('error_value')}")
                        return DynamicAnalysisSpecialist._parse_report(data.get("data", {}))
                    elif resp.status_code == 404:
                        pass
                except httpx.RequestError as e:
                    log.warning("[DynamicAnalysis] API poll error: %s", e)

                await asyncio.sleep(delay)
                delay = min(delay * 1.5, 10.0)

    @staticmethod
    def _mock_documentation_check(file_path: str) -> dict:
        """Simulate running '--help' on the binary to check for documentation."""
        name = Path(file_path).name.lower()
        # If it's a known Linux binary, simulate real documentation output
        is_benign, _ = DynamicAnalysisSpecialist._is_known_linux_binary(file_path)
        if is_benign:
            return {
                "has_documentation": True,
                "method": "both",
                "stdout_help": f"Usage: {name} [OPTION]... [FILE]...\nPrint system information.",
                "stdout_h": f"Usage: {name} [OPTION]... [FILE]...\n  -h, --help    display this help and exit",
                "binary_class": "system_utility",
            }
        # Not a known binary — simulate no documentation (suspicious)
        return {
            "has_documentation": False,
            "method": "both",
            "stdout_help": "",
            "stdout_h": "",
            "binary_class": "unknown",
        }

    @staticmethod
    async def check_documentation(file_path: str) -> dict:
        """Check if the binary has documentation by running '--help' and '-h'."""
        if USE_MOCK_SANDBOX:
            return DynamicAnalysisSpecialist._mock_documentation_check(file_path)
        # Real sandbox path: execute the binary with --help / -h
        task_id = await DynamicAnalysisSpecialist.submit_to_sandbox(file_path)
        help_result = await DynamicAnalysisSpecialist.execute_command(
            task_id, f"{file_path} --help"
        )
        h_result = await DynamicAnalysisSpecialist.execute_command(
            task_id, f"{file_path} -h"
        )
        return {
            "has_documentation": bool(
                (help_result.get("stdout") or "").strip()
                or (h_result.get("stdout") or "").strip()
            ),
            "method": "both",
            "stdout_help": help_result.get("stdout", ""),
            "stdout_h": h_result.get("stdout", ""),
            "binary_class": "unknown",
        }

    @staticmethod
    def _is_known_linux_binary(file_path: str) -> tuple[bool, float]:
        """Check if the file is a known benign Linux binary and return a realistic score."""
        import re as _re
        raw_name = Path(file_path).name.lower()
        # The dashboard renames uploads as "<hex8>_<original_name>".
        # Strip that prefix so "daeb0c73_cat" is treated the same as "cat".
        _prefix_re = _re.compile(r'^[0-9a-f]{6,16}_(.+)$')
        m = _prefix_re.match(raw_name)
        name = m.group(1) if m else raw_name
        # Core utilities, shells, system tools — never malware
        # Comprehensive list covering GNU coreutils, diffutils, findutils,
        # util-linux, procps, net-tools, iproute2, and common system packages
        _BENIGN_BINARIES = {
            # GNU coreutils
            "apt", "apt-get", "apt-cache", "dpkg", "cat", "ls", "cp", "mv", "rm",
            "mkdir", "rmdir", "touch", "chmod", "chown", "ln", "find", "grep",
            "sed", "awk", "sort", "uniq", "wc", "tee", "head", "tail", "cut",
            "tr", "diff", "patch", "echo", "printf", "test", "true", "false",
            "basename", "dirname", "readlink", "realpath", "pathchk",
            "dd", "install", "mkfifo", "mknod", "shred", "truncate",
            "seq", "shuf", "factor", "numfmt", "nproc", "b2sum",
            "base32", "base64", "cksum", "md5sum", "sha1sum", "sha256sum",
            "sha224sum", "sha384sum", "sha512sum", "sum",
            "comm", "csplit", "expand", "unexpand", "fmt", "fold", "join",
            "nl", "od", "paste", "pr", "ptx", "split", "tsort",
            "stty", "tty", "yes", "expr", "stdbuf", "env",
            "chroot", "chcon", "runcon", "nohup", "nice", "renice",
            "dir", "vdir", "dircolors", "link", "unlink",
            # GNU diffutils
            "cmp", "diff3", "sdiff",
            # GNU findutils
            "xargs", "locate", "updatedb",
            # file, strings, and other common analysis tools
            "file", "strings", "ldd", "ltrace", "strace", "hexdump", "xxd",
            # Shells
            "bash", "sh", "zsh", "dash", "ksh",
            "env", "which", "whereis", "type", "command",
            # Process management
            "ps", "top", "htop", "kill", "pkill", "killall", "pgrep",
            "nice", "renice", "nohup", "setsid",
            # User/identity
            "id", "whoami", "who", "w", "last", "lastb", "lastlog",
            "groups", "users", "logname", "pinky",
            # Filesystem
            "mount", "umount", "df", "du", "stat", "sync", "lsblk", "blkid",
            "fdisk", "parted", "mkfs", "fsck", "e2fsck",
            # Archives/compression
            "tar", "gzip", "gunzip", "bzip2", "xz", "zip", "unzip",
            "zcat", "bzcat", "xzcat", "lz4", "zstd", "pigz",
            "cpio", "ar",
            # Build tools
            "make", "gcc", "g++", "clang", "clang++", "ld", "as", "ar",
            "nm", "objdump", "objcopy", "strip", "ranlib", "size", "readelf",
            "cmake", "pkg-config",
            # Scripting languages
            "python", "python3", "python3.10", "python3.11", "python3.12",
            "perl", "ruby", "php", "lua", "node", "nodejs",
            # Network tools
            "ssh", "scp", "rsync", "curl", "wget", "ftp", "telnet", "nc",
            "ncat", "socat",
            "ping", "ping6", "traceroute", "tracepath", "mtr",
            "nslookup", "dig", "host", "netstat", "ss",
            "ip", "ifconfig", "route", "arp", "bridge", "iptables", "nft",
            "ethtool", "tc", "iw", "iwconfig",
            # Systemd / init
            "systemctl", "journalctl", "service", "init", "systemd",
            "systemd-analyze", "systemd-run", "systemd-cat",
            # Scheduling
            "cron", "crontab", "at", "atq", "atrm", "anacron", "batch",
            "watch", "sleep", "timeout",
            # Editors / pagers
            "nano", "vim", "vi", "emacs", "ed", "less", "more", "pager",
            # Documentation
            "man", "info", "whatis", "apropos", "help",
            # Authentication / user admin
            "passwd", "chsh", "chfn", "login", "logout", "su", "sudo",
            "useradd", "userdel", "usermod", "groupadd", "groupdel",
            "adduser", "deluser", "addgroup", "delgroup", "chage", "gpasswd",
            # System info
            "date", "cal", "uptime", "uname", "hostname", "arch",
            "locale", "localectl", "timedatectl", "loginctl",
            "hostnamectl", "lscpu", "lsmem", "lsmod", "lspci", "lsusb",
            "dmesg", "free", "vmstat", "iostat", "mpstat", "sar",
            # Package managers
            "snap", "flatpak", "pip", "pip3", "gem", "npm", "yarn", "cargo",
            "yum", "dnf", "pacman", "zypper", "apk", "brew",
        }
        if name in _BENIGN_BINARIES:
            return True, 0.05

        # Fallback heuristic: binaries residing in standard system directories
        # are overwhelmingly benign. This prevents the mock sandbox from
        # injecting false malicious indicators for unlisted system tools.
        try:
            resolved = Path(file_path).resolve()
            _SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin",
                            "/usr/local/bin", "/usr/local/sbin")
            if any(str(resolved).startswith(d + "/") for d in _SYSTEM_DIRS):
                log.info("[DynamicAnalysis] System-path heuristic: %s treated as benign", name)
                return True, 0.05
        except Exception:
            pass

        # Could add SHA256 hash checking for known clean files
        return False, None

    @staticmethod
    def _parse_report(report: dict, file_path: str = "") -> dict:
        """Extracts required IOCs and ATT&CK IDs."""
        network_iocs = []
        dropped_files = []
        attack_techniques = []

        # For known Linux binaries, return a minimal benign report
        is_benign, benign_score = DynamicAnalysisSpecialist._is_known_linux_binary(file_path)
        doc_check = DynamicAnalysisSpecialist._mock_documentation_check(file_path) if file_path else {}
        if is_benign:
            return {
                "network_iocs": [],
                "dropped_files": [],
                "process_tree": [],
                "attack_techniques": [],
                "confidence_boost": benign_score,
                "documentation_check": doc_check,
            }

        net = report.get("network", {})
        for dns in net.get("dns", []):
            if dns.get("request"):
                network_iocs.append(dns["request"])
            for ans in dns.get("answers", []):
                if ans.get("data"):
                    network_iocs.append(ans["data"])
        for http in net.get("http", []):
            if http.get("uri"):
                network_iocs.append(http["uri"])

        behavior = report.get("behavior", {})
        summary = behavior.get("summary", {})
        if "file_created" in summary:
            dropped_files.extend(summary["file_created"])
        elif "files" in summary:
            dropped_files.extend(summary["files"])

        process_tree = []
        for proc in behavior.get("processes", []):
            process_tree.append({
                "process_name": proc.get("process_name"),
                "pid": proc.get("pid")
            })

        for sig in report.get("signatures", []):
            attack_techniques.extend(sig.get("attck_ids", []))

        confidence_boost = min(1.0, report.get("info", {}).get("score", 0.0) / 10.0)

        return {
            "network_iocs": sorted(list(set(network_iocs))),
            "dropped_files": sorted(list(set(dropped_files))),
            "process_tree": process_tree,
            "attack_techniques": sorted(list(set(attack_techniques))),
            "confidence_boost": round(confidence_boost, 3)
        }

    @staticmethod
    async def execute_command(task_id: str, command: str) -> dict:
        """Run an arbitrary command on the sandbox VM and return output."""
        if USE_MOCK_SANDBOX:
            return DynamicAnalysisSpecialist._mock_command_output(command)

        url = f"{CAPE_API_URL}/tasks/execute/{task_id}/"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json={"command": command})
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def block_network(task_id: str, target: str, target_type: str = "port") -> dict:
        """Block a port, IP, or domain on the sandbox VM."""
        if USE_MOCK_SANDBOX:
            return DynamicAnalysisSpecialist._mock_block_output(target, target_type)

        url = f"{CAPE_API_URL}/tasks/block/{task_id}/"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json={"target": target, "target_type": target_type})
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def get_sandbox_status(task_id: str) -> dict:
        """Get current process/network status of the sandbox VM."""
        if USE_MOCK_SANDBOX:
            return DynamicAnalysisSpecialist._mock_status_output()

        url = f"{CAPE_API_URL}/tasks/status/{task_id}/"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def _mock_command_output(command: str) -> dict:
        cmd_lower = command.lower()
        if "netstat" in cmd_lower or "network" in cmd_lower or "net" in cmd_lower:
            return {
                "stdout": (
                    "Active Connections\n"
                    "  Proto  Local Address          Foreign Address        State\n"
                    "  TCP    10.0.2.15:49152        198.51.100.2:443       ESTABLISHED\n"
                    "  TCP    10.0.2.15:49153        198.51.100.2:80        TIME_WAIT\n"
                    "  TCP    10.0.2.15:49154        192.168.1.1:53         CLOSE_WAIT\n"
                ),
                "stderr": "",
                "return_code": 0,
            }
        if "ping" in cmd_lower:
            return {
                "stdout": (
                    "Pinging 198.51.100.2 with 32 bytes of data:\n"
                    "Request timed out.\n"
                    "Request timed out.\n"
                    "Request timed out.\n"
                    "Ping statistics: Packets: Sent = 3, Received = 0, Lost = 3 (100% loss)"
                ),
                "stderr": "",
                "return_code": 1,
            }
        if "tasklist" in cmd_lower or "ps " in cmd_lower or "pslist" in cmd_lower:
            return {
                "stdout": (
                    "Image Name                     PID     Session Name\n"
                    "malware.exe                     4321    Console\n"
                    "svchost.exe                     1234    Console\n"
                    "notepad.exe                     5678    Console\n"
                    "cmd.exe                         9012    Console\n"
                ),
                "stderr": "",
                "return_code": 0,
            }
        if "reg" in cmd_lower and ("query" in cmd_lower or "hkcu" in cmd_lower or "hkcu" in cmd_lower):
            return {
                "stdout": (
                    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                    "    MaliciousUpdater    REG_SZ    C:\\Users\\Public\\payload.exe\n"
                ),
                "stderr": "",
                "return_code": 0,
            }
        if "process" in cmd_lower or "proc" in cmd_lower:
            return {
                "stdout": (
                    "malware.exe (PID: 4321) - Running - CPU: 12% - MEM: 45MB\n"
                    "  Threads: 8 | Handles: 256\n"
                    "  Window Title: (none)\n"
                    "  Command Line: C:\\Users\\Public\\malware.exe -silent\n"
                ),
                "stderr": "",
                "return_code": 0,
            }
        return {
            "stdout": f"Command '{command}' executed successfully.",
            "stderr": "",
            "return_code": 0,
        }

    @staticmethod
    def _mock_block_output(target: str, target_type: str) -> dict:
        if target_type == "port":
            return {
                "action": f"Blocked port {target}",
                "status": "active",
                "rule": f"iptables -A OUTPUT -p tcp --dport {target} -j DROP",
            }
        elif target_type == "ip":
            return {
                "action": f"Blocked IP {target}",
                "status": "active",
                "rule": f"iptables -A OUTPUT -d {target} -j DROP",
            }
        elif target_type == "domain":
            return {
                "action": f"Blocked domain {target}",
                "status": "active",
                "rule": f"echo '127.0.0.1 {target}' >> /etc/hosts",
            }
        return {
            "action": f"Blocked {target_type}: {target}",
            "status": "active",
            "rule": "nft add rule ip filter output drop",
        }

    @staticmethod
    async def query_dropped_files(task_id: str) -> dict:
        """Query the sandbox specifically for files dropped by the malware."""
        if USE_MOCK_SANDBOX:
            return {"dropped_files": DynamicAnalysisSpecialist._mock_dropped_files(task_id)}

        url = f"{CAPE_API_URL}/tasks/get/dropped/{task_id}/"
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                return {"dropped_files": data.get("data", [])}
            except httpx.HTTPStatusError as e:
                # If the endpoint doesn't exist or task not found, fail gracefully
                return {"error": f"API Error: {str(e)}"}

    @staticmethod
    def _mock_dropped_files(task_id: str) -> list:
        return [
            {
                "name": "payload.exe",
                "path": "C:\\Users\\Public\\payload.exe",
                "size": 15432,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            {
                "name": "ransom_note.txt",
                "path": "C:\\Users\\Public\\Desktop\\ransom_note.txt",
                "size": 1024,
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            }
        ]

    @staticmethod
    def _mock_status_output() -> dict:
        return {
            "vm_status": "running",
            "uptime_seconds": 124,
            "processes": [
                {"name": "malware.exe", "pid": 4321, "state": "running", "cpu": 12.0, "memory_mb": 45},
                {"name": "svchost.exe", "pid": 1234, "state": "running", "cpu": 2.0, "memory_mb": 18},
                {"name": "cmd.exe", "pid": 9012, "state": "sleeping", "cpu": 0.0, "memory_mb": 6},
            ],
            "network_connections": [
                {"protocol": "TCP", "local": "10.0.2.15:49152", "remote": "198.51.100.2:443", "state": "ESTABLISHED"},
                {"protocol": "TCP", "local": "10.0.2.15:49153", "remote": "198.51.100.2:80", "state": "TIME_WAIT"},
            ],
            "blocked_rules": [],
        }
