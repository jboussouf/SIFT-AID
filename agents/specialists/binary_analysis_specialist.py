"""
BinaryAnalysisSpecialist — PE/ELF structural binary analysis.

Analyzes binary structure: sections, imports, exports, packer detection,
compilation timestamps, embedded certificates, and architecture metadata.

Dependencies (optional, tried in order):
  1. lief  (best — covers PE/ELF/Mach-O)
  2. pefile + pyelftools (pure Python fallback)
  3. readelf / objdump / xxd subprocess (CLI fallback)
"""

import asyncio
import logging
import os
import re
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sift_aid.specialists.binary")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "30"))

_SUSPICIOUS_IMPORTS: dict[str, list[str]] = {
    "kernel32.dll": [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "ResumeThread", "SetThreadContext",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
        "ReadProcessMemory", "QueueUserAPC", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "OpenProcess",
    ],
    "ntdll.dll": [
        "NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
        "NtAllocateVirtualMemory", "NtCreateThreadEx", "NtResumeThread",
        "NtQueueApcThread", "NtSetContextThread",
    ],
    "wininet.dll": ["InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
                     "HttpSendRequestA", "InternetReadFile"],
    "ws2_32.dll": ["socket", "connect", "send", "recv", "WSASocketA", "WSAConnect"],
    "advapi32.dll": ["CreateServiceA", "StartServiceA", "OpenSCManagerA",
                      "RegCreateKeyExA", "RegSetValueExA"],
    "user32.dll": ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                    "GetForegroundWindow", "FindWindowA"],
    "psapi.dll": ["EnumProcesses", "EnumProcessModules", "GetModuleBaseNameA"],
}

_BENIGN_SECTION_NAMES = {
    # Standard PE sections
    ".text", ".data", ".rdata", ".pdata", ".edata", ".idata", ".rsrc",
    ".reloc", ".bss", ".tls", ".debug", ".stab", ".stabstr",
    # Standard ELF sections
    ".note", ".comment", ".got", ".plt", ".bss", ".symtab", ".strtab",
    ".shstrtab", ".init", ".fini", ".init_array", ".fini_array",
    ".ctors", ".dtors", ".dynamic", ".dynsym", ".dynstr",
    ".interp", ".gnu.hash", ".hash", ".ARM.exidx",
    # Modern ELF sections produced by GCC/clang (all standard / non-suspicious)
    ".note.gnu.property", ".note.gnu.build-id", ".note.ABI-tag",
    ".note.gnu.gold-version", ".note.stapsdt",
    ".gnu.version", ".gnu.version_r", ".gnu.version_d",
    ".rela.dyn", ".rela.plt", ".rela.text", ".rela.data",
    ".rel.dyn", ".rel.plt", ".rel.text", ".rel.data",
    ".plt.got", ".plt.sec", ".plt.bnd",
    ".rodata", ".rodata1",
    ".eh_frame", ".eh_frame_hdr", ".gcc_except_table",
    ".data.rel.ro", ".data.rel.ro.local",
    ".gnu_debuglink", ".gnu_debugaltlink",
    ".debug_info", ".debug_abbrev", ".debug_aranges", ".debug_line",
    ".debug_str", ".debug_loc", ".debug_ranges", ".debug_frame",
    ".debug_types", ".debug_pubnames", ".debug_pubtypes",
    ".debug_macro", ".debug_addr", ".debug_rnglists",
    ".debug_loclists", ".debug_line_str",
    ".got.plt", ".lrodata", ".ldata", ".lbss",
    ".preinit_array", ".tbss", ".tdata",
    ".ARM.attributes", ".ARM.extab", ".ARM.exidx",
    ".openbsd.randomdata",
}


_PACKER_SECTION_PATTERNS = {
    "UPX0", "UPX1", "UPX2", "UPX!", "UPX",
    ".packed", ".packing", ".lzma", ".RLPack",
    "ASPACK", ".adata", "ASPack",
    ".MPRESS1", ".MPRESS2", "MPRESS",
    ".nsp0", ".nsp1", ".nsp2",
    ".petite", ".pdata",
    ".scy", ".scys", ".tkbox",
    "PEC2TO", "PEC2FW",
    ".vmp0", ".vmp1", ".vmp2",
    ".enigma0", ".enigma1",
    ".Upack", ".ByDll",
    ".the0", ".the1", "themida",
    "TAPI", "TAPI0", "TAPI1",
    ".budle", ".bundle",
    "WCODE", ".winapi",
    ".mask", ".MASK",
    ".sforce", ".SForce",
    ".00cfg", ".0Rsrc",
    ".armad",
}

_SUSPICIOUS_SECTION_FLAGS = {
    "MEM_EXECUTE_AND_WRITE",
    "contains_code_and_writable_data",
}


class BinaryAnalysisSpecialist:
    """Analyze PE/ELF binary structure. Fully read-only."""

    @staticmethod
    async def run(sample_path: str) -> dict:
        """Run binary analysis and return structured results."""
        t0 = time.monotonic()
        p = Path(sample_path)

        if not p.exists():
            return {"error": f"File not found: {sample_path}", "format": None}

        file_size = p.stat().st_size
        with open(p, "rb") as f:
            header_data = f.read(4096)

        fmt = BinaryAnalysisSpecialist._detect_format(header_data)
        if not fmt:
            return {
                "file": str(p),
                "format": "unknown",
                "note": "Not a recognized PE/ELF/Mach-O binary",
                "elapsed_seconds": round(time.monotonic() - t0, 3),
            }

        result: dict[str, Any] = {
            "file": str(p),
            "format": fmt,
            "size_bytes": file_size,
        }

        lief_result = await BinaryAnalysisSpecialist._analyze_lief(str(p), fmt)
        if lief_result:
            result.update(lief_result)
        else:
            fallback = await BinaryAnalysisSpecialist._analyze_fallback(str(p), fmt, header_data)
            result.update(fallback)

        sections = result.get("sections", [])
        if sections:
            def _calc_entropies():
                with open(p, "rb") as f:
                    for sec in sections:
                        sec_start = sec.get("offset", 0)
                        sec_size = sec.get("size", 0)
                        if sec_start and sec_size and sec_start + sec_size <= file_size:
                            read_size = min(sec_size, 10 * 1024 * 1024)
                            f.seek(sec_start)
                            sec_data = f.read(read_size)
                            sec["entropy"] = round(BinaryAnalysisSpecialist._shannon_entropy(sec_data), 4)
                        else:
                            sec["entropy"] = 0.0
            await asyncio.to_thread(_calc_entropies)

        result["packer_detected"] = BinaryAnalysisSpecialist._detect_packer(result)

        suspicious = BinaryAnalysisSpecialist._check_suspicious_imports(
            result.get("imports", {})
        )
        result["suspicious_imports"] = suspicious
        result["suspicious_import_count"] = len(suspicious)

        ts = result.get("compile_timestamp")
        if ts:
            result["timestamp_anomaly"] = BinaryAnalysisSpecialist._check_timestamp(ts)

        result["elapsed_seconds"] = round(time.monotonic() - t0, 3)
        result["timestamp"] = datetime.now(timezone.utc).isoformat()

        log.info(
            "[BinaryAnalysisSpecialist] %s format=%s packer=%s suspicious_imports=%d",
            p.name, fmt, result.get("packer_detected", {}).get("detected", False),
            result.get("suspicious_import_count", 0),
        )
        return result

    @staticmethod
    def _detect_format(data: bytes) -> Optional[str]:
        if len(data) < 4:
            return None
        if data[:2] == b"MZ":
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 4 <= len(data) and data[pe_offset:pe_offset+4] == b"PE\x00\x00":
                return "pe"
        if data[:4] == b"\x7fELF":
            return "elf"
        if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            return "macho"
        return None

    @staticmethod
    async def _analyze_lief(path: str, fmt: str) -> Optional[dict]:
        def _parse():
            try:
                import lief
                binary = lief.parse(path)
                if binary is None:
                    return None

                result: dict[str, Any] = {}
    
                sections = []
                for sec in binary.sections:
                    s = {
                        "name": sec.name,
                        "size": sec.size,
                        "offset": sec.offset,
                        "virtual_address": hex(sec.virtual_address),
                        "characteristics": str(sec.characteristics) if hasattr(sec, "characteristics") else "",
                    }
                    sections.append(s)
                result["sections"] = sections
                result["section_count"] = len(sections)
    
                if hasattr(binary, "header"):
                    h = binary.header
                    result["architecture"] = str(h.machine) if hasattr(h, "machine") else str(h.machine_type) if hasattr(h, "machine_type") else "unknown"
                    result["bits"] = binary.bits if hasattr(binary, "bits") else 32
                    result["entry_point"] = hex(h.entrypoint) if hasattr(h, "entrypoint") else ""
    
                imports: dict[str, list[str]] = {}
                if hasattr(binary, "imports"):
                    for imp in binary.imports:
                        dll_name = imp.name.lower()
                        for entry in imp.entries:
                            if dll_name not in imports:
                                imports[dll_name] = []
                            name = entry.name if hasattr(entry, "name") and entry.name else f"ordinal_{entry.ordinal}" if hasattr(entry, "ordinal") else "unknown"
                            imports[dll_name].append(name)
                result["imports"] = imports
                result["import_count"] = sum(len(v) for v in imports.values())
    
                exports = []
                if hasattr(binary, "exported_functions"):
                    for ef in binary.exported_functions:
                        exports.append(ef.name if hasattr(ef, "name") else str(ef))
                result["exports"] = exports
                result["export_count"] = len(exports)
    
                if fmt == "pe" and hasattr(binary, "header") and hasattr(binary.header, "time_date_stamps"):
                    result["compile_timestamp"] = str(datetime.fromtimestamp(
                        binary.header.time_date_stamps, tz=timezone.utc
                    ))
    
                if hasattr(binary, "resources"):
                    result["resource_count"] = len(list(binary.resources)) if binary.resources else 0
    
                if hasattr(binary, "signatures") and binary.signatures:
                    sigs = []
                    for sig in binary.signatures:
                        sigs.append({
                            "issuer": str(sig.issuer) if hasattr(sig, "issuer") else "",
                            "is_signed": True,
                        })
                    result["signatures"] = sigs
                    result["has_signature"] = True
                else:
                    result["has_signature"] = False
    
                return result
    
            except ImportError:
                log.debug("[BinaryAnalysisSpecialist] LIEF not available, trying fallback")
                return None
            except Exception as exc:
                log.warning("[BinaryAnalysisSpecialist] LIEF analysis failed: %s", exc)
                return None
            
        return await asyncio.to_thread(_parse)

    @staticmethod
    async def _analyze_fallback(path: str, fmt: str, data: bytes) -> dict:
        result: dict[str, Any] = {}
        result["sections"] = []
        result["imports"] = {}

        if fmt == "elf":
            elf_result = await BinaryAnalysisSpecialist._analyze_elf_cli(path)
            result.update(elf_result)
        elif fmt == "pe":
            pe_result = await BinaryAnalysisSpecialist._analyze_pe_cli(path)
            result.update(pe_result)

        if not result.get("sections") and not result.get("imports"):
            result["sections"] = BinaryAnalysisSpecialist._manual_sections(data, fmt)
            result["imports"] = BinaryAnalysisSpecialist._manual_imports(data, fmt)

        if result.get("sections"):
            result["section_count"] = len(result["sections"])
        if result.get("imports"):
            result["import_count"] = sum(len(v) for v in result["imports"].values())

        result["architecture"] = "unknown"
        result["bits"] = 32
        result["entry_point"] = ""
        result["exports"] = []
        result["export_count"] = 0
        result["has_signature"] = False

        return result

    @staticmethod
    async def _analyze_elf_cli(path: str) -> dict:
        result: dict[str, Any] = {}
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "readelf", "-S", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                ),
                timeout=TOOL_TIMEOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
            text = stdout.decode("utf-8", errors="replace")

            sections = []
            for line in text.splitlines():
                m = re.match(
                    r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                    line,
                )
                if m:
                    sections.append({
                        "name": m.group(1),
                        "size": int(m.group(4), 16),
                        "offset": int(m.group(3), 16),
                        "virtual_address": f"0x{m.group(2)}",
                    })
            if sections:
                result["sections"] = sections

            proc2 = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "readelf", "-s", "--dyn-syms", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                ),
                timeout=TOOL_TIMEOUT,
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=TOOL_TIMEOUT)
            text2 = stdout2.decode("utf-8", errors="replace")

            imports: dict[str, list[str]] = {}
            for line in text2.splitlines():
                m = re.match(r".*\s+(\w+)\s+FUNC\s+.*\s+(\S+)$", line)
                if m:
                    lib = "UNKNOWN"
                    imports.setdefault(lib, [])
                    imports[lib].append(m.group(2))
            if imports:
                result["imports"] = imports

        except (FileNotFoundError, asyncio.TimeoutError, Exception) as exc:
            log.debug("[Binary] readelf fallback failed: %s", exc)

        return result

    @staticmethod
    async def _analyze_pe_cli(path: str) -> dict:
        result: dict[str, Any] = {}
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "objdump", "-p", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                ),
                timeout=TOOL_TIMEOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
            text = stdout.decode("utf-8", errors="replace")

            sections = []
            in_sections = False
            for line in text.splitlines():
                if "Section Table:" in line:
                    in_sections = True
                    continue
                if in_sections and line.strip() and not line.startswith(" "):
                    in_sections = False
                if in_sections:
                    m = re.match(r"\s*(\d+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
                    if m:
                        sections.append({
                            "name": m.group(2),
                            "size": int(m.group(3), 16),
                            "offset": int(m.group(4), 16),
                        })
            if sections:
                result["sections"] = sections

            imports: dict[str, list[str]] = {}
            current_dll = ""
            for line in text.splitlines():
                dm = re.match(r"^\s+DLL Name:\s+(\S+)", line)
                if dm:
                    current_dll = dm.group(1).lower().strip()
                    imports.setdefault(current_dll, [])
                im = re.match(r"^\s+ordinal:\s+\d+\s+Hint:\s+\w+\s+Name:\s+(\S+)", line)
                if im and current_dll:
                    imports[current_dll].append(im.group(1))
            if imports:
                result["imports"] = imports

        except (FileNotFoundError, asyncio.TimeoutError, Exception) as exc:
            log.debug("[Binary] objdump fallback failed: %s", exc)
        return result

    @staticmethod
    def _manual_sections(data: bytes, fmt: str) -> list[dict]:
        sections = []
        if fmt == "pe":
            try:
                pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
                if pe_offset + 4 + 20 > len(data):
                    return sections
                num_sections = struct.unpack_from("<H", data, pe_offset + 4 + 2)[0]
                sec_table_offset = pe_offset + 4 + 20
                for i in range(num_sections):
                    off = sec_table_offset + i * 40
                    if off + 40 > len(data):
                        break
                    name_raw = data[off:off+8]
                    name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
                    sec_size = struct.unpack_from("<I", data, off + 16)[0]
                    sec_offset = struct.unpack_from("<I", data, off + 20)[0]
                    sections.append({"name": name, "size": sec_size, "offset": sec_offset})
            except Exception:
                pass
        elif fmt == "elf":
            try:
                is_64 = data[4] == 2
                if is_64:
                    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
                    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
                    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
                    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
                else:
                    e_shoff = struct.unpack_from("<I", data, 0x20)[0]
                    e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
                    e_shnum = struct.unpack_from("<H", data, 0x30)[0]
                    e_shstrndx = struct.unpack_from("<H", data, 0x32)[0]
                str_sec_off = e_shoff + e_shstrndx * e_shentsize
                if is_64:
                    sh_offset = struct.unpack_from("<Q", data, str_sec_off + 0x18)[0]
                    sh_size = struct.unpack_from("<Q", data, str_sec_off + 0x20)[0]
                else:
                    sh_offset = struct.unpack_from("<I", data, str_sec_off + 0x10)[0]
                    sh_size = struct.unpack_from("<I", data, str_sec_off + 0x14)[0]
                str_table = data[sh_offset:sh_offset + sh_size]

                for i in range(e_shnum):
                    off = e_shoff + i * e_shentsize
                    if off + e_shentsize > len(data):
                        break
                    if is_64:
                        sh_name_idx = struct.unpack_from("<I", data, off)[0]
                        sh_offset = struct.unpack_from("<Q", data, off + 0x18)[0]
                        sh_size = struct.unpack_from("<Q", data, off + 0x20)[0]
                    else:
                        sh_name_idx = struct.unpack_from("<I", data, off)[0]
                        sh_offset = struct.unpack_from("<I", data, off + 0x10)[0]
                        sh_size = struct.unpack_from("<I", data, off + 0x14)[0]
                    name = str_table[sh_name_idx:str_table.find(b"\x00", sh_name_idx)].decode("ascii", errors="replace")
                    if name:
                        sections.append({"name": name, "size": sh_size, "offset": sh_offset})
            except Exception:
                pass
        return sections

    @staticmethod
    def _manual_imports(data: bytes, fmt: str) -> dict[str, list[str]]:
        imports: dict[str, list[str]] = {}
        if fmt != "pe":
            text = data.decode("ascii", errors="replace")
            for dll, apis in _SUSPICIOUS_IMPORTS.items():
                found = [api for api in apis if api in text]
                if found:
                    imports[dll] = found
            return imports

        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 4 + 24 > len(data):
                return imports
            dd_offset = pe_offset + 4 + 24
            import_rva = struct.unpack_from("<I", data, dd_offset + 8)[0]
            import_size = struct.unpack_from("<I", data, dd_offset + 12)[0]
            if import_rva == 0 or import_size == 0:
                return imports

            num_sections = struct.unpack_from("<H", data, pe_offset + 4 + 2)[0]
            sec_table_offset = pe_offset + 4 + 20
            sections_offsets = []
            for i in range(num_sections):
                off = sec_table_offset + i * 40
                if off + 40 > len(data):
                    break
                sec_vaddr = struct.unpack_from("<I", data, off + 12)[0]
                sec_size = struct.unpack_from("<I", data, off + 16)[0]
                sec_offset = struct.unpack_from("<I", data, off + 20)[0]
                sections_offsets.append((sec_vaddr, sec_vaddr + sec_size, sec_offset))

            def rva_to_offset(rva: int) -> int:
                for vaddr, vend, offset in sections_offsets:
                    if vaddr <= rva < vend:
                        return offset + (rva - vaddr)
                return rva

            imp_desc_off = rva_to_offset(import_rva)
            while imp_desc_off + 20 <= len(data):
                thunk_rva = struct.unpack_from("<I", data, imp_desc_off + 12)[0]
                name_rva = struct.unpack_from("<I", data, imp_desc_off + 16)[0]
                if thunk_rva == 0:
                    break
                dll_name_off = rva_to_offset(name_rva)
                if dll_name_off == 0:
                    imp_desc_off += 20
                    continue
                dll_end = data.find(b"\x00", dll_name_off)
                dll_name = data[dll_name_off:dll_end].decode("ascii", errors="replace").lower() if dll_end > dll_name_off else ""
                if not dll_name:
                    imp_desc_off += 20
                    continue
                thunk_off = rva_to_offset(thunk_rva)
                while thunk_off + 4 <= len(data):
                    thunk_val = struct.unpack_from("<I", data, thunk_off)[0]
                    if thunk_val == 0:
                        break
                    if thunk_val & 0x80000000:
                        api_name = f"ordinal_{thunk_val & 0xFFFF}"
                    else:
                        api_name_off = rva_to_offset(thunk_val + 2)
                        if api_name_off > 0 and api_name_off < len(data):
                            api_end = data.find(b"\x00", api_name_off)
                            api_name = data[api_name_off:api_end].decode("ascii", errors="replace") if api_end > api_name_off else ""
                        else:
                            api_name = ""
                    if api_name:
                        imports.setdefault(dll_name, [])
                        imports[dll_name].append(api_name)
                    thunk_off += 4
                imp_desc_off += 20
        except Exception as exc:
            log.debug("[Binary] Manual PE import parsing failed: %s", exc)
        return imports

    @staticmethod
    def _detect_packer(result: dict) -> dict:
        sections = result.get("sections", [])
        sig = result.get("has_signature", False)

        packer_indicators = []
        packer_names: set[str] = set()

        for sec in sections:
            name = sec.get("name", "")
            if name in _PACKER_SECTION_PATTERNS:
                packer_names.add(name)
                packer_indicators.append(f"Packer section name: {name}")
            elif name and name not in _BENIGN_SECTION_NAMES:
                packer_indicators.append(f"Unknown section: {name}")

        high_entropy_sections = [
            sec.get("name", "?") for sec in sections
            if sec.get("entropy", 0) > 0.75
        ]
        if len(high_entropy_sections) >= 2:
            packer_indicators.append(f"High entropy in sections: {high_entropy_sections}")

        import_count = result.get("import_count", 0)
        if 0 < import_count <= 5:
            packer_indicators.append(f"Very few imports ({import_count})")

        for sec in sections:
            chars = sec.get("characteristics", "")
            if any(flag in chars for flag in _SUSPICIOUS_SECTION_FLAGS):
                packer_indicators.append(f"Suspicious section flags: {sec.get('name')} ({chars})")

        detected = len(packer_indicators) >= 1
        confidence = 0.0
        if detected:
            score = 0.0
            if packer_names:
                score = max(score, 0.7)
            if high_entropy_sections:
                score = max(score, 0.6)
            if import_count <= 5:
                score = max(score, 0.5)
            confidence = min(score + 0.1 * (len(packer_indicators) - 1), 0.95)

        return {
            "detected": detected,
            "confidence": round(confidence, 3),
            "indicators": packer_indicators,
            "suspected_packers": sorted(packer_names) if packer_names else [],
            "note": "Heuristic detection — may produce false positives for custom or unusual binaries",
        }

    @staticmethod
    def _check_suspicious_imports(imports: dict[str, list[str]]) -> list[dict]:
        flagged = []
        for dll, apis in imports.items():
            dll_lower = dll.lower()
            suspicious_list = _SUSPICIOUS_IMPORTS.get(dll_lower, [])
            if not suspicious_list:
                continue
            for api in apis:
                api_clean = api.split("|")[0].strip()
                if api_clean in suspicious_list:
                    flagged.append({
                        "dll": dll_lower,
                        "api": api_clean,
                        "category": _classify_suspicious_api(dll_lower, api_clean),
                    })
        return flagged

    @staticmethod
    def _check_timestamp(ts_str: str) -> Optional[dict]:
        try:
            ts = datetime.fromisoformat(ts_str)
            now = datetime.now(timezone.utc)
            if ts > now:
                return {"anomaly": "future_timestamp", "detail": f"Compiled in the future: {ts_str}", "confidence": 0.6}
            if ts.year < 2000:
                return {"anomaly": "improbable_timestamp", "detail": f"Improbable timestamp: {ts_str}", "confidence": 0.4}
            if ts.year < 2015 and now.year - ts.year >= 10:
                return {"anomaly": "very_old_binary", "detail": f"Binary is {now.year - ts.year} years old: {ts_str}", "confidence": 0.2}
        except (ValueError, OverflowError):
            return {"anomaly": "invalid_timestamp", "detail": f"Cannot parse: {ts_str}", "confidence": 0.3}
        return None

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        length = len(data)
        import math
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy / 8.0


def _classify_suspicious_api(dll: str, api: str) -> str:
    injection_apis = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "CreateRemoteThread", "ResumeThread",
        "SetThreadContext", "NtUnmapViewOfSection", "NtWriteVirtualMemory",
        "NtProtectVirtualMemory", "NtAllocateVirtualMemory", "NtCreateThreadEx",
        "NtResumeThread", "NtQueueApcThread", "NtSetContextThread",
        "QueueUserAPC", "GetThreadContext",
    }
    persistence_apis = {
        "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
        "OpenSCManagerA", "OpenSCManagerW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegSetValueExA", "RegSetValueExW",
    }
    network_apis = {
        "socket", "connect", "send", "recv", "WSASocketA", "WSASocketW",
        "WSAConnect", "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
        "HttpSendRequestA", "InternetReadFile",
    }
    cred_theft_apis = {
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    }
    evasion_apis = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NqQueryInformationProcess",
        "GetTickCount",
    }

    if api in injection_apis:
        return "process_injection"
    if api in persistence_apis:
        return "persistence"
    if api in network_apis:
        return "network_communication"
    if api in cred_theft_apis:
        return "credential_theft"
    if api in evasion_apis:
        return "anti_analysis"
    return "other_suspicious"
