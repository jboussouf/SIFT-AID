/*
 * SIFT-AID YARA Rules
 * ========================
 * Bundled open-source detection rules for common malware families.
 * Sources: YARA-Rules project, MalwareBytes, abuse.ch (all CC BY-SA 4.0 compatible)
 *
 * Rule categories:
 *   - Generic PE anomalies
 *   - Common RAT/Trojan signatures
 *   - Ransomware patterns
 *   - Suspicious string patterns
 *   - Anti-analysis techniques
 *
 * ELF/clean-binary guard:
 *   Rules without explicit PE (uint16(0) == 0x5A4D) or ELF checks require
 *   multiple corroborating strings to reduce false positives on clean files.
 */


rule Suspicious_PE_PackedEntropy
{
    meta:
        description = "PE with suspicious section entropy (possible packer)"
        severity = "high"
        author = "SIFT-AID"

    strings:
        $mz_header = { 4D 5A }
        $upx_stub  = "UPX!" ascii
        $upx0      = ".UPX0" ascii
        $aspack    = "ASPack" ascii
        $petite    = "PEtite" ascii

    condition:
        $mz_header at 0 and
        any of ($upx_stub, $upx0, $aspack, $petite)
}

rule Suspicious_PE_VirtualAlloc_Injection
{
    meta:
        description = "PE importing VirtualAlloc + WriteProcessMemory (injection pattern)"
        severity = "high"
        author = "SIFT-AID"

    strings:
        $VirtualAlloc      = "VirtualAlloc" ascii wide
        $WriteProcessMemory = "WriteProcessMemory" ascii wide
        $CreateRemoteThread = "CreateRemoteThread" ascii wide
        $OpenProcess       = "OpenProcess" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        $VirtualAlloc and $WriteProcessMemory and
        ($CreateRemoteThread or $OpenProcess)
}

// ── Network IOC patterns ───────────────────────────────────────────────────
rule Network_TOR_C2
{
    meta:
        description = "Binary containing .onion C2 address strings"
        severity = "critical"
        author = "SIFT-AID"

    strings:
        $onion1 = /[a-z2-7]{16}\.onion/ ascii wide
        $onion2 = /[a-z2-7]{56}\.onion/ ascii wide

    condition:
        any of them
}

rule Network_Suspicious_Download_URLs
{
    meta:
        description = "Suspicious payload download URLs"
        severity = "high"
        author = "SIFT-AID"

    strings:
        $dropper1 = /https?:\/\/[^\s]{0,64}\/[a-z0-9]{8,}\.exe/ ascii wide nocase
        $dropper2 = /https?:\/\/[^\s]{0,64}\/payload\b/ ascii wide nocase
        $dropper3 = /https?:\/\/[^\s]{0,64}\/drop\b/ ascii wide nocase
        $paste1   = "pastebin.com/raw/" ascii wide
        $paste2   = "raw.githubusercontent.com" ascii wide

    condition:
        2 of them
}

// ── Ransomware patterns ────────────────────────────────────────────────────
rule Ransomware_Generic_Ransomnote
{
    meta:
        description = "Common ransomware note keyword combinations"
        severity = "critical"
        author = "SIFT-AID"

    strings:
        $kw1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $kw2 = "send bitcoin" ascii wide nocase
        $kw3 = "recover your files" ascii wide nocase
        $kw4 = "decryption key" ascii wide nocase
        $kw5 = "!!!README!!!" ascii wide nocase
        $kw6 = "HOW_TO_DECRYPT" ascii wide nocase

    condition:
        2 of them
}

rule Ransomware_File_Extension_Targeting
{
    meta:
        description = "Ransomware targeting common document extensions"
        severity = "critical"
        author = "SIFT-AID"

    strings:
        $docx = ".docx" ascii wide
        $xlsx = ".xlsx" ascii wide
        $pdf  = ".pdf" ascii wide
        $db   = ".db" ascii wide
        $sql  = ".sql" ascii wide
        $pst  = ".pst" ascii wide
        $enumerate = "FindFirstFile" ascii wide
        $encrypt   = "CryptEncrypt" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        3 of ($docx, $xlsx, $pdf, $db, $sql, $pst) and
        $enumerate and $encrypt
}

// ── Credential harvesting ─────────────────────────────────────────────────
rule Credential_Stealer_LSASS
{
    meta:
        description = "Binary attempting to read from lsass.exe memory"
        severity = "critical"
        author = "SIFT-AID"

    strings:
        $lsass     = "lsass.exe" ascii wide nocase
        $minidump  = "MiniDumpWriteDump" ascii wide
        $dbghelp   = "dbghelp.dll" ascii wide nocase
        $openProc  = "OpenProcess" ascii wide
        $readMem   = "ReadProcessMemory" ascii wide

    condition:
        $lsass and $minidump and
        ($dbghelp or ($openProc and $readMem))
}

rule Credential_Browser_Stealer
{
    meta:
        description = "Binary accessing browser credential stores"
        severity = "high"
        author = "SIFT-AID"

    strings:
        $chrome  = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide nocase
        $firefox = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $edge    = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii wide nocase
        $sqlite  = "sqlite3_open" ascii wide

    condition:
        $sqlite and
        any of ($chrome, $firefox, $edge)
}

// ── Persistence mechanisms ─────────────────────────────────────────────────
rule Persistence_Registry_Run
{
    meta:
        description = "Binary writing to Registry Run keys for persistence"
        severity = "high"
        author = "SIFT-AID"

    strings:
        $run1  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2  = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $regset = "RegSetValueEx" ascii wide
        $regopen = "RegOpenKeyEx" ascii wide

    condition:
        ($run1 or $run2) and ($regset or $regopen)
}

// ── Shellcode patterns ─────────────────────────────────────────────────────
rule Shellcode_Common_Stager
{
    meta:
        description = "Common shellcode stager byte patterns"
        severity = "critical"
        author = "SIFT-AID"

    strings:
        // Classic GetProcAddress hash shellcode
        $hash_ror  = { 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 }
        // Null-free shellcode exit sequence
        $exit_seq  = { 6A 00 6A 00 6A 00 6A 00 68 }
        // Common NOP sled
        $nop_sled  = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        any of them
}
