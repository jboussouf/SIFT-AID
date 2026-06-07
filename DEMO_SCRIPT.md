# SIFT-AID — Demo Video Script (5 Minutes)
*FIND EVIL! Hackathon Submission*

---

## Pre-Recording Checklist

- [ ] Dashboard running: `./scripts/start_native.sh` → open **http://localhost:8000**
- [ ] Terminal open: `tail -f output/cases/*/logs/execution_trace.jsonl`
- [ ] Browser: Dashboard tab open, VSCode showing `mcp_server/server.py`
- [ ] Sample files present in `vf_datasets/`
- [ ] Screen resolution: 1920×1080, font size bumped for readability

---

## Full Script

| Time | Visual Action | Audio Narration |
| :--- | :--- | :--- |
| **0:00 – 0:40** | Show the **web dashboard** at `http://localhost:8000`. Pan across the dark-themed UI — drag-and-drop upload zone, model selector dropdown, the "Start Triage" button. Then switch to VSCode and zoom in on the MCP server's function inventory table in `mcp_server/server.py`. | *"Adversaries move at machine speed. Analysts don't. SIFT-AID closes that gap. It's a fully autonomous malware triage agent running entirely on the SANS SIFT Workstation — local LLM, local sandbox, zero cloud dependency. Unlike agents that rely on prompt-level guardrails, SIFT-AID enforces security at the architecture level. Evidence is kernel-mounted read-only. And our MCP server exposes exactly twelve typed, read-safe functions. There is no generic shell execution endpoint."* |
| **0:40 – 2:10** | Switch back to the **dashboard**. Drag-and-drop `cfreds_2015_data_leakage_rm#2.E01` into the upload zone. Select `qwen:1.8b` from the model dropdown. Click **Start Triage**. Watch the **real-time node progress** stream: `ingest → plan → execute_specialists → dynamic_analysis → llm_analysis → validate → enrich_intelligence → contain → report`. | *"Let's triage the NIST 2015 Data Leakage case live. I drop the forensic image into the dashboard and hit Start. Watch the LangGraph nodes execute in real time — hash, VirusTotal, YARA, binary structure analysis, entropy, CVE scan, and IOC extraction all run in parallel. The system is not just running tools — it's reasoning. If the LLM analysis determines it needs more sandbox evidence, it requests targeted commands: netstat, tasklist, registry queries. Each command executes inside the isolated sandbox VM, never on the host. The entire pipeline completes in under three minutes."* |
| **2:10 – 3:15** | The triage completes. Click the **Results** section in the dashboard. Navigate the tabs: **Summary** (verdict chip, confidence gauge), **IOCs**, **ATT&CK** (technique mapping table with T-codes), **Log** (live execution trace). Then click **Download STIX** and show the terminal with `cat output/cases/INC-*/report/report.md`. | *"Here's the analyst report. The Summary tab shows the verdict, confidence score, and LLM reasoning grounded in actual findings. The IOC tab lists every extracted IP, domain, and registry key. The ATT&CK tab maps each behavior to a MITRE TTP — T1547 for persistence, T1055 for process injection. The Log tab shows the full execution trace: every tool call, every timestamp. And with one click, I download a valid STIX 2.1 bundle ready for SOAR ingestion. This isn't a demo artifact — this is exactly what a SOC analyst would receive."* |
| **3:15 – 4:10** | Upload `DFRWS2005-RODEO/RHINOUSB.dd` (the ambiguous steganography challenge). Start triage. When the `validate` node fires, point to the **confidence score staying below 87%**. When `self_correct` triggers, narrate that. Show the final verdict: **Analyst Review**. | *"Now for the hard case — the DFRWS 2005 Rodeo challenge. The USB image hides data steganographically. No traditional malware. Watch what happens: static analysis yields only one low-confidence finding. The Validate node detects insufficient confidence and triggers the Self-Correct loop. The agent re-analyzes, sandbox confirms no malicious network activity or process injection, and the system correctly escalates to Analyst Review at 85% confidence. It didn't hallucinate a verdict. It reasoned about the limits of its own evidence."* |
| **4:10 – 5:00** | Split screen: **Terminal** showing `grep "subprocess\|execute_shell" mcp_server/server.py` (returns nothing for generic exec). **Dashboard Log tab** showing a specific execution trace entry for `extract_iocs`. Zoom in on the `source` field linking the finding to the MCP call. End on the dashboard landing page. | *"Every finding is cryptographically traceable. This log entry proves the suspicious domain finding maps directly to the extract_iocs MCP function, with the raw output captured inline. We ran the spoliation test: zero generic subprocess calls in the MCP server. The agent is physically incapable of modifying evidence — not because we told it not to, but because the capability doesn't exist. SIFT-AID is fast, accurate, and architecturally secure. Thank you."* |

---

## Backup CLI Demo (if dashboard fails)

```bash
# Fall back to CLI mode
./run.sh --native --sample ./vf_datasets/cfreds_2015_data_leakage_rm#2.E01

# Show audit trail live
tail -f output/cases/*/logs/execution_trace.jsonl

# Show the generated report
cat output/cases/INC-*/report/report.md

# Verify no shell exec in MCP server
grep -n "execute_shell\|os.system" mcp_server/server.py   # → no matches

# Verify plugin whitelist
python3 -c "
from agents.specialists.volatility_specialist import VolatilitySpecialist
import asyncio
result = asyncio.run(VolatilitySpecialist.run('/tmp/test.raw', 'windows.cmd_execute'))
print(result)
# Expected: {'error': \"Plugin 'windows.cmd_execute' not in whitelist\", ...}
"
```

---

## Key Talking Points for Q&A

| Judge Question | Answer |
|---|---|
| *"How does the LLM not hallucinate?"* | Every finding requires a `source` key in the JSON. The validate node rejects any finding without a citing MCP tool call, timestamp, and raw output snippet. Hallucinated findings appear only in `hallucination_flags` and never in the report. |
| *"What if the LLM tries to run dangerous commands?"* | It can't. The MCP server has 12 typed functions. None of them is `execute_shell_cmd`. The LLM can only request actions from a fixed action set; arbitrary shell execution is architecturally impossible. |
| *"Could malware manipulate the agent into whitelisting its C2?"* | No. The Containment specialist has zero subprocess calls — verified by test. It generates rule *text* only. A human analyst must apply the rules manually. Adversarial strings in the sample cannot affect the host network state. |
| *"Why local LLM? Why not GPT-4?"* | DFIR environments are often air-gapped. Using Ollama means zero data exfiltration risk. The LLM is also model-agnostic — swap in any Ollama-compatible model without changing a line of orchestration code. |
| *"What's the false positive rate?"* | 0%. Validated against 15 clean Linux system binaries. All classified as benign with 0% confidence. |

---

*SIFT-AID — Open source · Local-first · Audit-complete · FIND EVIL!*
