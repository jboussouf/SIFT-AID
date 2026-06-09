import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import sys
import json
import uuid
import shutil
from pathlib import Path
from datetime import datetime, timezone

# Inject root so we can import agents
root_dir = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(root_dir))

from sandbox_orchestrator import SandboxOrchestrator

os.environ.setdefault("CASES_DIR", str(root_dir / "output/cases"))
os.environ.setdefault("YARA_RULES_DIR", str(root_dir / "yara_rules"))
os.environ.setdefault("EVIDENCE_ROOT", str(root_dir / "vf_datasets"))
os.environ.setdefault("LOG_LEVEL", "INFO")
# NOTE: USE_MOCK_SANDBOX and CAPE_API_URL are set per-sample by SandboxOrchestrator
# inside the WebSocket handler (before the graph is first imported).
# This ensures the DynamicAnalysisSpecialist reads the correct env vars at import time.

app = FastAPI(title="SIFT-AID Dashboard")

# Ensure the static directory exists
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)

# Uploads directory — forensic images uploaded via the browser are stored here
uploads_dir = root_dir / "uploads"
uploads_dir.mkdir(exist_ok=True)

# Serve static files
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    """Serve the main dashboard HTML."""
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/api/llm")
async def llm_list():
    """Return list of available Ollama models."""
    import ollama
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    try:
        client = ollama.AsyncClient(host=host)
        models = await client.list()
        names = [m["model"] for m in models.get("models", [])]
        return {"models": names}
    except Exception as e:
        return {"models": [], "error": str(e)}

@app.get("/api/llm/{model}")
async def llm_check(model: str):
    """Test a specific Ollama model and set it as the active model."""
    import ollama
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    try:
        client = ollama.AsyncClient(host=host)
        response = await client.chat(model=model, messages=[
            {"role": "user", "content": "who are you? answer in one sentence."}
        ])
        os.environ["OLLAMA_MODEL"] = model
        return {"status": "ok", "model": model, "response": response["message"]["content"]}
    except Exception as e:
        return {"status": "error", "model": model, "error": str(e)}

@app.get("/api/ollama/models")
async def list_ollama_models():
    """Return list of available Ollama models on the host."""
    import ollama
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    try:
        client = ollama.AsyncClient(host=host)
        models = await client.list()
        names = [m["model"] for m in models.get("models", [])]
        return {"models": names}
    except Exception as e:
        return {"models": [], "error": str(e)}

@app.get("/api/env")
async def get_env():
    """Return the runtime environment status."""
    is_docker = os.path.exists("/.dockerenv")
    return {"is_docker": is_docker}

@app.get("/api/files")
async def list_files():
    """Return available forensic dataset files from vf_datasets/."""
    datasets_dir = Path(os.environ["EVIDENCE_ROOT"])
    extensions = {".E01", ".raw", ".dd", ".001", ".002", ".003", ".004", ".005", ".img"}
    files = []
    if datasets_dir.exists():
        for f in sorted(datasets_dir.iterdir()):
            if f.is_file() and (f.suffix.lower() in extensions or f.suffix == ""):
                size_mb = f.stat().st_size / (1024 * 1024)
                files.append({"name": f.name, "size_mb": round(size_mb, 1)})
    return {"files": files}

@app.get("/api/report/{incident_id}")
async def get_report(incident_id: str):
    """Return the JSON report for a given incident ID."""
    from fastapi.responses import JSONResponse
    report_path = Path(os.environ["CASES_DIR"]) / incident_id / "report" / "report.json"
    if not report_path.exists():
        return JSONResponse({"error": f"Report not found for {incident_id}"}, status_code=404)
    return JSONResponse(json.loads(report_path.read_text()))

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Accept any file upload and save it to the uploads/ directory."""
    # Use a UUID prefix to avoid filename collisions
    safe_name = f"{uuid.uuid4().hex[:8]}_{file.filename}"
    dest = uploads_dir / safe_name
    with dest.open("wb") as f_out:
        shutil.copyfileobj(file.file, f_out)
    size_mb = round(dest.stat().st_size / (1024 * 1024), 2)
    return {"file_name": safe_name, "original_name": file.filename, "size_mb": size_mb}


@app.get("/api/upload/{file_name}")
async def delete_upload(file_name: str):
    """Return info about an uploaded file."""
    path = uploads_dir / file_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return {"file_name": file_name, "size_mb": round(path.stat().st_size / (1024 * 1024), 2)}


@app.get("/api/download/{incident_id}/{file_type}")
async def download_report(incident_id: str, file_type: str):
    """Download the markdown or STIX report file."""
    from fastapi.responses import FileResponse as FR
    names = {"markdown": "report.md", "stix": "stix_bundle.json", "json": "report.json"}
    if file_type not in names:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "Invalid file_type"}, status_code=400)
    path = Path(os.environ["CASES_DIR"]) / incident_id / "report" / names[file_type]
    if not path.exists():
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "File not found"}, status_code=404)
    return FR(str(path), filename=f"{incident_id}_{names[file_type]}")

@app.websocket("/ws/triage")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    file_path = None
    is_upload = False
    sandbox = SandboxOrchestrator()
    try:
        data = await websocket.receive_text()
        request_data = json.loads(data)
        file_name = request_data.get("file_name")
        model_name = request_data.get("model_name", "")
        triage_timeout = int(request_data.get("timeout", 300))

        if not file_name:
            await websocket.send_text(json.dumps({"error": "No file_name provided"}))
            return
            
        # Resolve file from vf_datasets/ first, then uploads/
        file_path = Path(os.environ["EVIDENCE_ROOT"]) / file_name
        if not file_path.exists():
            file_path = uploads_dir / file_name
            is_upload = True
        if not file_path.exists():
            await websocket.send_text(json.dumps({"error": f"File not found: {file_name}"}))
            return
            
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

        # Prepare sandbox environment BEFORE importing the triage graph
        # (DynamicAnalysisSpecialist reads env vars at module init)
        sandbox_env = await sandbox.prepare(str(file_path), incident_id)
        for k, v in sandbox_env.items():
            if v:
                os.environ[k] = v
        await websocket.send_text(json.dumps({
            "sandbox_mode": sandbox.resolved_mode,
            "sandbox_url": sandbox.api_url or "mock",
            "model_selected": model_name or "default",
            "timeout": triage_timeout,
        }))

        # Override model if user selected one from dropdown
        if model_name:
            os.environ["OLLAMA_MODEL"] = model_name

        # Lazy import — env vars must be set before the specialist module initializes
        from agents.orchestrator import build_graph, AgentState

        initial_state = {
            "incident_id": incident_id,
            "session_start": datetime.now(timezone.utc).isoformat(),
            "sample_path": str(file_path),
            "memory_image_path": None,
            "iteration": 0,
            "max_iterations": 3,
            "node_timings": {},
            "errors": [],
            "hash_results": None,
            "vt_results": None,
            "yara_results": None,
            "volatility_results": {},
            "ioc_results": None,
            "dynamic_results": None,
            "firewall_rules": None,
            "findings": [],
            "inferences": [],
            "confidence_score": 0.0,
            "static_confidence_score": 0.0,
            "dynamic_confidence_score": 0.0,
            "validation_delta": 0.0,
            "hallucination_flags": [],
            "llm_model": model_name or None,
            "llm_analysis": None,
            "sandbox_actions_requested": [],
            "llm_iteration": 0,
            "max_llm_iterations": 3,
            "needs_correction": False,
            "correction_reason": "",
            "status": "running",
            "plan": [],
            "report_paths": {},
            "attack_techniques": [],
            "ioc_memory_warnings": [],
        }

        graph = build_graph()
        sent_interactive_count = 0
        
        try:
            async with asyncio.timeout(triage_timeout):
                async for output in graph.astream(initial_state):
                    for node_name, state in output.items():
                        interactive_results = state.get("dynamic_results", {}).get("interactive_results", []) if state.get("dynamic_results") else []
                        new_interactive = interactive_results[sent_interactive_count:]
                        sent_interactive_count = len(interactive_results)

                        await websocket.send_text(json.dumps({
                            "node": node_name,
                            "confidence": state.get("confidence_score", 0.0),
                            "verdict": state.get("verdict", "PENDING"),
                            "findings_count": len(state.get("findings", [])),
                            "iteration": state.get("iteration", 0),
                            "sandbox_actions": state.get("sandbox_actions_requested", []),
                            "new_interactive_results": new_interactive,
                            "llm_analysis": state.get("llm_analysis") if node_name == "llm_analysis" else None,
                            "attack_techniques": state.get("attack_techniques", []) if node_name == "enrich_intelligence" else None
                        }))
            await websocket.send_text(json.dumps({"status": "completed", "incident_id": incident_id}))
        except TimeoutError:
            try:
                await websocket.send_text(json.dumps({
                    "error": f"Triage timed out after {triage_timeout}s",
                    "status": "timeout",
                }))
            except RuntimeError:
                pass
        except WebSocketDisconnect:
            raise
        except Exception as graph_err:
            try:
                await websocket.send_text(json.dumps({"error": f"Graph error: {str(graph_err)}"}))
            except RuntimeError:
                pass # socket already closed
    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except Exception as e:
        await websocket.send_text(json.dumps({"error": str(e)}))
    finally:
        await sandbox.cleanup()
        if is_upload and file_path and file_path.exists():
            try:
                file_path.unlink()
                print(f"Deleted uploaded file: {file_path}")
            except Exception as e:
                print(f"Failed to delete uploaded file {file_path}: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
