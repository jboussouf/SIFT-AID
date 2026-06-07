import asyncio
import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sandbox_api")

app = FastAPI(title="Lightweight Sandbox API")

TASKS = {}
UPLOADS_DIR = Path("/tmp/sandbox_uploads")
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

class ExecuteCommand(BaseModel):
    command: str

class BlockNetwork(BaseModel):
    target: str
    target_type: str = "port"

@app.post("/apiv2/tasks/create/file/")
async def create_file_task(file: UploadFile = File(...)):
    task_id = f"task_{uuid.uuid4().hex[:8]}"
    file_path = UPLOADS_DIR / f"{task_id}_{file.filename}"
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    
    TASKS[task_id] = {
        "status": "running",
        "file_path": str(file_path),
        "filename": file.filename,
        "start_time": time.time()
    }
    log.info(f"Created task {task_id} for {file.filename}")
    return {"error": False, "data": {"task_ids": [task_id]}}

@app.get("/apiv2/tasks/get/report/{task_id}/")
async def get_report(task_id: str):
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = TASKS[task_id]
    
    # Simple heuristic to return benign or malicious report based on filename for testing
    is_benign = False
    name = task["filename"].lower()
    _BENIGN_BINARIES = {"cmp", "ls", "dd", "file", "stat", "xargs", "bash", "sh"}
    if name in _BENIGN_BINARIES:
        is_benign = True

    # Build report
    report = {
        "info": {"score": 0.5 if is_benign else 8.5},
        "signatures": [] if is_benign else [
            {"description": "Modifies Proxy Settings", "name": "proxy_mod", "attck_ids": ["T1090"]},
            {"description": "Creates Suspicious Registry Key", "name": "susp_reg", "attck_ids": ["T1112"]}
        ],
        "network": {
            "dns": [] if is_benign else [{"request": "evil-c2.example.com", "answers": [{"data": "198.51.100.2"}]}],
            "http": [] if is_benign else [{"uri": "http://evil-c2.example.com/checkin"}]
        },
        "behavior": {
            "processes": [
                {"process_name": name, "pid": 4321, "calls": []}
            ],
            "summary": {
                "file_created": [] if is_benign else ["C:\\Users\\Public\\payload.exe"]
            }
        }
    }
    return {"error": False, "data": report}

@app.post("/apiv2/tasks/execute/{task_id}/")
async def execute_command(task_id: str, payload: ExecuteCommand):
    cmd = payload.command.lower()
    log.info(f"Executing command on {task_id}: {cmd}")
    return {
        "stdout": f"Command '{payload.command}' executed successfully in sandbox container.",
        "stderr": "",
        "return_code": 0
    }

@app.post("/apiv2/tasks/block/{task_id}/")
async def block_network(task_id: str, payload: BlockNetwork):
    log.info(f"Blocking {payload.target_type} {payload.target} on {task_id}")
    return {
        "action": f"Blocked {payload.target_type}: {payload.target}",
        "status": "active",
        "rule": "nft add rule ip filter output drop"
    }

@app.get("/apiv2/tasks/status/{task_id}/")
async def get_status(task_id: str):
    return {
        "vm_status": "running",
        "uptime_seconds": 124,
        "processes": [
            {"name": "malware.exe", "pid": 4321, "state": "running", "cpu": 12.0, "memory_mb": 45}
        ],
        "network_connections": [],
        "blocked_rules": []
    }

@app.get("/apiv2/tasks/get/dropped/{task_id}/")
async def get_dropped(task_id: str):
    return {"data": []}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
