"""
HF Guardian - FastAPI Server with Continuous Intrusion Monitoring & Real-time Alerts
"""

import sys
import json
import time
import asyncio
import traceback
from pathlib import Path
from dataclasses import asdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))
from scanner import HFScanner, Severity
from monitor import monitor_engine, TargetType, AlertSeverity
import auth
from database import db_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Attempt connecting to MongoDB Atlas asynchronously
    asyncio.create_task(asyncio.to_thread(db_manager.connect))

    # Start continuous monitor loop
    await monitor_engine.start()
    yield
    # Cleanup
    await monitor_engine.stop()

app = FastAPI(title="Sentinel", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

scanner = HFScanner()
_cache: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 300

# ─── Pydantic Models ─────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_id: str

class AddTargetRequest(BaseModel):
    name: str = ""
    target_type: str = "website" # website or huggingface
    url_or_repo: str
    interval_seconds: int = 30
    webhook_url: str = ""
    alert_emails: str = ""

class UpdateTargetRequest(BaseModel):
    name: str = ""
    target_type: str = ""
    url_or_repo: str = ""
    interval_seconds: int = 0
    webhook_url: str = ""
    alert_emails: str = ""

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class SignupRequest(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: str = "Security Analyst"

# ─── Frontend Entrypoint ───────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    html_path = Path(__file__).parent.parent / "frontend" / "index.html"
    return HTMLResponse(html_path.read_text())

@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    html_path = Path(__file__).parent.parent / "frontend" / "login.html"
    return HTMLResponse(html_path.read_text())

# ─── Authentication API (MongoDB Atlas) ────────────────────────────────────

@app.post("/api/auth/signup")
async def api_signup(req: SignupRequest):
    try:
        res = auth.register_user(
            username=req.username,
            email=req.email,
            full_name=req.full_name,
            password=req.password,
            role=req.role
        )
        return JSONResponse(res)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {e}")

@app.post("/api/auth/login")
async def api_login(req: LoginRequest):
    try:
        res = auth.authenticate_user(
            login_identifier=req.username_or_email,
            password=req.password
        )
        return JSONResponse(res)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {e}")

@app.get("/api/auth/me")
async def api_me(request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=401, detail="Authentication token missing")
    payload = auth.decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    user = auth.get_user_by_id(payload.get("sub"))
    if not user:
        return JSONResponse({
            "id": payload.get("sub"),
            "username": payload.get("username"),
            "email": payload.get("email"),
            "full_name": payload.get("full_name"),
            "role": payload.get("role")
        })
    return JSONResponse(user)

@app.get("/api/db/status")
async def api_db_status():
    return {
        "type": "MongoDB Atlas",
        "connected": db_manager.is_connected,
        "database": db_manager.db_name
    }

# ─── Continuous Monitoring API ──────────────────────────────────────────────

@app.get("/api/targets")
async def list_targets():
    return JSONResponse(monitor_engine.get_targets())

@app.post("/api/targets")
async def add_target(req: AddTargetRequest):
    if not req.url_or_repo.strip():
        raise HTTPException(400, "URL or repository identifier is required")
    target = monitor_engine.add_target(
        name=req.name,
        target_type=req.target_type,
        url_or_repo=req.url_or_repo,
        interval_seconds=req.interval_seconds,
        webhook_url=req.webhook_url,
        alert_emails=req.alert_emails
    )
    # Trigger an immediate background scan for the new target
    asyncio.create_task(monitor_engine.scan_target(target))
    return JSONResponse(asdict(target))

@app.put("/api/targets/{target_id}")
async def update_target(target_id: str, req: UpdateTargetRequest):
    updated = monitor_engine.update_target(
        target_id=target_id,
        name=req.name if req.name else None,
        target_type=req.target_type if req.target_type else None,
        url_or_repo=req.url_or_repo if req.url_or_repo else None,
        interval_seconds=req.interval_seconds if req.interval_seconds > 0 else None,
        webhook_url=req.webhook_url if req.webhook_url else None,
        alert_emails=req.alert_emails if req.alert_emails else None
    )
    if not updated:
        raise HTTPException(404, "Target not found")
    return JSONResponse(asdict(updated))

@app.delete("/api/targets/{target_id}")
async def remove_target(target_id: str):
    success = monitor_engine.remove_target(target_id)
    if not success:
        raise HTTPException(404, "Target not found")
    return JSONResponse({"status": "deleted", "target_id": target_id})

@app.post("/api/targets/{target_id}/scan")
async def force_scan_target(target_id: str):
    target = monitor_engine.targets.get(target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    asyncio.create_task(monitor_engine.scan_target(target))
    return JSONResponse({"status": "scan_initiated", "target_id": target_id})

@app.post("/api/targets/{target_id}/simulate-attack")
async def simulate_attack_on_target(target_id: str):
    alert = monitor_engine.simulate_attack(target_id)
    if not alert:
        raise HTTPException(404, "Target not found")
    return JSONResponse({"status": "attack_simulated", "alert": asdict(alert)})

@app.get("/api/alerts")
async def list_alerts(limit: int = 50):
    return JSONResponse(monitor_engine.get_alerts(limit=limit))

@app.post("/api/alerts/{alert_id}/ack")
async def acknowledge_alert(alert_id: str):
    success = monitor_engine.acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(404, "Alert not found")
    return JSONResponse({"status": "acknowledged", "alert_id": alert_id})

@app.post("/api/alerts/clear")
async def clear_all_alerts():
    monitor_engine.clear_alerts()
    return JSONResponse({"status": "cleared"})

# ─── Live SSE Stream ────────────────────────────────────────────────────────

@app.get("/api/events")
async def sse_events(request: Request):
    """Server-Sent Events streaming for instantaneous real-time alerts and state updates."""
    queue = monitor_engine.subscribe()

    async def event_generator():
        try:
            # Send initial connected ping
            yield f"data: {json.dumps({'type': 'connected', 'timestamp': time.time()})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat
                    yield f": heartbeat {time.time()}\n\n"
        finally:
            monitor_engine.unsubscribe(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ─── On-Demand Instant Scan API ─────────────────────────────────────────────

@app.post("/api/scan")
async def scan_repo(req: ScanRequest):
    repo_id = req.repo_id.strip().strip("/")
    if not repo_id:
        raise HTTPException(400, "repo_id is required")

    now = time.time()
    if repo_id in _cache:
        ts, cached = _cache[repo_id]
        if now - ts < CACHE_TTL:
            return JSONResponse({"cached": True, **cached})

    try:
        result = await asyncio.to_thread(scanner.scan_repo, repo_id)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, f"Scan failed: {e}")

    result_dict = {
        "repo_id": result.repo_id,
        "risk_score": result.risk_score,
        "scan_error": result.scan_error,
        "files_scanned": result.files_scanned,
        "metadata": result.metadata,
        "threats": [
            {
                "id": t.id,
                "title": t.title,
                "severity": t.severity.value,
                "category": t.category,
                "description": t.description,
                "evidence": t.evidence,
                "mitigation": t.mitigation,
                "cve": t.cve,
            }
            for t in result.threats
        ],
    }

    _cache[repo_id] = (now, result_dict)
    return JSONResponse({"cached": False, **result_dict})

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "Sentinel",
        "monitored_targets_count": len(monitor_engine.targets),
        "total_alerts": len(monitor_engine.alerts)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
