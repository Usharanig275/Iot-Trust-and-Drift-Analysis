"""SentinelTrust - Backend API v5 (per-user isolation + auto email alerts)"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio, logging, time, json, os
from contextlib import asynccontextmanager
from services.trust_engine import TrustEngine
from services.websocket_manager import WebSocketManager
from services.telemetry_processor import TelemetryProcessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentineltrust")

ws_manager = WebSocketManager()
trust_engine = TrustEngine()
telemetry_processor = TelemetryProcessor(trust_engine, ws_manager)

AUTH_FILE = os.path.join(os.path.dirname(__file__), "auth_store.json")
_alerted: dict = {}  # {user_email+device_id: last_alert_time}

def _load_auth():
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE) as f: return json.load(f)
        except: pass
    return {"users": {}, "admins": {}}

async def auto_alert_loop():
    """Background: check every 30s, email each user about THEIR anomalous devices."""
    from api.routes.notifications import _send_email, ATTACK_IP_MAP
    while True:
        try:
            auth = _load_auth()
            for email, user in auth.get("users", {}).items():
                scores = trust_engine.get_all_scores(email)
                devices = trust_engine.get_device_list(email)
                dev_map = {d["id"]: d for d in devices}
                for s in scores:
                    is_anomaly = s.get("anomaly_detected") or s["score"] < 40
                    key = f"{email}:{s['device_id']}"
                    last = _alerted.get(key, 0)
                    if is_anomaly and (time.time() - last) > 300:
                        _alerted[key] = time.time()
                        dev = dev_map.get(s["device_id"], {})
                        attack = (trust_engine._attack_mode.get(email) or {}).get(s["device_id"])
                        asyncio.create_task(asyncio.to_thread(
                            _send_email,
                            email, user.get("name","User"),
                            s["device_id"], s["score"], s["level"],
                            s.get("explanation",""), s.get("top_risk_factors",[]),
                            attack, ATTACK_IP_MAP.get(attack or "",""),
                            dev.get("ip")
                        ))
                        logger.info(f"Auto-alert → {email} for {s['device_id']} score={s['score']}")
                    elif not is_anomaly and key in _alerted:
                        del _alerted[key]
        except Exception as e:
            logger.error(f"Auto-alert loop error: {e}")
        await asyncio.sleep(30)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await trust_engine.initialize()
    t1 = asyncio.create_task(telemetry_processor.run_scoring_loop())
    t2 = asyncio.create_task(auto_alert_loop())
    yield
    t1.cancel(); t2.cancel()

app = FastAPI(title="SentinelTrust API", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.state.trust_engine = trust_engine
app.state.ws_manager = ws_manager

from api.routes import devices, trust, alerts, simulator, policies, auth, notifications
app.include_router(devices.router,       prefix="/api/v1/devices",       tags=["Devices"])
app.include_router(trust.router,         prefix="/api/v1/trust",         tags=["Trust"])
app.include_router(alerts.router,        prefix="/api/v1/alerts",        tags=["Alerts"])
app.include_router(simulator.router,     prefix="/api/v1/simulator",     tags=["Simulator"])
app.include_router(policies.router,      prefix="/api/v1/policies",      tags=["Policies"])
app.include_router(auth.router,          prefix="/api/v1/auth",          tags=["Auth"])
app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["Notifications"])

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True: await asyncio.sleep(1)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "SentinelTrust", "version": "2.0.0"}
