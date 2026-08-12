from fastapi import APIRouter, Request, Header
from typing import Optional
import time
router = APIRouter()

def _get_user(request, x_user_email):
    email = x_user_email or request.headers.get("x-user-email","")
    if not email:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Missing X-User-Email header")
    return email

@router.get("/")
async def get_alerts(request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    scores = request.app.state.trust_engine.get_all_scores(user)
    alerts = [
        {"id": f"alert-{s['device_id']}", "device_id": s["device_id"],
         "severity": "critical" if s["score"]<30 else "high" if s["score"]<50 else "medium",
         "score": s["score"], "explanation": s["explanation"],
         "risk_factors": s["top_risk_factors"], "timestamp": s["timestamp"]}
        for s in scores if s["anomaly_detected"] or s["score"] < 60
    ]
    return {"alerts": alerts, "count": len(alerts)}
