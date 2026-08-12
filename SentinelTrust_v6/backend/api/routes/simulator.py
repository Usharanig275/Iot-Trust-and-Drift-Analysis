from fastapi import APIRouter, Request, Header
from pydantic import BaseModel
from typing import Optional
router = APIRouter()

def _get_user(request, x_user_email):
    email = x_user_email or request.headers.get("x-user-email","")
    if not email:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Missing X-User-Email header")
    return email

class AttackReq(BaseModel):
    device_id: str; attack_type: str

class StopReq(BaseModel):
    device_id: Optional[str] = None

@router.post("/trigger")
async def trigger(body: AttackReq, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    valid = ["mirai","exfiltration","lateral_movement","port_scan"]
    if body.attack_type not in valid:
        return {"error": f"Choose from: {valid}"}
    request.app.state.trust_engine.trigger_attack(user, body.device_id, body.attack_type)
    return {"status": "triggered", "device_id": body.device_id, "attack": body.attack_type}

@router.post("/stop")
async def stop(body: StopReq, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    if body.device_id:
        request.app.state.trust_engine.stop_attack(user, body.device_id)
        return {"status": "stopped", "device_id": body.device_id}
    request.app.state.trust_engine.stop_all_attacks(user)
    return {"status": "all_stopped"}

@router.get("/attacks")
async def list_attacks():
    return {"attacks": [
        {"id":"mirai","name":"Mirai Botnet","desc":"SYN flood targeting IoT Telnet/SSH"},
        {"id":"exfiltration","name":"Data Exfiltration","desc":"DNS tunneling covert channel"},
        {"id":"lateral_movement","name":"Lateral Movement","desc":"Internal subnet scanning"},
        {"id":"port_scan","name":"Port Scan","desc":"Service enumeration sweep"},
    ]}
