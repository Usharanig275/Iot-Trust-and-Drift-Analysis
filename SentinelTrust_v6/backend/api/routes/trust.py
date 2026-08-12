from fastapi import APIRouter, Request, Header
from typing import Optional
router = APIRouter()

def _get_user(request, x_user_email):
    email = x_user_email or request.headers.get("x-user-email","")
    if not email:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Missing X-User-Email header")
    return email

@router.get("/scores")
async def all_scores(request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return {"scores": request.app.state.trust_engine.get_all_scores(user)}

@router.get("/health")
async def network_health(request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return request.app.state.trust_engine.get_network_health(user)

@router.get("/history/{device_id}")
async def score_history(device_id: str, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return {"device_id": device_id, "history": request.app.state.trust_engine.get_history(user, device_id)}
