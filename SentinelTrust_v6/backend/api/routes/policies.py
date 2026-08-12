from fastapi import APIRouter, Request, Header
from typing import Optional
router = APIRouter()

def _get_user(request, x_user_email):
    email = x_user_email or request.headers.get("x-user-email","")
    if not email:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Missing X-User-Email header")
    return email

@router.get("/")
async def get_policies(request: Request, x_user_email: Optional[str] = Header(None)):
    return {"policies": [
        {"id":"p1","name":"Max DNS Queries","threshold":150,"action":"alert"},
        {"id":"p2","name":"Max External Connections","threshold":5,"action":"alert"},
        {"id":"p3","name":"TCP Flag Anomaly","threshold":0.3,"action":"block"},
        {"id":"p4","name":"Port Entropy Limit","threshold":3.5,"action":"alert"},
    ]}
