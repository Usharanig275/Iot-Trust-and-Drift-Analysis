import csv, io
from fastapi import APIRouter, Request, UploadFile, File, Header
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter()

FEATURE_COLS = [
    "packet_rate","byte_entropy","protocol_tcp_ratio","dns_query_freq",
    "unique_dest_ips","avg_connection_duration","port_entropy",
    "bandwidth_mbps","new_ext_conns","tcp_flag_anomaly",
]

class RegisterDevice(BaseModel):
    id: str; name: str; type: str; ip: str; description: Optional[str] = ""

class TestDataRow(BaseModel):
    packet_rate: Optional[float]=None; byte_entropy: Optional[float]=None
    protocol_tcp_ratio: Optional[float]=None; dns_query_freq: Optional[float]=None
    unique_dest_ips: Optional[float]=None; avg_connection_duration: Optional[float]=None
    port_entropy: Optional[float]=None; bandwidth_mbps: Optional[float]=None
    new_ext_conns: Optional[float]=None; tcp_flag_anomaly: Optional[float]=None

class BatchTestData(BaseModel):
    rows: List[TestDataRow]

def _parse_csv(content: bytes) -> list:
    text = content.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        parsed = {}
        for k, v in row.items():
            k = k.strip()
            try: parsed[k] = float(v.strip()) if v.strip() else None
            except ValueError: parsed[k] = v.strip()
        rows.append(parsed)
    return rows

def _get_user(request: Request, x_user_email: Optional[str]) -> str:
    email = x_user_email or request.headers.get("x-user-email","")
    if not email:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Missing X-User-Email header")
    return email

@router.get("/")
async def list_devices(request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return {"devices": request.app.state.trust_engine.get_device_list(user)}

@router.post("/register")
async def register_device(body: RegisterDevice, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return request.app.state.trust_engine.register_device(user, body.id, body.name, body.type, body.ip, body.description or "")

@router.delete("/{device_id}")
async def delete_device(device_id: str, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return request.app.state.trust_engine.delete_device(user, device_id)

@router.get("/{device_id}/score")
async def device_score(device_id: str, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    score = request.app.state.trust_engine.get_score(user, device_id)
    return score or {"error": "Device not found or not yet scored"}

@router.get("/{device_id}/history")
async def device_history(device_id: str, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return {"device_id": device_id, "history": request.app.state.trust_engine.get_history(user, device_id)}

@router.get("/{device_id}/baseline")
async def get_baseline(device_id: str, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    return request.app.state.trust_engine.get_baseline(user, device_id)

@router.post("/{device_id}/baseline")
async def upload_baseline_csv(device_id: str, request: Request, file: UploadFile = File(...), x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    content = await file.read()
    rows = _parse_csv(content)
    if not rows: return {"error": "Empty or invalid CSV"}
    return request.app.state.trust_engine.train_baseline(user, device_id, rows)

@router.post("/{device_id}/test")
async def score_single(device_id: str, body: TestDataRow, request: Request, x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    features = {k: v for k, v in body.dict().items() if v is not None}
    return request.app.state.trust_engine.score_test_data(user, device_id, features)

@router.post("/{device_id}/test/csv")
async def score_csv(device_id: str, request: Request, file: UploadFile = File(...), x_user_email: Optional[str] = Header(None)):
    user = _get_user(request, x_user_email)
    content = await file.read()
    rows = _parse_csv(content)
    if not rows: return {"error": "Empty or invalid CSV"}
    return request.app.state.trust_engine.score_batch(user, device_id, rows)

@router.get("/features/schema")
async def feature_schema():
    return {"feature_columns": FEATURE_COLS}
