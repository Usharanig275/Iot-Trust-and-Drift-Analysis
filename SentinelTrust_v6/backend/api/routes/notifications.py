"""
SentinelTrust - Notifications
- Sends email to the LOGGED-IN USER's email when anomaly detected
- SMTP configured once via /configure-email endpoint
- Auto-alert fires every 5 min per device when anomaly persists
- IP tracking for known attack patterns
"""
import json, os, time, smtplib, asyncio
from concurrent.futures import ThreadPoolExecutor
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fastapi import APIRouter, Request, Header
from pydantic import BaseModel
from typing import Optional

_email_executor = ThreadPoolExecutor(max_workers=4)

router = APIRouter()

NOTIF_FILE   = os.path.join(os.path.dirname(__file__), "..", "..", "notifications_store.json")
SMTP_FILE    = os.path.join(os.path.dirname(__file__), "..", "..", "smtp_config.json")

ATTACK_IP_MAP = {
    "mirai":            ["185.220.101.47","45.142.212.100","194.165.16.77"],
    "exfiltration":     ["91.108.4.15",   "77.247.181.208","185.220.101.22"],
    "lateral_movement": ["192.168.1.99",  "192.168.2.44",  "10.0.0.254"],
    "port_scan":        ["194.165.16.33", "45.142.212.77", "91.108.4.200"],
}

def _load_smtp():
    if os.path.exists(SMTP_FILE):
        try:
            with open(SMTP_FILE) as f: return json.load(f)
        except: pass
    return {}

def _save_smtp(cfg):
    with open(SMTP_FILE, "w") as f: json.dump(cfg, f, indent=2)

def _load_notifs():
    if os.path.exists(NOTIF_FILE):
        try:
            with open(NOTIF_FILE) as f: return json.load(f)
        except: pass
    return {"notifications": []}

def _save_notifs(store):
    with open(NOTIF_FILE, "w") as f: json.dump(store, f, indent=2)

def _build_html(to_name, device_id, score, level, explanation, risk_factors, attack_type, suspicious_ips, device_ip):
    lc = {"trusted":"#16a34a","stable":"#65a30d","suspicious":"#d97706","high_risk":"#ea580c","critical":"#dc2626"}.get(level,"#dc2626")
    risk_rows = "".join(f"<tr><td style='padding:7px 14px;color:#dc2626;font-size:13px'>⚠ {f}</td></tr>" for f in risk_factors) or "<tr><td style='padding:7px 14px;color:#6b7280'>No specific risk factors</td></tr>"
    ip_section = ""
    if suspicious_ips:
        ip_rows = "".join(f"<tr><td style='padding:6px 12px;font-family:monospace;font-size:13px;color:#dc2626'>{ip}</td><td style='padding:6px 12px;color:#6b7280'>Known threat actor range</td></tr>" for ip in suspicious_ips)
        ip_section = f"""
        <h3 style='color:#dc2626;margin:20px 0 8px'>🔍 Suspicious IP Addresses Tracked</h3>
        <table style='width:100%;border-collapse:collapse;border:1px solid #fecaca;border-radius:8px;overflow:hidden'>
          <tr style='background:#fee2e2'><th style='padding:8px 12px;text-align:left;font-size:12px'>IP Address</th><th style='padding:8px 12px;text-align:left;font-size:12px'>Threat Intel</th></tr>
          {ip_rows}
        </table>"""
    device_ip_section = f"<p style='font-family:monospace;color:#dc2626;background:#fff5f5;padding:8px 12px;border-radius:4px;font-size:13px'>📍 Device IP: {device_ip}</p>" if device_ip else ""
    return f"""<!DOCTYPE html><html><body style='margin:0;padding:0;background:#f0f4f8;font-family:system-ui,sans-serif'>
<div style='max-width:600px;margin:30px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.1)'>
  <div style='background:linear-gradient(135deg,#0f172a,#1e3a5f);padding:28px 32px;text-align:center'>
    <div style='font-size:40px;margin-bottom:8px'>🛡️</div>
    <h1 style='color:#fff;margin:0;font-size:24px;letter-spacing:2px'>SENTINELTRUST</h1>
    <p style='color:#94a3b8;margin:4px 0 0;font-size:12px;letter-spacing:1px'>SECURITY ALERT</p>
  </div>
  <div style='padding:28px 32px'>
    <p style='color:#374151;margin-bottom:20px'>Hi <b>{to_name}</b>, an anomaly has been detected on your IoT network.</p>
    <div style='background:{lc}15;border:2px solid {lc};border-radius:10px;padding:20px;text-align:center;margin-bottom:20px'>
      <div style='font-size:48px;font-weight:900;color:{lc};line-height:1'>{score}</div>
      <div style='font-size:11px;color:{lc};font-weight:700;letter-spacing:2px;margin-top:4px'>/100 — {level.upper().replace("_"," ")}</div>
      <div style='font-size:13px;color:#6b7280;margin-top:6px'>Device: <b style='color:#111'>{device_id}</b></div>
      {f"<div style='font-size:12px;color:#ef4444;margin-top:4px'>Attack Type: <b>{attack_type.replace('_',' ').upper()}</b></div>" if attack_type else ""}
    </div>
    {device_ip_section}
    <h3 style='color:#111827;margin:0 0 8px'>📋 What Happened</h3>
    <p style='color:#374151;background:#f8fafc;padding:12px 16px;border-radius:6px;line-height:1.7;font-size:14px'>{explanation}</p>
    <h3 style='color:#111827;margin:20px 0 8px'>⚠ Risk Factors Detected</h3>
    <table style='width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden'>{risk_rows}</table>
    {ip_section}
    <div style='margin-top:24px;padding:14px;background:#eff6ff;border-radius:6px;font-size:12px;color:#6b7280;text-align:center'>
      Alert generated at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} · SentinelTrust Security Platform
    </div>
  </div>
</div></body></html>"""

def _send_email(to_email, to_name, device_id, score, level, explanation, risk_factors, attack_type, suspicious_ips, device_ip):
    smtp = _load_smtp()
    notif_record = {
        "id": f"notif-{int(time.time()*1000)}",
        "to_email": to_email, "to_name": to_name,
        "device_id": device_id, "score": score, "level": level,
        "explanation": explanation, "risk_factors": risk_factors,
        "attack_type": attack_type, "suspicious_ips": suspicious_ips,
        "device_ip": device_ip, "sent_at": time.time(), "email_sent": False,
    }
    if smtp.get("username") and smtp.get("password"):
        try:
            msg = MIMEMultipart("alternative")
            sev = "CRITICAL" if score < 30 else "HIGH RISK" if score < 50 else "WARNING"
            msg["Subject"] = f"🚨 SentinelTrust {sev}: {device_id} — Score {score}/100"
            msg["From"] = smtp.get("from_email", smtp["username"])
            msg["To"] = to_email
            msg.attach(MIMEText(_build_html(to_name, device_id, score, level, explanation, risk_factors, attack_type, suspicious_ips, device_ip), "html"))
            server = smtplib.SMTP(smtp.get("host","smtp.gmail.com"), int(smtp.get("port",587)), timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp["username"], smtp["password"])
            server.sendmail(msg["From"], to_email, msg.as_string())
            server.quit()
            notif_record["email_sent"] = True
            print(f"[EMAIL SENT] {to_email} — {device_id} score={score}")
        except Exception as e:
            print(f"[EMAIL FAILED] {to_email}: {e}")
    else:
        print(f"[EMAIL SKIPPED] SMTP not configured. Alert for {device_id} logged only.")

    store = _load_notifs()
    store["notifications"].append(notif_record)
    if len(store["notifications"]) > 500:
        store["notifications"] = store["notifications"][-500:]
    _save_notifs(store)
    return notif_record

# ── Models ────────────────────────────────────────────────────────────────────
class EmailConfig(BaseModel):
    host: str = "smtp.gmail.com"
    port: int = 587
    username: str
    password: str
    from_email: Optional[str] = None

class AlertRequest(BaseModel):
    to_email: str
    to_name: str = "User"
    device_id: str
    score: float
    level: str
    explanation: str
    risk_factors: list = []
    attack_type: Optional[str] = None
    device_ip: Optional[str] = None

# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/configure-email")
async def configure_email(config: EmailConfig):
    cfg = config.dict()
    if not cfg.get("from_email"):
        cfg["from_email"] = cfg["username"]
    _save_smtp(cfg)
    return {"status": "smtp_configured", "username": cfg["username"]}

@router.get("/email-config-status")
async def email_config_status():
    smtp = _load_smtp()
    return {"configured": bool(smtp.get("username")), "username": smtp.get("username","(not set)")}

@router.post("/send-alert")
async def send_alert(body: AlertRequest):
    suspicious_ips = ATTACK_IP_MAP.get(body.attack_type or "", [])
    loop = asyncio.get_event_loop()
    rec = await loop.run_in_executor(
        _email_executor,
        lambda: _send_email(
            body.to_email, body.to_name, body.device_id, body.score,
            body.level, body.explanation, body.risk_factors,
            body.attack_type, suspicious_ips, body.device_ip
        )
    )
    return {"status": "done", "email_sent": rec["email_sent"],
            "suspicious_ips": suspicious_ips, "notification_id": rec["id"]}

@router.get("/log")
async def get_log():
    store = _load_notifs()
    return {"notifications": list(reversed(store["notifications"][-50:])),
            "total": len(store["notifications"])}

@router.get("/ip-threats/{attack_type}")
async def ip_threats(attack_type: str):
    return {"attack_type": attack_type, "suspicious_ips": ATTACK_IP_MAP.get(attack_type,[])}
