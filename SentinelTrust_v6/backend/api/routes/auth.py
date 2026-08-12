"""
SentinelTrust - Auth Routes
- User registration/login (unlimited users)
- Admin registration/login (ONE admin only)
- Admin data endpoint: returns all users, devices, alerts, notifications
"""

import json, os, time, hashlib
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

AUTH_FILE          = os.path.join(os.path.dirname(__file__), "..", "..", "auth_store.json")
DEVICES_FILE       = os.path.join(os.path.dirname(__file__), "..", "..", "devices_store.json")
NOTIFICATIONS_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "notifications_store.json")

def _load_auth():
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"users": {}, "admins": {}}

def _save_auth(store):
    with open(AUTH_FILE, "w") as f:
        json.dump(store, f, indent=2)

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ── Models ─────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    name: str
    email: str
    phone: str
    password: str

class AdminRegister(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str
    role: str  # "user" or "admin"

# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/register/user")
async def register_user(body: UserRegister):
    store = _load_auth()
    if body.email in store["users"]:
        raise HTTPException(status_code=400, detail="Email already registered")
    store["users"][body.email] = {
        "name": body.name,
        "email": body.email,
        "phone": body.phone,
        "password": _hash(body.password),
        "role": "user",
        "created_at": time.time(),
    }
    _save_auth(store)
    return {"status": "registered", "role": "user", "name": body.name, "email": body.email}

@router.post("/register/admin")
async def register_admin(body: AdminRegister):
    store = _load_auth()
    # ONE admin only
    if len(store["admins"]) >= 1:
        raise HTTPException(status_code=400, detail="An admin account already exists. Only one admin is allowed.")
    store["admins"][body.email] = {
        "name": body.name,
        "email": body.email,
        "password": _hash(body.password),
        "role": "admin",
        "created_at": time.time(),
    }
    _save_auth(store)
    return {"status": "registered", "role": "admin", "name": body.name, "email": body.email}

@router.post("/login")
async def login(body: LoginRequest):
    store = _load_auth()
    if body.role == "user":
        user = store["users"].get(body.email)
        if not user or user["password"] != _hash(body.password):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        return {
            "status": "ok",
            "token": _hash(body.email + body.password + "user"),
            "role": "user",
            "name": user["name"],
            "email": user["email"],
            "phone": user["phone"],
        }
    elif body.role == "admin":
        admin = store["admins"].get(body.email)
        if not admin or admin["password"] != _hash(body.password):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        return {
            "status": "ok",
            "token": _hash(body.email + body.password + "admin"),
            "role": "admin",
            "name": admin["name"],
            "email": admin["email"],
        }
    raise HTTPException(status_code=400, detail="Invalid role")

@router.get("/admin/dashboard-data")
async def admin_dashboard_data():
    """Returns ALL data for admin dashboard view."""
    # Users
    auth = _load_auth()
    users = [
        {
            "name": u["name"],
            "email": u["email"],
            "phone": u["phone"],
            "joined": time.strftime("%Y-%m-%d %H:%M", time.localtime(u["created_at"])),
        }
        for u in auth["users"].values()
    ]

    # Devices + scores — scan ALL user_data folders (per-user isolation)
    devices = []
    baselines = []
    USER_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "user_data")
    if os.path.exists(USER_DATA_DIR):
        for folder in os.listdir(USER_DATA_DIR):
            store_path = os.path.join(USER_DATA_DIR, folder, "store.json")
            if not os.path.exists(store_path):
                continue
            try:
                with open(store_path) as ff:
                    ds = json.load(ff)
                owner = folder.replace("_at_", "@")
                for d in ds.get("devices", {}).values():
                    devices.append({
                        "id": d["id"], "name": d["name"],
                        "type": d["type"], "ip": d["ip"],
                        "has_baseline": d.get("has_baseline", False),
                        "test_count": d.get("test_count", 0),
                        "owner": owner,
                        "registered_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(d.get("registered_at", 0))),
                    })
                for did, bl in ds.get("baselines", {}).items():
                    baselines.append({
                        "device_id": did, "owner": owner,
                        "n_samples": bl.get("n_samples", 0),
                        "trained_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(bl.get("trained_at", 0))),
                        "features": bl.get("feature_cols", []),
                    })
            except Exception:
                pass

    # Notifications
    notifications = []
    if os.path.exists(NOTIFICATIONS_FILE):
        try:
            with open(NOTIFICATIONS_FILE) as f:
                ns = json.load(f)
            for n in ns.get("notifications", [])[-50:]:
                notifications.append({
                    "device_id": n.get("device_id"),
                    "to_email": n.get("to_email"),
                    "score": n.get("score"),
                    "level": n.get("level"),
                    "explanation": n.get("explanation"),
                    "attack_type": n.get("attack_type"),
                    "suspicious_ips": n.get("suspicious_ips", []),
                    "sent_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(n.get("sent_at", 0))),
                    "email_sent": n.get("email_sent", False),
                })
        except Exception:
            pass

    return {
        "users": users,
        "devices": devices,
        "baselines": baselines,
        "notifications": list(reversed(notifications)),
        "summary": {
            "total_users": len(users),
            "total_devices": len(devices),
            "total_alerts": len(notifications),
            "devices_with_baseline": sum(1 for d in devices if d["has_baseline"]),
        }
    }

@router.get("/users")
async def list_users():
    store = _load_auth()
    return {"users": [
        {"name": u["name"], "email": u["email"], "phone": u["phone"]}
        for u in store["users"].values()
    ]}

@router.get("/admin/users-full")
async def admin_users_full():
    """Admin-only: returns all user records including password hashes."""
    auth = _load_auth()
    users = []
    for u in auth["users"].values():
        users.append({
            "name": u["name"],
            "email": u["email"],
            "phone": u.get("phone", ""),
            "password_hash": u["password"],   # SHA-256 hex string
            "role": u.get("role", "user"),
            "joined": time.strftime("%Y-%m-%d %H:%M", time.localtime(u.get("created_at", 0))),
        })
    return {"users": users}

@router.get("/admin/exists")
async def admin_exists():
    store = _load_auth()
    return {"exists": len(store["admins"]) >= 1}
