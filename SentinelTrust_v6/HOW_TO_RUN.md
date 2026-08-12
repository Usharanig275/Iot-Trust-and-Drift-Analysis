# ▶️ How to Run SentinelTrust in VSCode

Follow these steps exactly. You need **Python 3.10+** and **Node.js 18+** installed.

---

## STEP 1 — Open the project in VSCode

1. Open VSCode
2. File → Open Folder → select the `SentinelTrust` folder
3. You should see this structure in the Explorer panel:
   ```
   SentinelTrust/
   ├── backend/
   ├── frontend/
   ├── ml/
   ├── simulator/
   └── HOW_TO_RUN.md  ← you are here
   ```

---

## STEP 2 — Start the Backend (Terminal 1)

Open a new terminal in VSCode: **Terminal → New Terminal**

```bash
cd backend
pip install fastapi "uvicorn[standard]" pydantic websockets numpy
uvicorn main:app --reload --port 8000
```

✅ You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

Test it: open http://localhost:8000/health in your browser → should return `{"status":"healthy"}`

Open http://localhost:8000/docs to see all API endpoints with live testing UI.

---

## STEP 3 — Start the Frontend (Terminal 2)

Open a **second terminal**: click the **+** icon in the terminal panel.

```bash
cd frontend
npm install
npm start
```

✅ After ~30 seconds the browser opens automatically at **http://localhost:3000**

If it doesn't open automatically, visit http://localhost:3000 manually.

---

## STEP 4 — Use the Dashboard

Once both terminals are running:

1. **Dashboard tab** — see all 8 IoT devices with live trust scores updating every 5 seconds
2. **Each device card** shows:
   - Trust score gauge (0–100)
   - Trust level: Trusted / Stable / Suspicious / High Risk / Critical
   - Score breakdown bars (Behavioral, Policy, History)
   - SHAP-style explanation text
3. **Simulate Attacks** — click "⚡ Simulate Attack" on any device card, then choose:
   - `mirai` — SYN flood botnet attack
   - `exfiltration` — DNS tunneling data theft
   - `lateral_movement` — internal scanning
   - `port_scan` — service enumeration
   - Watch the trust score collapse in real time!
4. **Global Attack Simulator** bar at the top — one-click trigger any attack on a random device
5. **Alerts tab** — shows all active security alerts with explanations
6. **About tab** — architecture and formula overview

---

## STEP 5 — Trigger Attacks via API (optional)

Open a **third terminal** and run:

```bash
# Trigger Mirai botnet on Entry Camera
curl -X POST http://localhost:8000/api/v1/simulator/trigger \
  -H "Content-Type: application/json" \
  -d '{"device_id": "camera-001", "attack_type": "mirai"}'

# Trigger DNS exfiltration on temperature sensor
curl -X POST http://localhost:8000/api/v1/simulator/trigger \
  -d '{"device_id": "sensor-001", "attack_type": "exfiltration"}'

# Stop all attacks
curl -X POST http://localhost:8000/api/v1/simulator/stop \
  -H "Content-Type: application/json" -d '{}'
```

---

## STEP 6 — Train ML Models (optional, for full pipeline)

```bash
cd ml/training
pip install scikit-learn joblib numpy
python train_models.py --output ../models/
```

For LSTM Autoencoder (requires GPU or patience):
```bash
pip install tensorflow
python lstm_autoencoder.py
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: fastapi` | Run `pip install fastapi "uvicorn[standard]" pydantic websockets numpy` |
| `npm: command not found` | Install Node.js from https://nodejs.org (LTS version) |
| Port 8000 already in use | Run `uvicorn main:app --port 8001` and update `REACT_APP_API_URL=http://localhost:8001` |
| Port 3000 already in use | React will ask to use 3001 — press Y |
| Dashboard shows "Connecting…" | Make sure backend is running on port 8000 first |
| `CORS error` in browser console | Restart the backend — CORS middleware is already configured |

---

## Device List

| Device ID | Type | IP |
|-----------|------|----|
| camera-001 | IP Camera | 192.168.1.10 |
| camera-002 | IP Camera | 192.168.1.11 |
| sensor-001 | Temp Sensor | 192.168.1.20 |
| sensor-002 | Temp Sensor | 192.168.1.21 |
| router-001 | Router | 192.168.1.1 |
| hub-001 | Smart Hub | 192.168.1.5 |
| plc-001 | SCADA PLC | 192.168.1.30 |
| lock-001 | Smart Lock | 192.168.1.40 |

---

## Full Docker Stack (alternative)

If you have Docker Desktop installed:

```bash
docker-compose up --build
```

- Dashboard: http://localhost:3000
- API + Docs: http://localhost:8000/docs

---

*SentinelTrust | Team Code Catalyst | GDG Hackathon 2025*
