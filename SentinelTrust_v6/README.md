# 🛡️ SentinelTrust
## Predictive Behavioral Trust Engine for IoT Networks

> **Team Code Catalyst** | GDG Hackathon 2025
> Bhavya J · Punyashree TS · Soujanya M · Usha Rani G

---

## 🚀 Quick Start (VSCode)

### Option A: Run without Docker (recommended for hackathon demo)

**Step 1 – Start the Backend**
```bash
cd SentinelTrust/backend
pip install fastapi uvicorn[standard] pydantic websockets loguru
uvicorn main:app --reload --port 8000
```
Open http://localhost:8000/docs to verify the API is running.

**Step 2 – Start the Frontend**
```bash
cd SentinelTrust/frontend
npm install
npm start
```
Open http://localhost:3000 for the live dashboard.

---

### Option B: Full Docker Stack

```bash
cd SentinelTrust
docker-compose up --build
```
- Dashboard: http://localhost:3000
- API Docs:  http://localhost:8000/docs

---

## 📁 Project Structure

```
SentinelTrust/
├── backend/
│   ├── main.py                    # FastAPI entry point
│   ├── services/
│   │   ├── trust_engine.py        # Core trust scoring (0-100)
│   │   ├── telemetry_processor.py # 30s scoring loop
│   │   └── websocket_manager.py   # Real-time WebSocket push
│   ├── api/routes/
│   │   ├── devices.py             # Device list & scores
│   │   ├── trust.py               # Trust score endpoints
│   │   ├── alerts.py              # Active alerts
│   │   ├── simulator.py           # Attack trigger API
│   │   └── policies.py            # Device policy profiles
│   └── Dockerfile
├── frontend/
│   ├── src/App.jsx                # Full dashboard (single-file React)
│   └── Dockerfile
├── ml/
│   ├── training/
│   │   ├── train_models.py        # Isolation Forest training
│   │   └── lstm_autoencoder.py    # LSTM AE architecture
│   └── models/                    # Saved .pkl / .h5 files (after training)
├── simulator/
│   └── simulator.py               # Attack replay simulator
├── config/
│   └── device_policies.yaml       # Role-based device policies
├── scripts/
│   └── init_db.sql                # PostgreSQL schema
├── docker-compose.yml
└── requirements.txt
```

---

## 🎯 Trust Score Formula

```
TrustScore = 0.40 × BehavioralStability
           + 0.30 × PolicyCompliance
           + 0.20 × HistoricalTrust
           + 0.10 × RecentActivityConfidence
```

| Score Range | Level       | Action                    |
|-------------|-------------|---------------------------|
| 90–100      | Trusted     | Normal operation          |
| 70–89       | Stable      | Monitor                   |
| 50–69       | Suspicious  | Log + human review        |
| 30–49       | High Risk   | Alert + isolate candidate |
| 0–29        | Critical    | Quarantine immediately    |

---

## ⚡ Attack Simulator (Hackathon Demo)

Trigger attacks via the dashboard or API:

```bash
# Mirai botnet
curl -X POST http://localhost:8000/api/v1/simulator/trigger \
  -H "Content-Type: application/json" \
  -d '{"device_id": "camera-001", "attack_type": "mirai"}'

# Data exfiltration
curl -X POST http://localhost:8000/api/v1/simulator/trigger \
  -d '{"device_id": "sensor-001", "attack_type": "exfiltration"}'

# Stop all attacks
curl -X POST http://localhost:8000/api/v1/simulator/stop -d '{}'
```

Attack types: `mirai` | `exfiltration` | `lateral_movement` | `port_scan`

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/v1/devices/` | List all IoT devices |
| GET  | `/api/v1/devices/{id}/score` | Single device trust score |
| GET  | `/api/v1/devices/{id}/history` | Score history (last 60 windows) |
| GET  | `/api/v1/trust/scores` | All device trust scores |
| GET  | `/api/v1/trust/summary` | Aggregated trust summary |
| GET  | `/api/v1/alerts/` | Active security alerts |
| POST | `/api/v1/simulator/trigger` | Trigger attack scenario |
| POST | `/api/v1/simulator/stop` | Stop attack |
| GET  | `/api/v1/policies/` | Device policy profiles |
| WS   | `/ws` | Real-time trust updates (5s cadence) |

---

## 🧠 ML Pipeline

Implemented in `backend/ml/` and called live from `TrustEngine.train_baseline()` /
`score_test_data()` in `backend/services/trust_engine.py` — trained per device
(not per generic device-type) on that device's own uploaded baseline, using
the real 10-feature schema (`FEATURE_COLS`). Both degrade gracefully (report
`trained: False` + a reason, and the statistical z-score signal keeps working
on its own) rather than silently pretending to be active.

### Model 1 — Isolation Forest (Point Drift)
- `backend/ml/isolation_forest_model.py`
- Unsupervised, per-device model, `n_estimators` and `contamination` scaled to
  the device's actual baseline size
- Requires ≥5 baseline rows; reliability is labeled `low` / `medium` / `high`
  based on sample count (honest about small-baseline uncertainty)

### Model 2 — LSTM Autoencoder (Temporal Drift)
- `backend/ml/lstm_autoencoder_model.py`
- Encoder: LSTM(16→8), Decoder: LSTM(8→16) — sized for per-device training,
  not a shared 24h-scale model
- `seq_len` is chosen adaptively per device (3–10 steps) based on how much
  baseline/live data actually exists, not a fixed 48-step window
- Requires ≥8 baseline rows to form multiple sequence windows; scores once the
  device's live rolling buffer reaches `seq_len` readings
- Drift = sigmoid(reconstruction MSE relative to this device's own training
  error distribution)

### Blending
`TrustEngine._compute_trust()` combines statistical z-score drift, Isolation
Forest anomaly score, and LSTM reconstruction-error score with weights
0.40 / 0.35 / 0.25. If a device doesn't have a trained IF or LSTM model yet,
that weight is dropped and the rest are renormalized — a missing model is
never silently treated as "normal."

### Model 3 — XGBoost Classifier
Referenced above in earlier docs but **not implemented anywhere in this
codebase** — no training script, no model file, no call site. If you want
this added, it needs labeled attack data (e.g. UNSW-NB15/N-BaIoT) and a
training pipeline from scratch; happy to help build it, just flagging it's a
separate, larger task from the IF/LSTM work above.

### Retrain models for a device:
Training happens automatically whenever a baseline CSV/JSON is uploaded via
`POST /api/v1/devices/{id}/baseline` — there's no separate CLI step. Models
are stored per-user, per-device under `backend/user_data/<user>/models/`.

### Validation (real numbers, reproducible)

`sample_data/camera_baseline_large.csv` (300 rows) replaces the original
10-row baseline for anything you want to actually demo or evaluate — 10 rows
isn't enough for either model to be statistically meaningful. It's synthetic
but grounded in the real 10-row sample's measured mean/std, with a mild
diurnal cycle so there's genuine temporal structure for the LSTM to learn
(not just i.i.d. noise). `camera_test_normal_large.csv` and
`camera_test_attack_large.csv` (60 rows each, held out, with a labeled
sustained Mirai-style ramp attack in the latter) are used to measure real
precision/recall — not just eyeballed scores.

Run it yourself:
```bash
cd backend
python3 ../scripts/validate_models.py
```

Measured results on this repo's data:

| Metric | Value |
|---|---|
| False positives on 60 clean/normal rows | 0 (0.0%) |
| Precision (attack test, 20 normal + 40 attack) | 0.976 |
| Recall | 1.000 |
| F1 | 0.988 |
| Isolation Forest reliability | high (300 baseline samples) |
| LSTM Autoencoder reliability | high (291 training windows, seq_len=10) |

Note: IsolationForest is deterministic (`random_state=42`); the LSTM has some
run-to-run variance from Keras/TensorFlow weight initialization, so exact
numbers may shift slightly between runs — the precision/recall story won't.

---

## 💡 SHAP Explainability

Every alert includes human-readable reasoning:
```
"CRITICAL: Mirai botnet pattern detected. SYN-flood targeting port 23/2323.
  • SYN flood — packet_rate +1500%
  • Port scan — 500 unique dest IPs in 30s
  • TCP flag anomaly: SYN-only bursts"
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REACT_APP_API_URL` | `http://localhost:8000` | Backend URL |
| `REACT_APP_WS_URL`  | `ws://localhost:8000/ws` | WebSocket URL |
| `REDIS_URL`         | `redis://localhost:6379` | Redis cache |
| `POSTGRES_URL`      | `postgresql://...` | Database |

---

## 📊 Performance

- Trust scoring latency: **<15ms per device**
- Dashboard WebSocket update: **5s** (simulates 30s IoT cadence)
- Scales to 1000+ concurrent devices on 16-core CPU
- Edge-deployable: runs on Raspberry Pi 4 / Jetson Nano

---

*Built with FastAPI · React · scikit-learn · TensorFlow · WebSockets*
