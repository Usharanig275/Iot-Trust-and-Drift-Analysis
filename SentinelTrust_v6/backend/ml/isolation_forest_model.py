"""
Per-device Isolation Forest anomaly detector.

Unlike the old ml/training/train_models.py (which trained one model per generic
DEVICE_TYPE on synthetic data and was never actually loaded by the backend),
this trains one real model PER DEVICE on that device's own uploaded baseline
rows, using the exact feature schema the rest of the app uses
(backend/services/trust_engine.FEATURE_COLS). It's called directly from
TrustEngine.train_baseline() / score_test_data(), and persists to disk so
the model survives process restarts.
"""
import os
import json
import time
import logging

import numpy as np

logger = logging.getLogger("sentineltrust")

FEATURE_COLS = [
    "packet_rate", "byte_entropy", "protocol_tcp_ratio", "dns_query_freq",
    "unique_dest_ips", "avg_connection_duration", "port_entropy",
    "bandwidth_mbps", "new_ext_conns", "tcp_flag_anomaly",
]

MIN_SAMPLES = 5            # below this we refuse to train at all (too few to fit anything)
LOW_RELIABILITY_N = 20     # below this, flag the model's verdicts as low-confidence
MED_RELIABILITY_N = 100


def _paths(model_dir, device_id):
    return (
        os.path.join(model_dir, f"{device_id}_if_model.joblib"),
        os.path.join(model_dir, f"{device_id}_if_scaler.joblib"),
        os.path.join(model_dir, f"{device_id}_if_meta.json"),
    )


def _rows_to_matrix(rows):
    X = []
    for r in rows:
        vec = []
        for c in FEATURE_COLS:
            v = r.get(c, 0.0)
            try:
                vec.append(float(v) if v is not None else 0.0)
            except (TypeError, ValueError):
                vec.append(0.0)
        X.append(vec)
    return np.array(X, dtype=float)


def _reliability(n):
    if n < LOW_RELIABILITY_N:
        return "low"
    if n < MED_RELIABILITY_N:
        return "medium"
    return "high"


def train(model_dir, device_id, rows):
    """Fit an IsolationForest on this device's baseline rows. Returns a status dict
    that is safe to store directly in the device's baseline record."""
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import joblib
    except ImportError as e:
        return {"trained": False, "reason": f"scikit-learn not installed ({e})"}

    X = _rows_to_matrix(rows)
    n = len(X)
    if n < MIN_SAMPLES:
        return {"trained": False, "reason": f"need >= {MIN_SAMPLES} baseline rows, got {n}"}

    os.makedirs(model_dir, exist_ok=True)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # Scale model complexity to how much data we actually have instead of
    # pretending we always have a big dataset.
    n_estimators = int(min(200, max(50, n * 10)))
    contamination = min(0.15, max(0.01, 1.0 / n))

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=min(n, 256),
        random_state=42,
    )
    model.fit(Xs)

    # Calibrate: capture the training score distribution so inference scores
    # can be normalized into a stable, comparable [0,1] anomaly range instead
    # of sklearn's unbounded score_samples output.
    train_scores = model.score_samples(Xs)  # higher = more normal
    lo, hi = float(train_scores.min()), float(train_scores.max())

    model_path, scaler_path, meta_path = _paths(model_dir, device_id)
    try:
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
    except Exception as e:
        return {"trained": False, "reason": f"failed to persist model: {e}"}

    meta = {
        "trained": True,
        "n_samples": n,
        "trained_at": time.time(),
        "reliability": _reliability(n),
        "score_lo": lo,
        "score_hi": hi,
        "n_estimators": n_estimators,
        "contamination": round(contamination, 4),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f)
    return meta


def score(model_dir, device_id, features):
    """Return {"anomaly_score": float in [0,1], "reliability": str, "n_samples": int}
    for a single feature row, or None if this device has no trained model."""
    model_path, scaler_path, meta_path = _paths(model_dir, device_id)
    if not (os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(meta_path)):
        return None

    try:
        import joblib
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        with open(meta_path) as f:
            meta = json.load(f)

        vec = np.array([[
            float(features.get(c, 0.0) or 0.0) for c in FEATURE_COLS
        ]])
        vec_s = scaler.transform(vec)
        raw = float(model.score_samples(vec_s)[0])  # higher = more normal

        lo, hi = meta["score_lo"], meta["score_hi"]
        span = max(hi - lo, 1e-6)
        normal_ness = (raw - lo) / span  # can exceed [0,1] for points outside training range
        anomaly = 1.0 - normal_ness

        return {
            "anomaly_score": float(max(0.0, min(1.0, anomaly))),
            "reliability": meta["reliability"],
            "n_samples": meta["n_samples"],
        }
    except Exception as e:
        logger.warning(f"IsolationForest scoring failed for device {device_id}: {e}")
        return None
