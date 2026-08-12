"""
SentinelTrust - Per-User Trust Engine
Each user gets their OWN isolated devices, baselines, scores and history.
Global (shared) data is gone — everything scoped to user_email.
"""

import time, json, os, statistics
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
import logging

from ml import isolation_forest_model as if_model
from ml import lstm_autoencoder_model as lstm_model

logger = logging.getLogger("sentineltrust")

FEATURE_COLS = [
    "packet_rate","byte_entropy","protocol_tcp_ratio","dns_query_freq",
    "unique_dest_ips","avg_connection_duration","port_entropy",
    "bandwidth_mbps","new_ext_conns","tcp_flag_anomaly",
]

# How the three anomaly signals get blended in _compute_trust. Not all three
# are always available (IF needs >=5 baseline rows, LSTM needs >=8 plus a
# live rolling buffer at least seq_len long) — when a signal is missing its
# weight is dropped and the rest are renormalized, rather than treating a
# missing model as "0 = normal".
DETECTOR_WEIGHTS = {
    "statistical":       0.40,
    "isolation_forest":  0.35,
    "lstm_autoencoder":  0.25,
}

SEQUENCE_BUFFER_CAP = 50  # how many recent raw feature rows we keep per device for LSTM scoring

TRUST_WEIGHTS = {
    "behavioral_stability": 0.40,
    "policy_compliance":    0.30,
    "historical_trust":     0.20,
    "recent_activity":      0.10,
}

TRUST_LEVELS = [
    (90,100,"trusted","#16a34a"),
    (70, 89,"stable","#65a30d"),
    (50, 69,"suspicious","#d97706"),
    (30, 49,"high_risk","#ea580c"),
    (0,  29,"critical","#dc2626"),
]
# NOTE: this table is documentation of the level bands only. The actual
# score->level logic lives in _score_to_level() below as simple threshold
# checks, because these integer (lo, hi) tuples have gaps a float score can
# fall through (e.g. 89.8 matches neither (90,100) nor (70,89)).

# One JSON file per user: users/<email_hash>/store.json
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "user_data")


def _user_dir(user_email: str) -> str:
    safe = user_email.replace("@","_at_").replace(".","_")
    d = os.path.join(DATA_DIR, safe)
    os.makedirs(d, exist_ok=True)
    return d

def _store_path(user_email: str) -> str:
    return os.path.join(_user_dir(user_email), "store.json")

def _model_dir(user_email: str) -> str:
    d = os.path.join(_user_dir(user_email), "models")
    os.makedirs(d, exist_ok=True)
    return d

def _load_store(user_email: str) -> dict:
    p = _store_path(user_email)
    if os.path.exists(p):
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            pass
    return {"devices": {}, "baselines": {}, "history": {}}

def _save_store(user_email: str, store: dict):
    try:
        with open(_store_path(user_email), "w") as f:
            json.dump(store, f, indent=2)
    except Exception as e:
        logger.error(f"Store save failed for {user_email}: {e}")

def _compute_baseline_stats(rows):
    stats = {}
    for col in FEATURE_COLS:
        vals = [float(r[col]) for r in rows if col in r and r[col] is not None]
        if vals:
            mean = statistics.mean(vals)
            std = statistics.stdev(vals) if len(vals) > 1 else mean * 0.1 + 0.001
            stats[col] = {"mean": mean, "std": max(std, 0.001),
                          "min": min(vals), "max": max(vals), "n": len(vals)}
    return stats

def _zscore_drift(value, stat):
    return min(5.0, abs(value - stat["mean"]) / stat["std"])

def _score_to_level(score):
    # Boundary-inclusive on the low end, exclusive on the high end (except the
    # top bucket), so a float score like 89.8 or 69.99 lands somewhere instead
    # of falling through the gap between integer buckets and silently
    # defaulting to "critical".
    if score >= 90:
        return "trusted", "#16a34a"
    if score >= 70:
        return "stable", "#65a30d"
    if score >= 50:
        return "suspicious", "#d97706"
    if score >= 30:
        return "high_risk", "#ea580c"
    return "critical", "#dc2626"


@dataclass
class TrustResult:
    device_id: str
    score: float
    level: str
    color: str
    behavioral_stability: float
    policy_compliance: float
    historical_trust: float
    recent_activity: float
    drift_score: float
    anomaly_detected: bool
    explanation: str
    top_risk_factors: List[str]
    feature_zscores: dict
    trend: str
    trend_delta: float
    predicted_score: float
    risk_rank: int
    shap_features: dict
    active_detectors: List[str]
    detector_scores: dict
    detector_status: dict
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return asdict(self)


class TrustEngine:
    """
    Per-user trust engine. All methods require user_email parameter.
    In-memory cache per user for speed; persisted to user_data/<email>/ folder.
    """

    def __init__(self):
        # In-memory caches keyed by user_email
        self._scores:      Dict[str, Dict[str, TrustResult]] = {}
        self._history:     Dict[str, Dict[str, List[float]]] = {}
        self._attack_mode: Dict[str, Dict[str, Optional[str]]] = {}

    async def initialize(self):
        logger.info("TrustEngine (per-user) ready")

    # ── helpers ──────────────────────────────────────────────────────────────

    def _ensure_user(self, email: str):
        if email not in self._scores:
            self._scores[email] = {}
            self._attack_mode[email] = {}
            store = _load_store(email)
            hist = {}
            for did, h in store.get("history", {}).items():
                hist[did] = h
            self._history[email] = hist
            # Rebuild scores from baselines
            for did, dev in store["devices"].items():
                self._attack_mode[email][did] = None
                bl = store["baselines"].get(did)
                if bl and bl.get("stats"):
                    mean_features = {col: bl["stats"][col]["mean"]
                                     for col in FEATURE_COLS if col in bl["stats"]}
                    result = self._compute_trust(email, did, mean_features)
                    self._scores[email][did] = result

    # ── Device management ─────────────────────────────────────────────────────

    def register_device(self, user_email, device_id, name, device_type, ip, description=""):
        self._ensure_user(user_email)
        store = _load_store(user_email)
        if device_id in store["devices"]:
            return {"error": f"Device '{device_id}' already exists"}
        store["devices"][device_id] = {
            "id": device_id, "name": name, "type": device_type,
            "ip": ip, "description": description,
            "registered_at": time.time(), "has_baseline": False, "test_count": 0,
        }
        self._attack_mode[user_email][device_id] = None
        self._history[user_email][device_id] = []
        _save_store(user_email, store)
        return {"status": "registered", "device_id": device_id}

    def delete_device(self, user_email, device_id):
        self._ensure_user(user_email)
        store = _load_store(user_email)
        if device_id not in store["devices"]:
            return {"error": "Device not found"}
        del store["devices"][device_id]
        store["baselines"].pop(device_id, None)
        store["history"].pop(device_id, None)
        self._scores[user_email].pop(device_id, None)
        self._history[user_email].pop(device_id, None)
        _save_store(user_email, store)
        return {"status": "deleted"}

    def get_device_list(self, user_email):
        self._ensure_user(user_email)
        store = _load_store(user_email)
        return list(store["devices"].values())

    # ── Baseline ──────────────────────────────────────────────────────────────

    def train_baseline(self, user_email, device_id, rows):
        self._ensure_user(user_email)
        store = _load_store(user_email)
        if device_id not in store["devices"]:
            return {"error": "Device not registered"}
        if len(rows) < 5:
            return {"error": f"Need at least 5 rows, got {len(rows)}"}
        missing = [c for c in FEATURE_COLS if c not in rows[0]]
        if missing:
            return {"error": f"Missing columns: {missing}", "required": FEATURE_COLS}
        stats = _compute_baseline_stats(rows)

        # Train the real per-device anomaly models on this device's actual
        # baseline rows (not the disconnected generic-profile mock in
        # ml/training/). Both degrade gracefully (trained: False + reason)
        # if there isn't enough data yet or the dependency isn't installed —
        # the statistical z-score path keeps working either way.
        model_dir = _model_dir(user_email)
        try:
            if_status = if_model.train(model_dir, device_id, rows)
        except Exception as e:
            if_status = {"trained": False, "reason": f"isolation forest training error: {e}"}
        try:
            lstm_status = lstm_model.train(model_dir, device_id, rows)
        except Exception as e:
            lstm_status = {"trained": False, "reason": f"lstm training error: {e}"}

        store["baselines"][device_id] = {
            "stats": stats, "n_samples": len(rows),
            "trained_at": time.time(), "feature_cols": FEATURE_COLS,
            "isolation_forest": if_status,
            "lstm_autoencoder": lstm_status,
        }
        store["devices"][device_id]["has_baseline"] = True
        # Seed the rolling live-telemetry buffer with the baseline rows so
        # the LSTM detector has a head start on sequence context.
        seq_buf = store.setdefault("sequence_buffer", {})
        seq_buf[device_id] = [
            {c: r.get(c) for c in FEATURE_COLS} for r in rows[-SEQUENCE_BUFFER_CAP:]
        ]
        _save_store(user_email, store)
        # Initial score after training
        mean_features = {col: stats[col]["mean"] for col in FEATURE_COLS if col in stats}
        result = self._compute_trust(user_email, device_id, mean_features)
        self._scores[user_email][device_id] = result
        return {
            "status": "baseline_trained", "device_id": device_id,
            "n_samples": len(rows), "features": list(stats.keys()),
            "summary": {col: {"mean": round(v["mean"], 4), "std": round(v["std"], 4)}
                        for col, v in stats.items()},
            "isolation_forest": if_status,
            "lstm_autoencoder": lstm_status,
        }

    def get_baseline(self, user_email, device_id):
        self._ensure_user(user_email)
        store = _load_store(user_email)
        if device_id not in store["devices"]:
            return {"error": "Device not found"}
        bl = store["baselines"].get(device_id)
        return bl or {"error": "No baseline trained yet"}

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score_test_data(self, user_email, device_id, features):
        self._ensure_user(user_email)
        store = _load_store(user_email)
        if device_id not in store["devices"]:
            return {"error": "Device not registered"}
        bl = store["baselines"].get(device_id)
        if not bl or not bl.get("stats"):
            return {"error": "No baseline trained for this device"}
        stats = bl["stats"]
        for col in FEATURE_COLS:
            if col not in features and col in stats:
                features[col] = stats[col]["mean"]

        # Update the rolling live-telemetry buffer (this is what the LSTM
        # detector uses for sequence scoring — a single row has no "temporal"
        # component on its own).
        seq_buf = store.setdefault("sequence_buffer", {}).setdefault(device_id, [])
        seq_buf.append({c: features.get(c) for c in FEATURE_COLS})
        if len(seq_buf) > SEQUENCE_BUFFER_CAP:
            del seq_buf[: len(seq_buf) - SEQUENCE_BUFFER_CAP]

        model_dir = _model_dir(user_email)
        try:
            if_result = if_model.score(model_dir, device_id, features)
        except Exception as e:
            logger.warning(f"IsolationForest scoring error for {device_id}: {e}")
            if_result = None
        try:
            lstm_result = lstm_model.score(model_dir, device_id, seq_buf)
        except Exception as e:
            logger.warning(f"LSTM scoring error for {device_id}: {e}")
            lstm_result = None

        result = self._compute_trust(user_email, device_id, features, if_result, lstm_result)
        self._scores[user_email][device_id] = result
        h = self._history[user_email].setdefault(device_id, [])
        h.append(result.score)
        if len(h) > 100:
            h.pop(0)
        store["history"][device_id] = h
        store["devices"][device_id]["test_count"] = store["devices"][device_id].get("test_count", 0) + 1
        _save_store(user_email, store)
        return result.to_dict()

    def score_batch(self, user_email, device_id, rows):
        results = []
        for row in rows:
            r = self.score_test_data(user_email, device_id, row)
            if "error" not in r:
                results.append(r)
        if not results:
            return {"error": "No valid results"}
        scores = [r["score"] for r in results]
        anomalies = [r for r in results if r["anomaly_detected"]]
        return {
            "device_id": device_id, "n_rows": len(results),
            "avg_score": round(sum(scores)/len(scores), 1),
            "min_score": round(min(scores), 1), "max_score": round(max(scores), 1),
            "anomaly_count": len(anomalies),
            "anomaly_rate": round(len(anomalies)/len(results)*100, 1),
            "final_level": results[-1]["level"], "results": results,
        }

    # ── Core computation ──────────────────────────────────────────────────────

    def _compute_trust(self, user_email, device_id, features, if_result=None, lstm_result=None):
        store = _load_store(user_email)
        bl = store["baselines"].get(device_id, {})
        stats = bl.get("stats", {})
        hist = self._history.get(user_email, {}).get(device_id, [])
        attack = (self._attack_mode.get(user_email) or {}).get(device_id)

        zscores = {}
        for col in FEATURE_COLS:
            if col in features and col in stats:
                zscores[col] = round(_zscore_drift(float(features[col]), stats[col]), 3)
            elif col in stats:
                zscores[col] = 0.0

        raw_drift = sum(zscores.values()) / len(zscores) if zscores else 0.0
        stat_drift = min(1.0, raw_drift / 3.0)

        # Blend the three anomaly signals. Not every device has a trained IF
        # or LSTM model yet (not enough baseline data, or LSTM's rolling
        # buffer hasn't reached seq_len live readings) — when a signal is
        # missing, its weight is dropped and the remaining weights are
        # renormalized rather than treating "no model" as "score 0".
        if_score = if_result.get("anomaly_score") if isinstance(if_result, dict) and "anomaly_score" in if_result else None
        lstm_score = lstm_result.get("anomaly_score") if isinstance(lstm_result, dict) and "anomaly_score" in lstm_result else None

        components = {"statistical": stat_drift}
        weights = {"statistical": DETECTOR_WEIGHTS["statistical"]}
        if if_score is not None:
            components["isolation_forest"] = if_score
            weights["isolation_forest"] = DETECTOR_WEIGHTS["isolation_forest"]
        if lstm_score is not None:
            components["lstm_autoencoder"] = lstm_score
            weights["lstm_autoencoder"] = DETECTOR_WEIGHTS["lstm_autoencoder"]

        total_w = sum(weights.values())
        drift_score = sum(components[k] * weights[k] for k in weights) / total_w if total_w > 0 else stat_drift
        active_detectors = list(weights.keys())

        detector_status = {
            "isolation_forest": if_result if if_result is not None else {"trained": False, "reason": "no model yet"},
            "lstm_autoencoder": lstm_result if lstm_result is not None else {"trained": False, "reason": "no model yet"},
        }

        simulated_attack_override = False
        if attack:
            t = time.time()
            ramp = min(1.0, (t % 120) / 60.0)
            drift_score = min(0.95, 0.4 + ramp * 0.5)
            simulated_attack_override = True

        behavioral_stability = max(0.0, (1.0 - drift_score) * 100)
        policy_compliance = self._check_policy(features, attack) * 100
        historical_trust = sum(hist[-6:])/len(hist[-6:]) if hist else 85.0
        recent_activity = min(100.0, max(60.0, 100 - drift_score * 30))

        shap = {
            "behavioral_stability": round(TRUST_WEIGHTS["behavioral_stability"] * behavioral_stability, 2),
            "policy_compliance":    round(TRUST_WEIGHTS["policy_compliance"]    * policy_compliance, 2),
            "historical_trust":     round(TRUST_WEIGHTS["historical_trust"]     * historical_trust, 2),
            "recent_activity":      round(TRUST_WEIGHTS["recent_activity"]      * recent_activity, 2),
        }
        score = round(max(0.0, min(100.0, sum(shap.values()))), 1)
        level, color = _score_to_level(score)

        sorted_z = sorted(zscores.items(), key=lambda x: x[1], reverse=True)
        risk_factors = []
        for col, z in sorted_z[:3]:
            if z > 1.5:
                actual = features.get(col)
                mean = stats[col]["mean"] if col in stats else "?"
                try:
                    risk_factors.append(f"{col}: {float(actual):.2f} vs baseline {mean:.2f} (z={z:.1f}σ)")
                except Exception:
                    risk_factors.append(f"{col}: z={z:.1f}σ drift")
        if if_score is not None and if_score > 0.6:
            risk_factors.append(f"Isolation Forest: reading flagged anomalous (score={if_score:.2f})")
        if lstm_score is not None and lstm_score > 0.6:
            risk_factors.append(f"LSTM Autoencoder: recent sequence reconstructs poorly (score={lstm_score:.2f})")

        explanation = self._generate_explanation(
            score, drift_score, risk_factors, attack,
            simulated_attack_override, if_score, lstm_score,
        )
        trend, delta = "stable", 0.0
        if len(hist) >= 2:
            delta = round(score - hist[-1], 1)
            trend = "rising" if delta > 3 else "falling" if delta < -3 else "stable"
        predicted = score
        if len(hist) >= 3:
            slope = (hist[-1] - hist[-3]) / 2
            predicted = round(max(0, min(100, score + slope * 0.5)), 1)

        return TrustResult(
            device_id=device_id, score=score, level=level, color=color,
            behavioral_stability=round(behavioral_stability,1),
            policy_compliance=round(policy_compliance,1),
            historical_trust=round(historical_trust,1),
            recent_activity=round(recent_activity,1),
            drift_score=round(drift_score,3),
            # Threshold validated empirically (scripts/validate_models.py): on
            # the labeled test set, normal-data drift topped out ~0.57 while
            # every real attack row hit 1.0 — 0.6 gives a wide margin instead
            # of the too-aggressive 0.4 that produced ~12% false positives on
            # clean data with zero recall benefit.
            anomaly_detected=(drift_score > 0.6 or bool(attack)),
            explanation=explanation, top_risk_factors=risk_factors,
            feature_zscores=zscores, trend=trend, trend_delta=delta,
            predicted_score=predicted, risk_rank=0, shap_features=shap,
            active_detectors=active_detectors,
            detector_scores={
                "statistical": round(stat_drift, 3),
                "isolation_forest": round(if_score, 3) if if_score is not None else None,
                "lstm_autoencoder": round(lstm_score, 3) if lstm_score is not None else None,
            },
            detector_status=detector_status,
        )

    def _check_policy(self, features, attack):
        if attack:
            t = time.time()
            return max(0.05, 1.0 - min(0.9, (t % 120) / 80))
        violations = 0
        if features.get("new_ext_conns", 0) > 5:   violations += 1
        if features.get("dns_query_freq", 0) > 150: violations += 1
        if features.get("port_entropy", 0) > 3.5:   violations += 1
        return max(0.1, 1.0 - violations * 0.25)

    def _generate_explanation(self, score, drift, risks, attack, simulated=False,
                               if_score=None, lstm_score=None):
        if attack == "mirai":        return "CRITICAL: Mirai botnet traffic detected. SYN-flood targeting Telnet/SSH. (simulated attack)"
        if attack == "exfiltration": return "CRITICAL: DNS tunneling exfiltration detected. Covert outbound channel active. (simulated attack)"
        if attack == "lateral_movement": return "HIGH RISK: Lateral movement — device scanning internal subnets. (simulated attack)"
        if attack == "port_scan":    return "HIGH RISK: Port scan — service enumeration across wide IP range. (simulated attack)"

        detectors = []
        if if_score is not None:
            detectors.append(f"IF={if_score:.2f}")
        if lstm_score is not None:
            detectors.append(f"LSTM={lstm_score:.2f}")
        detector_note = f" [{', '.join(detectors)}]" if detectors else ""

        if drift > 0.6: return f"ANOMALY: High behavioral drift (drift={drift:.2f}){detector_note}. Device significantly off baseline."
        if drift > 0.3: return f"WARNING: Moderate drift (drift={drift:.2f}){detector_note}. {len(risks)} features outside normal range."
        if score > 80:  return f"Normal: Device within baseline envelope{detector_note}. Trust score {score}/100."
        return f"Stable with minor variations{detector_note}. Trust score {score}/100."

    # ── Public helpers ────────────────────────────────────────────────────────

    def get_all_scores(self, user_email):
        self._ensure_user(user_email)
        return [s.to_dict() for s in self._scores.get(user_email, {}).values()]

    def get_score(self, user_email, device_id):
        self._ensure_user(user_email)
        s = self._scores.get(user_email, {}).get(device_id)
        return s.to_dict() if s else None

    def get_history(self, user_email, device_id):
        self._ensure_user(user_email)
        return self._history.get(user_email, {}).get(device_id, [])

    def get_network_health(self, user_email):
        self._ensure_user(user_email)
        store = _load_store(user_email)
        scores = list(self._scores.get(user_email, {}).values())
        if not scores:
            return {"network_trust_score": 0, "health_status": "no_data",
                    "total_devices": len(store["devices"])}
        avg = sum(s.score for s in scores) / len(scores)
        return {
            "network_trust_score": round(avg, 1),
            "health_status": "healthy" if avg > 70 else "degraded" if avg > 50 else "critical",
            "total_devices": len(store["devices"]),
            "scored_devices": len(scores),
            "anomalous_devices": sum(1 for s in scores if s.anomaly_detected),
            "critical_count": sum(1 for s in scores if s.score < 30),
        }

    def trigger_attack(self, user_email, device_id, attack_type):
        self._ensure_user(user_email)
        self._attack_mode.setdefault(user_email, {})[device_id] = attack_type

    def stop_attack(self, user_email, device_id):
        self._ensure_user(user_email)
        self._attack_mode.setdefault(user_email, {})[device_id] = None

    def stop_all_attacks(self, user_email):
        self._ensure_user(user_email)
        for k in self._attack_mode.get(user_email, {}):
            self._attack_mode[user_email][k] = None

    # Admin: see ALL users data
    def get_all_users_summary(self):
        if not os.path.exists(DATA_DIR):
            return []
        summary = []
        for folder in os.listdir(DATA_DIR):
            path = os.path.join(DATA_DIR, folder, "store.json")
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        store = json.load(f)
                    summary.append({
                        "user_folder": folder,
                        "device_count": len(store.get("devices", {})),
                        "devices": list(store.get("devices", {}).keys()),
                    })
                except Exception:
                    pass
        return summary
