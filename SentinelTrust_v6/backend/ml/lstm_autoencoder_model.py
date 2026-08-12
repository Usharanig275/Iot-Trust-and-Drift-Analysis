"""
Per-device LSTM Autoencoder for temporal drift detection.

The old ml/training/lstm_autoencoder.py hardcoded seq_len=48, which assumes a
large historical dataset that doesn't exist here (baseline uploads are ~10
rows). Instead of faking that scale, seq_len is chosen per device based on
how much data it actually has, and the model is retrained as more baseline
data comes in. It genuinely needs several sequence windows to learn from, so
below a small-sample floor it honestly reports "not trained" rather than
fitting noise.

This detector catches a different failure mode than the Isolation Forest:
IF flags a single reading that looks statistically odd; this flags a
*sequence* of readings whose pattern over time doesn't reconstruct well,
i.e. gradual drift rather than a one-off spike.
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

MIN_ROWS_FOR_LSTM = 8   # need enough rows to build several sequence windows
MAX_SEQ_LEN = 10
MIN_SEQ_LEN = 3


def _seq_len_for(n_rows):
    return min(MAX_SEQ_LEN, max(MIN_SEQ_LEN, n_rows // 3))


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


def _make_windows(X, seq_len):
    n = len(X)
    if n < seq_len:
        return None
    return np.array([X[i:i + seq_len] for i in range(n - seq_len + 1)])


def _paths(model_dir, device_id):
    return (
        os.path.join(model_dir, f"{device_id}_lstm.weights.h5"),
        os.path.join(model_dir, f"{device_id}_lstm_meta.json"),
    )


def _build_model(seq_len, n_features, compile_model=True):
    import tensorflow as tf
    from tensorflow.keras import layers, Model

    inp = tf.keras.Input(shape=(seq_len, n_features))
    x = layers.LSTM(16, return_sequences=True)(inp)
    enc = layers.LSTM(8)(x)
    x = layers.RepeatVector(seq_len)(enc)
    x = layers.LSTM(8, return_sequences=True)(x)
    x = layers.LSTM(16, return_sequences=True)(x)
    out = layers.TimeDistributed(layers.Dense(n_features))(x)
    model = Model(inp, out, name="device_lstm_autoencoder")
    if compile_model:
        model.compile(optimizer="adam", loss="mse")
    return model


def train(model_dir, device_id, rows):
    """Train a small LSTM autoencoder on sliding windows of this device's
    baseline rows. Returns a status dict safe to store in the baseline record."""
    try:
        import tensorflow as tf  # noqa: F401 - import check only
    except ImportError as e:
        return {"trained": False, "reason": f"tensorflow not installed ({e})"}

    X = _rows_to_matrix(rows)
    n = len(X)
    if n < MIN_ROWS_FOR_LSTM:
        return {"trained": False, "reason": f"need >= {MIN_ROWS_FOR_LSTM} baseline rows for sequence training, got {n}"}

    seq_len = _seq_len_for(n)

    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std = np.where(std < 1e-6, 1e-6, std)
    Xn = (X - mean) / std

    windows = _make_windows(Xn, seq_len)
    if windows is None or len(windows) < 2:
        return {"trained": False, "reason": "not enough rows to build multiple sequence windows"}

    os.makedirs(model_dir, exist_ok=True)
    model = _build_model(seq_len, len(FEATURE_COLS))
    epochs = 80 if len(windows) < 10 else 40
    model.fit(
        windows, windows,
        epochs=epochs,
        batch_size=max(1, min(8, len(windows))),
        verbose=0,
    )

    recon = model.predict(windows, verbose=0)
    errors = np.mean((recon - windows) ** 2, axis=(1, 2))
    err_mean, err_std = float(errors.mean()), float(errors.std() or 1e-6)

    weights_path, meta_path = _paths(model_dir, device_id)
    try:
        model.save_weights(weights_path)
    except Exception as e:
        return {"trained": False, "reason": f"failed to persist model: {e}"}

    n_windows = len(windows)
    reliability = "low" if n_windows < 10 else "medium" if n_windows < 40 else "high"

    meta = {
        "trained": True,
        "seq_len": seq_len,
        "n_windows": n_windows,
        "n_rows": n,
        "feature_mean": mean.tolist(),
        "feature_std": std.tolist(),
        "err_mean": err_mean,
        "err_std": err_std,
        "trained_at": time.time(),
        "reliability": reliability,
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f)
    return meta


def score(model_dir, device_id, sequence_rows):
    """sequence_rows: ordered list of feature dicts (oldest first, most recent last),
    e.g. the device's rolling live-telemetry buffer. Returns
    {"anomaly_score": float in [0,1], "reliability": str, "reconstruction_error": float}
    on success, {"insufficient_history": True, "need": n, "have": n} if the model
    exists but the buffer isn't long enough yet, or None if no model is trained."""
    weights_path, meta_path = _paths(model_dir, device_id)
    if not (os.path.exists(weights_path) and os.path.exists(meta_path)):
        return None

    try:
        with open(meta_path) as f:
            meta = json.load(f)
        seq_len = meta["seq_len"]
        if len(sequence_rows) < seq_len:
            return {"insufficient_history": True, "need": seq_len, "have": len(sequence_rows)}

        recent = sequence_rows[-seq_len:]
        X = _rows_to_matrix(recent)
        mean = np.array(meta["feature_mean"])
        std = np.array(meta["feature_std"])
        Xn = (X - mean) / std

        # Inference only — no optimizer needed, so build uncompiled to avoid
        # a spurious "optimizer state mismatch" warning when loading weights
        # that were saved alongside a training-time optimizer.
        model = _build_model(seq_len, len(FEATURE_COLS), compile_model=False)
        model.load_weights(weights_path)

        window = Xn[np.newaxis, ...]
        recon = model.predict(window, verbose=0)
        err = float(np.mean((recon - window) ** 2))

        z = (err - meta["err_mean"]) / meta["err_std"]
        anomaly = 1.0 / (1.0 + np.exp(-(z - 1.0)))  # sigmoid, centered ~1 std above baseline error

        return {
            "anomaly_score": float(max(0.0, min(1.0, anomaly))),
            "reliability": meta["reliability"],
            "reconstruction_error": err,
        }
    except Exception as e:
        logger.warning(f"LSTM autoencoder scoring failed for device {device_id}: {e}")
        return None
