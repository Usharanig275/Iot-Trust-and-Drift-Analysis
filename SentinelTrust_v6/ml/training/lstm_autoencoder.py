"""
SUPERSEDED — this hardcoded seq_len=48 and a 12-feature schema, assuming a
large historical dataset that never existed here (baseline uploads are ~10
rows). It was never actually loaded or called by the backend.

The real, live LSTM Autoencoder implementation is
backend/ml/lstm_autoencoder_model.py — it picks seq_len adaptively per device
based on how much baseline/live data actually exists, uses the real 10-feature
schema (backend/services/trust_engine.FEATURE_COLS), and is called directly
from TrustEngine.train_baseline() / score_test_data(). There is nothing to
run here; this file is kept only so the old approach's problem is documented,
not repeated.
"""
