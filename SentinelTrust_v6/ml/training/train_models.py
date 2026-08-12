"""
SUPERSEDED — this script trained one IsolationForest per generic DEVICE_TYPE on
synthetic profile data, using a 12-feature schema that doesn't match the app's
real telemetry schema (10 features, see backend/services/trust_engine.FEATURE_COLS).
It was never actually loaded or called by the backend.

The real, live Isolation Forest implementation is
backend/ml/isolation_forest_model.py — it trains one model PER DEVICE on that
device's own uploaded baseline CSV, using the real feature schema, and is
called directly from TrustEngine.train_baseline() / score_test_data() in
backend/services/trust_engine.py. There is nothing to run here; this file is
kept only so the old approach's problem is documented, not repeated.
"""
