-- SentinelTrust Database Schema

CREATE TABLE IF NOT EXISTS devices (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128),
    device_type VARCHAR(64),
    ip_address VARCHAR(32),
    mac_address VARCHAR(32),
    registered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_scores (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) REFERENCES devices(id),
    score FLOAT NOT NULL,
    level VARCHAR(32),
    behavioral_stability FLOAT,
    policy_compliance FLOAT,
    historical_trust FLOAT,
    recent_activity FLOAT,
    drift_score FLOAT,
    anomaly_detected BOOLEAN DEFAULT FALSE,
    explanation TEXT,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_trust_device_time ON trust_scores(device_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64),
    severity VARCHAR(32),
    score FLOAT,
    explanation TEXT,
    risk_factors JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS policy_violations (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64),
    violation_type VARCHAR(64),
    details JSONB,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);
