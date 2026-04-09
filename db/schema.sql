-- ============================================================
-- CHAMP Project — PostgreSQL Schema
-- Secure Password Storage Beyond bcrypt
-- ============================================================

-- Drop existing tables if re-running
DROP TABLE IF EXISTS login_attempts CASCADE;
DROP TABLE IF EXISTS benchmark_results CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ── Users table ──────────────────────────────────────────────
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(100) UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    algorithm       VARCHAR(20) NOT NULL CHECK (algorithm IN ('bcrypt', 'argon2id', 'scrypt')),
    param_preset    VARCHAR(20) DEFAULT 'medium',   -- low / medium / high / ultra
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login      TIMESTAMP WITH TIME ZONE,
    is_active       BOOLEAN DEFAULT TRUE
);

-- ── Login attempts table (for rate-limiting analysis) ────────
CREATE TABLE login_attempts (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username_tried  VARCHAR(100),
    ip_address      INET,
    success         BOOLEAN NOT NULL,
    attempted_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Benchmark results table ───────────────────────────────────
CREATE TABLE benchmark_results (
    id              SERIAL PRIMARY KEY,
    algorithm       VARCHAR(20) NOT NULL,
    preset          VARCHAR(20),
    time_cost       INTEGER,
    memory_cost_kb  INTEGER,
    parallelism     INTEGER,
    avg_hash_ms     NUMERIC(10, 3),
    avg_verify_ms   NUMERIC(10, 3),
    avg_total_ms    NUMERIC(10, 3),
    peak_memory_mb  NUMERIC(10, 3),
    iterations      INTEGER,
    recorded_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes           TEXT
);

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX idx_users_username    ON users(username);
CREATE INDEX idx_users_email       ON users(email);
CREATE INDEX idx_attempts_user     ON login_attempts(user_id);
CREATE INDEX idx_attempts_time     ON login_attempts(attempted_at);
CREATE INDEX idx_benchmark_algo    ON benchmark_results(algorithm);

-- ── Attack results table ──────────────────────────────────────
CREATE TABLE attack_results (
    id              SERIAL PRIMARY KEY,
    algorithm       VARCHAR(20) NOT NULL,
    preset          VARCHAR(20),
    hps             NUMERIC(15, 2),
    attempts        BIGINT,
    duration        NUMERIC(10, 2),
    cost_ratio      NUMERIC(10, 2),
    is_real_hashcat BOOLEAN DEFAULT FALSE,
    recorded_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_attack_algo       ON attack_results(algorithm);

-- ── Auto-update updated_at trigger ───────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── Sample view: benchmark summary ───────────────────────────
CREATE VIEW benchmark_summary AS
SELECT
    algorithm,
    preset,
    memory_cost_kb / 1024  AS memory_cost_mb,
    ROUND(AVG(avg_hash_ms), 2)   AS mean_hash_ms,
    ROUND(AVG(avg_total_ms), 2)  AS mean_total_ms,
    ROUND(AVG(peak_memory_mb), 2) AS mean_peak_mb,
    COUNT(*)                AS runs
FROM benchmark_results
GROUP BY algorithm, preset, memory_cost_kb
ORDER BY algorithm, memory_cost_kb;