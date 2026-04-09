"""
Database Connection Manager
Handles PostgreSQL connections using psycopg2 with connection pooling.
"""

import os
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv() # Load variables from .env if it exists

# ── Config from environment variables (set in .env or docker-compose) ──────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", "5432")),
    "dbname":   os.getenv("DB_NAME",     "champ_db"),
    "user":     os.getenv("DB_USER",     "champ_user"),
    "password": os.getenv("DB_PASSWORD", "champ_pass"),
}

# Connection pool (min 2, max 10 connections)
_pool = None


def init_pool():
    global _pool
    _pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=2,
        maxconn=10,
        **DB_CONFIG
    )
    print("[DB] Connection pool initialized.")


@contextmanager
def get_connection():
    """Context manager to safely get and return a DB connection."""
    if _pool is None:
        init_pool()
    conn = _pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)


# ── User CRUD operations ───────────────────────────────────────────────────────

def create_user(username: str, email: str, password_hash: str,
                algorithm: str, preset: str = "medium") -> int:
    """Insert a new user. Returns the new user's ID."""
    sql = """
        INSERT INTO users (username, email, password_hash, algorithm, param_preset)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (username, email, password_hash, algorithm, preset))
            return cur.fetchone()[0]


def get_user_by_username(username: str) -> dict | None:
    """Fetch a user record by username. Returns dict or None."""
    sql = "SELECT id, username, email, password_hash, algorithm, param_preset FROM users WHERE username = %s AND is_active = TRUE;"
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (username,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0], "username": row[1], "email": row[2],
                "password_hash": row[3], "algorithm": row[4], "preset": row[5],
            }


def update_last_login(user_id: int):
    """Update last_login timestamp after successful authentication."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s;", (user_id,))


def log_attempt(username: str, success: bool, user_id: int = None, ip: str = None):
    """Record a login attempt for audit and rate-limiting."""
    sql = """
        INSERT INTO login_attempts (user_id, username_tried, ip_address, success)
        VALUES (%s, %s, %s, %s);
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (user_id, username, ip, success))


def save_benchmark(result: dict):
    """Persist a benchmark result dict to the database."""
    sql = """
        INSERT INTO benchmark_results
            (algorithm, preset, time_cost, memory_cost_kb, parallelism,
             avg_hash_ms, avg_verify_ms, avg_total_ms, peak_memory_mb, iterations, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """
    params = result.get("params", {})
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                result.get("algorithm"),
                result.get("preset", "custom"),
                params.get("time_cost"),
                params.get("memory_cost"),
                params.get("parallelism"),
                result.get("avg_hash_ms"),
                result.get("avg_verify_ms"),
                result.get("avg_total_ms"),
                result.get("peak_memory_mb"),
                result.get("iterations"),
                result.get("notes"),
            ))


def save_attack_result(algorithm: str, preset: str, hps: float, attempts: int, 
                       duration: float, cost_ratio: float, is_hashcat: bool = False):
    """Persist an attack simulation result to the database."""
    sql = """
        INSERT INTO attack_results (algorithm, preset, hps, attempts, duration, cost_ratio, is_real_hashcat)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (algorithm, preset, hps, attempts, duration, cost_ratio, is_hashcat))


def init_db():
    """Initialize the database schema from schema.sql."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        sql = f.read()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
    print("[DB] Schema initialized.")


if __name__ == "__main__":
    init_db()
    print("[DB] Ready.")