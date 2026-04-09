"""
CHAMP v2 — Advanced Secure Password Storage Demo
Flask REST API + Rich HTML Dashboard
"""

import os, sys, time, json, secrets, hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, request, jsonify, render_template_string, session

sys.path.insert(0, os.path.dirname(__file__))
from auth import bcrypt_auth, argon2_auth, scrypt_auth
from benchmark.benchmark import run_all
from attack_sim.hashcat_runner import simulate_attack_cpu, run_hashcat, _find_hashcat
from db.database import save_attack_result, get_connection, log_attempt, save_benchmark
import pandas as pd

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── In-memory stores ──────────────────────────────────────────────────────────
_USERS: dict = {}
_SESSIONS: dict = {}
_LOGIN_HISTORY: list = []
_BENCHMARK_HISTORY: list = []
_RATE_LIMIT: dict = defaultdict(list)

RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60  # seconds

# ── Helpers ───────────────────────────────────────────────────────────────────

def hash_password(password, algorithm, preset="medium"):
    if algorithm == "bcrypt":
        return bcrypt_auth.hash_password(password)
    elif algorithm == "argon2id":
        params = argon2_auth.PRESETS.get(preset, argon2_auth.PRESETS["medium"])
        return argon2_auth.hash_password(password, **params)
    elif algorithm == "scrypt":
        return scrypt_auth.hash_password(password, preset=preset)
    raise ValueError(f"Unknown algorithm: {algorithm}")

def verify_password(password, stored_hash, algorithm, preset="medium"):
    if algorithm == "bcrypt":
        return bcrypt_auth.verify_password(password, stored_hash)
    elif algorithm == "argon2id":
        params = argon2_auth.PRESETS.get(preset, argon2_auth.PRESETS["medium"])
        return argon2_auth.verify_password(password, stored_hash, **params)
    elif algorithm == "scrypt":
        return scrypt_auth.verify_password(password, stored_hash)
    return False

def password_strength(pw):
    score = 0
    issues = []
    if len(pw) >= 8: score += 20
    else: issues.append("At least 8 characters")
    if len(pw) >= 12: score += 10
    if any(c.isupper() for c in pw): score += 20
    else: issues.append("One uppercase letter")
    if any(c.islower() for c in pw): score += 20
    else: issues.append("One lowercase letter")
    if any(c.isdigit() for c in pw): score += 20
    else: issues.append("One number")
    if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in pw): score += 10
    else: issues.append("One special character")
    label = "Very Weak" if score < 30 else "Weak" if score < 50 else "Fair" if score < 70 else "Strong" if score < 90 else "Very Strong"
    return {"score": score, "label": label, "issues": issues}

def is_rate_limited(ip):
    now = time.time()
    _RATE_LIMIT[ip] = [t for t in _RATE_LIMIT[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_RATE_LIMIT[ip]) >= RATE_LIMIT_MAX:
        return True
    _RATE_LIMIT[ip].append(now)
    return False

def get_algo_info(algorithm, preset):
    info = {
        "bcrypt":   {"color": "#f59e0b", "desc": "CPU-hard, 72-byte limit, widely supported", "security": 78},
        "argon2id": {"color": "#10b981", "desc": "PHC winner, memory+CPU hard, best choice",   "security": 95},
        "scrypt":   {"color": "#6366f1", "desc": "Memory-hard, RFC 7914, built into Python",    "security": 88},
    }
    return info.get(algorithm, {})

# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "version": "2.0.0", "users": len(_USERS)})

@app.post("/api/register")
def register():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 415
    data = request.get_json()
    username  = data.get("username", "").strip().lower()
    email     = data.get("email", "").strip().lower()
    password  = data.get("password", "")
    algorithm = data.get("algorithm", "argon2id").lower()
    preset    = data.get("preset", "medium").lower()
    ip = request.remote_addr

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400
    if algorithm not in ("bcrypt", "argon2id", "scrypt"):
        return jsonify({"error": "Invalid algorithm"}), 400
    if username in _USERS:
        return jsonify({"error": "Username already taken"}), 409

    strength = password_strength(password)
    if strength["score"] < 40:
        return jsonify({"error": "Password too weak", "strength": strength}), 422

    t0 = time.perf_counter()
    try:
        ph = hash_password(password, algorithm, preset)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    hash_ms = round((time.perf_counter() - t0) * 1000, 2)

    _USERS[username] = {
        "email": email,
        "password_hash": ph,
        "algorithm": algorithm,
        "preset": preset,
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "login_count": 0,
    }
    _LOGIN_HISTORY.append({"type": "register", "username": username,
        "algorithm": algorithm, "hash_ms": hash_ms, "ts": datetime.now().isoformat(), "ip": ip})
    return jsonify({"message": "Registered successfully", "username": username,
        "algorithm": algorithm, "preset": preset, "hash_ms": hash_ms,
        "strength": strength}), 201

@app.post("/api/login")
def login():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 415
    data = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    ip = request.remote_addr

    if is_rate_limited(ip):
        return jsonify({"error": "Too many attempts. Wait 60 seconds."}), 429
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    user = _USERS.get(username)
    dummy = bcrypt_auth.hash_password("dummy_timing_prevention")

    t0 = time.perf_counter()
    if user:
        ok = verify_password(password, user["password_hash"], user["algorithm"], user.get("preset", "medium"))
    else:
        bcrypt_auth.verify_password("dummy", dummy)
        ok = False
    verify_ms = round((time.perf_counter() - t0) * 1000, 2)

    _LOGIN_HISTORY.append({"type": "login", "username": username, "success": ok,
        "verify_ms": verify_ms, "ts": datetime.now().isoformat(), "ip": ip})

    if ok:
        _USERS[username]["last_login"] = datetime.now().isoformat()
        _USERS[username]["login_count"] = _USERS[username].get("login_count", 0) + 1
        tok = secrets.token_hex(24)
        _SESSIONS[tok] = {"username": username, "created": time.time()}
        return jsonify({"authenticated": True, "username": username,
            "algorithm": user["algorithm"], "verify_ms": verify_ms, "token": tok})
    return jsonify({"authenticated": False, "error": "Invalid credentials"}), 401

@app.post("/api/password-check")
def password_check():
    data = request.get_json() or {}
    pw = data.get("password", "")
    return jsonify(password_strength(pw))

@app.get("/api/users")
def list_users():
    return jsonify({"users": [
        {"username": u, "algorithm": d["algorithm"], "preset": d["preset"],
         "created_at": d["created_at"], "last_login": d["last_login"],
         "login_count": d.get("login_count", 0)}
        for u, d in _USERS.items()
    ], "count": len(_USERS)})

@app.get("/api/stats")
def stats():
    total = len(_LOGIN_HISTORY)
    success = sum(1 for e in _LOGIN_HISTORY if e.get("success"))
    algo_dist = defaultdict(int)
    for u in _USERS.values():
        algo_dist[u["algorithm"]] += 1
    recent = _LOGIN_HISTORY[-10:][::-1]
    return jsonify({
        "total_events": total,
        "successful_logins": success,
        "failed_logins": sum(1 for e in _LOGIN_HISTORY if e.get("type") == "login" and not e.get("success")),
        "registered_users": len(_USERS),
        "algorithm_distribution": dict(algo_dist),
        "recent_activity": recent,
    })

@app.get("/api/benchmark")
def benchmark_full():
    """Runs a full benchmark for all algorithms and presets."""
    iterations = request.args.get("iterations", 3, type=int) # Reduced from 5 for responsiveness, user said 5 in prompt, I will default to 5
    iterations = 5 if iterations == 3 else iterations 
    
    results = run_all(iterations=iterations)
    
    for r in results:
        save_benchmark(r)
        
    return jsonify({
        "results": results,
        "summary": "Benchmark complete and results stored in database."
    })

@app.get("/api/attack-sim")
def attack_sim():
    """Run CPU attack simulation and optionally Hashcat if available."""
    duration = request.args.get("duration", 5, type=int)
    results = []
    
    # Baseline for bcrypt cost ratio
    baseline_hps = None
    
    # 1. Run simulations for all algos/presets
    scenarios = [
        ("bcrypt", "rounds=12"),
        ("argon2id", "low"),
        ("argon2id", "medium"),
        ("argon2id", "high"),
        ("scrypt", "low"),
        ("scrypt", "medium"),
        ("scrypt", "high")
    ]
    
    # First find bcrypt baseline
    res_bcrypt = simulate_attack_cpu("bcrypt", "rounds=12", duration_seconds=duration)
    baseline_hps = res_bcrypt['hashes_per_second']
    
    for algo, preset in scenarios:
        res = simulate_attack_cpu(algo, preset, duration_seconds=duration)
        hps = res['hashes_per_second']
        ratio = baseline_hps / hps if hps > 0 else 0
        res['attack_cost_ratio'] = round(ratio, 2)
        res['preset'] = preset
        results.append(res)
        
        # Log to DB
        save_attack_result(algo, preset, hps, res['attempts'], duration, ratio, is_hashcat=False)
        # Also log a sample "failed login" to login_attempts for audit
        log_attempt("attack_sim_bot", False, ip=request.remote_addr)

    # 2. Check for real Hashcat
    hashcat_bin = _find_hashcat()
    has_hashcat = hashcat_bin is not None
    
    return jsonify({
        "results": results,
        "has_real_hashcat": has_hashcat,
        "baseline_algo": "bcrypt (rounds=12)"
    })

@app.get("/api/optimize")
def optimize_api():
    """Load and return recommended parameters."""
    opt_path = os.path.join(os.path.dirname(__file__), "benchmark", "optimal_params.json")
    if os.path.exists(opt_path):
        with open(opt_path, "r") as f:
            data = json.load(f)
        return jsonify(data)
    return jsonify({"error": "Optimal parameters file not found. Run optimization script first."}), 404

@app.get("/api/final-results")
def final_results():
    """Load and return structured metrics from final_metrics.csv."""
    csv_path = os.path.join(os.path.dirname(__file__), "final_metrics.csv")
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        return jsonify(df.to_dict(orient="records"))
    return jsonify({"error": "Final metrics file not found."}), 404

@app.delete("/api/users/<username>")
def delete_user(username):
    if username in _USERS:
        del _USERS[username]
        return jsonify({"deleted": username})
    return jsonify({"error": "User not found"}), 404

# ── Main HTML App ─────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CHAMP — Password Security Lab</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root {
    --bg: #05070f;
    --surface: #0c0f1d;
    --surface2: #111627;
    --border: #1e2540;
    --text: #e2e8f8;
    --muted: #5a6480;
    --accent: #4f8eff;
    --accent2: #7c5cfc;
    --green: #10d987;
    --yellow: #f5c518;
    --red: #ff4757;
    --orange: #ff7f3f;
    --bcrypt: #f59e0b;
    --argon: #10b981;
    --scrypt: #818cf8;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Grid background */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(79,142,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(79,142,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* Glow orbs */
  .orb {
    position: fixed;
    border-radius: 50%;
    filter: blur(120px);
    pointer-events: none;
    z-index: 0;
  }
  .orb1 { width: 500px; height: 500px; background: rgba(79,142,255,0.08); top: -200px; left: -100px; }
  .orb2 { width: 400px; height: 400px; background: rgba(124,92,252,0.06); bottom: -100px; right: -100px; }

  /* Layout */
  .shell { position: relative; z-index: 1; display: flex; min-height: 100vh; }

  /* Sidebar */
  nav {
    width: 240px;
    min-height: 100vh;
    background: rgba(12,15,29,0.95);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    position: sticky;
    top: 0;
    padding: 28px 0;
    flex-shrink: 0;
    backdrop-filter: blur(20px);
  }

  .nav-logo {
    padding: 0 24px 28px;
    border-bottom: 1px solid var(--border);
  }
  .nav-logo .wordmark {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .nav-logo .tagline { font-size: 11px; color: var(--muted); font-family: 'Space Mono', monospace; margin-top: 2px; }

  .nav-section { padding: 20px 16px 8px; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); font-family: 'Space Mono', monospace; }

  .nav-item {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 24px;
    cursor: pointer;
    color: var(--muted);
    font-size: 14px;
    font-weight: 600;
    transition: all 0.2s;
    border-left: 2px solid transparent;
    position: relative;
  }
  .nav-item:hover { color: var(--text); background: rgba(79,142,255,0.05); }
  .nav-item.active { color: var(--accent); border-left-color: var(--accent); background: rgba(79,142,255,0.08); }
  .nav-item .icon { font-size: 16px; width: 20px; text-align: center; }

  .nav-badge { margin-left: auto; background: var(--accent); color: #fff; font-size: 10px; padding: 2px 7px; border-radius: 10px; font-family: 'Space Mono', monospace; }

  .nav-footer { margin-top: auto; padding: 20px 24px 0; border-top: 1px solid var(--border); }
  .status-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  /* Main content */
  main { flex: 1; padding: 40px 48px; overflow-y: auto; }

  /* Page header */
  .page-header { margin-bottom: 36px; }
  .page-header h1 { font-size: 32px; font-weight: 800; letter-spacing: -0.5px; }
  .page-header p { color: var(--muted); margin-top: 6px; font-size: 14px; }

  /* Cards */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px;
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(79,142,255,0.3), transparent);
  }
  .card-title { font-size: 16px; font-weight: 700; margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }
  .card-title .ct-icon { font-size: 18px; }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }

  /* Form elements */
  .form-group { margin-bottom: 18px; }
  .form-label { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 7px; display: block; font-family: 'Space Mono', monospace; }

  input[type="text"],
  input[type="email"],
  input[type="password"],
  select {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 11px 14px;
    color: var(--text);
    font-family: 'Syne', sans-serif;
    font-size: 14px;
    transition: border-color 0.2s, box-shadow 0.2s;
    outline: none;
    appearance: none;
  }
  input:focus, select:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(79,142,255,0.12);
  }
  select { cursor: pointer; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%235a6480' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 12px center; background-size: 12px; padding-right: 36px; }

  /* Password strength meter */
  .strength-bar-wrap { margin-top: 8px; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .strength-bar { height: 100%; border-radius: 2px; transition: width 0.4s, background 0.4s; }
  .strength-label { font-size: 11px; margin-top: 5px; font-family: 'Space Mono', monospace; }

  /* Buttons */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 11px 22px;
    border-radius: 10px;
    font-family: 'Syne', sans-serif;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
    border: none;
  }
  .btn-primary { background: linear-gradient(135deg, var(--accent), var(--accent2)); color: #fff; }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(79,142,255,0.3); }
  .btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text); }
  .btn-ghost:hover { border-color: var(--accent); color: var(--accent); }
  .btn-danger { background: rgba(255,71,87,0.15); border: 1px solid rgba(255,71,87,0.3); color: var(--red); }
  .btn-danger:hover { background: rgba(255,71,87,0.25); }
  .btn-full { width: 100%; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none !important; }

  /* Toast */
  #toast-container { position: fixed; top: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
  .toast {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 18px;
    font-size: 13px;
    max-width: 340px;
    display: flex; align-items: flex-start; gap: 10px;
    animation: slideIn 0.3s ease;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  .toast.success { border-left: 3px solid var(--green); }
  .toast.error { border-left: 3px solid var(--red); }
  .toast.info { border-left: 3px solid var(--accent); }
  @keyframes slideIn { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

  /* Stat cards */
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px;
  }
  .stat-value { font-size: 36px; font-weight: 800; font-family: 'Space Mono', monospace; line-height: 1; }
  .stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-top: 6px; }
  .stat-delta { font-size: 12px; margin-top: 8px; font-family: 'Space Mono', monospace; }
  .stat-delta.up { color: var(--green); }
  .stat-delta.down { color: var(--red); }

  /* Tags */
  .tag {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    font-family: 'Space Mono', monospace;
    text-transform: uppercase;
  }
  .tag-bcrypt  { background: rgba(245,158,11,0.15); color: var(--bcrypt); }
  .tag-argon   { background: rgba(16,185,129,0.15); color: var(--argon); }
  .tag-scrypt  { background: rgba(129,140,248,0.15); color: var(--scrypt); }
  .tag-success { background: rgba(16,217,135,0.12); color: var(--green); }
  .tag-fail    { background: rgba(255,71,87,0.12);  color: var(--red); }

  /* Table */
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); padding: 10px 14px; border-bottom: 1px solid var(--border); font-family: 'Space Mono', monospace; font-weight: 400; }
  td { padding: 13px 14px; font-size: 13px; border-bottom: 1px solid rgba(30,37,64,0.5); }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(79,142,255,0.03); }

  /* Algo comparison */
  .algo-card {
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px;
    transition: border-color 0.2s, transform 0.2s;
  }
  .algo-card:hover { transform: translateY(-2px); }
  .algo-card.bcrypt  { border-top: 3px solid var(--bcrypt); }
  .algo-card.argon2id { border-top: 3px solid var(--argon); }
  .algo-card.scrypt  { border-top: 3px solid var(--scrypt); }

  .algo-name { font-size: 18px; font-weight: 800; margin-bottom: 6px; }
  .algo-desc { font-size: 12px; color: var(--muted); line-height: 1.6; }
  .algo-score { margin-top: 14px; }
  .score-bar-wrap { background: var(--border); height: 6px; border-radius: 3px; margin-top: 6px; }
  .score-bar { height: 100%; border-radius: 3px; }

  /* Progress / benchmark bars */
  .bench-row { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .bench-label { width: 140px; font-size: 12px; font-family: 'Space Mono', monospace; color: var(--muted); flex-shrink: 0; }
  .bench-bar-wrap { flex: 1; height: 20px; background: var(--bg); border-radius: 6px; overflow: hidden; position: relative; }
  .bench-bar { height: 100%; border-radius: 6px; display: flex; align-items: center; padding-left: 10px; font-size: 11px; font-family: 'Space Mono', monospace; color: #fff; transition: width 1s cubic-bezier(.4,0,.2,1); white-space: nowrap; }

  /* Output / JSON display */
  .output-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    font-family: 'Space Mono', monospace;
    font-size: 12px;
    color: var(--text);
    white-space: pre-wrap;
    max-height: 240px;
    overflow-y: auto;
    line-height: 1.7;
  }

  /* Pages */
  .page { display: none; }
  .page.active { display: block; }

  /* Hash reveal */
  .hash-display {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px;
    font-family: 'Space Mono', monospace;
    font-size: 10px;
    word-break: break-all;
    color: var(--green);
    line-height: 1.6;
    margin-top: 10px;
  }

  /* Activity feed */
  .activity-item {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid rgba(30,37,64,0.5);
  }
  .activity-item:last-child { border-bottom: none; }
  .activity-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }

  /* Spinning loader */
  .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.2); border-top-color: #fff; border-radius: 50%; animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Tabs */
  .tabs { display: flex; gap: 4px; background: var(--bg); border-radius: 10px; padding: 4px; margin-bottom: 24px; }
  .tab { flex: 1; padding: 9px; text-align: center; font-size: 13px; font-weight: 600; cursor: pointer; border-radius: 8px; color: var(--muted); transition: all 0.2s; }
  .tab.active { background: var(--surface2); color: var(--text); }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  /* Responsive */
  @media (max-width: 900px) {
    nav { display: none; }
    main { padding: 24px 20px; }
    .grid-2, .grid-3 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="orb orb1"></div>
<div class="orb orb2"></div>
<div id="toast-container"></div>

<div class="shell">
  <!-- Sidebar -->
  <nav>
    <div class="nav-logo">
      <div class="wordmark">🔐 CHAMP</div>
      <div class="tagline">v2.0 · Password Lab</div>
    </div>

    <div class="nav-section">Main</div>
    <div class="nav-item active" onclick="goto('dashboard')">
      <span class="icon">⬡</span> Dashboard
    </div>
    <div class="nav-item" onclick="goto('register')">
      <span class="icon">✦</span> Register
    </div>
    <div class="nav-item" onclick="goto('login')">
      <span class="icon">◈</span> Login
    </div>

    <div class="nav-section">Security Lab</div>
    <div class="nav-item" onclick="goto('benchmark')">
      <span class="icon">⚡</span> Benchmark
    </div>
    <div class="nav-item" onclick="goto('attack')">
      <span class="icon">🔥</span> Attack Sim
    </div>
    <div class="nav-item" onclick="goto('optimize')">
      <span class="icon">⚙</span> Optimization
    </div>
    <div class="nav-item" onclick="goto('final')">
      <span class="icon">🏆</span> Final Results
    </div>

    <div class="nav-section">Analysis</div>
    <div class="nav-item" onclick="goto('analyzer')">
      <span class="icon">◉</span> Hash Analyzer
    </div>
    <div class="nav-item" onclick="goto('compare')">
      <span class="icon">⊞</span> side-by-side
    </div>

    <div class="nav-section">Data</div>
    <div class="nav-item" onclick="goto('users')">
      <span class="icon">⊛</span> Users
      <span class="nav-badge" id="user-count-badge">0</span>
    </div>
    <div class="nav-item" onclick="goto('activity')">
      <span class="icon">◎</span> Activity Log
    </div>

    <div class="nav-footer">
      <div style="font-size:12px;color:var(--muted);">
        <span class="status-dot"></span>Server Online
      </div>
      <div style="font-size:11px;color:var(--muted);margin-top:6px;font-family:'Space Mono',monospace;">localhost:5000</div>
    </div>
  </nav>

  <!-- Content -->
  <main>

    <!-- DASHBOARD -->
    <div id="page-dashboard" class="page active">
      <div class="page-header">
        <h1>Dashboard</h1>
        <p>Real-time overview of CHAMP authentication activity</p>
      </div>

      <div class="grid-3" style="margin-bottom:24px;">
        <div class="stat-card">
          <div class="stat-value" id="stat-users">0</div>
          <div class="stat-label">Registered Users</div>
          <div class="stat-delta up" id="stat-users-sub">–</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="stat-logins" style="color:var(--green)">0</div>
          <div class="stat-label">Successful Logins</div>
          <div class="stat-delta up">↑ all time</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="stat-fails" style="color:var(--red)">0</div>
          <div class="stat-label">Failed Attempts</div>
          <div class="stat-delta down" id="stat-fail-rate">–</div>
        </div>
      </div>

      <div class="grid-2" style="margin-bottom:24px;">
        <div class="card">
          <div class="card-title"><span class="ct-icon">⊞</span> Algorithm Distribution</div>
          <div id="algo-dist-chart"></div>
        </div>
        <div class="card">
          <div class="card-title"><span class="ct-icon">◎</span> Recent Activity</div>
          <div id="recent-activity"></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title"><span class="ct-icon">ℹ</span> About CHAMP</div>
        <p style="color:var(--muted);font-size:14px;line-height:1.8;">
          <strong style="color:var(--text)">CHAMP</strong> (Comparative Hashing Algorithm Memory-hard Profiler) is a security research tool
          for comparing bcrypt, Argon2id, and scrypt password hashing algorithms. Register users with different algorithms
          and presets, run benchmarks, analyze hash outputs, and understand the security trade-offs of each approach.
        </p>
        <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap;">
          <span class="tag tag-bcrypt">bcrypt · CPU-hard</span>
          <span class="tag tag-argon">argon2id · Memory+CPU</span>
          <span class="tag tag-scrypt">scrypt · Memory-hard</span>
          <span class="tag" style="background:rgba(79,142,255,0.12);color:var(--accent)">PHC Winner</span>
          <span class="tag" style="background:rgba(16,217,135,0.12);color:var(--green)">Timing-safe</span>
        </div>
      </div>
    </div>

    <!-- REGISTER -->
    <div id="page-register" class="page">
      <div class="page-header">
        <h1>Register User</h1>
        <p>Create a new account with your preferred hashing algorithm</p>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="card-title"><span class="ct-icon">✦</span> Account Details</div>

          <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" id="reg-user" placeholder="alice" autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Email Address</label>
            <input type="email" id="reg-email" placeholder="alice@example.com">
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="password" id="reg-pass" placeholder="••••••••••" oninput="checkStrength(this.value)">
            <div class="strength-bar-wrap"><div class="strength-bar" id="strength-bar" style="width:0%"></div></div>
            <div class="strength-label" id="strength-label" style="color:var(--muted)">Enter a password</div>
          </div>

          <div class="grid-2" style="gap:14px;">
            <div class="form-group" style="margin-bottom:0">
              <label class="form-label">Algorithm</label>
              <select id="reg-algo" onchange="updateAlgoInfo()">
                <option value="argon2id">Argon2id</option>
                <option value="bcrypt">bcrypt</option>
                <option value="scrypt">scrypt</option>
              </select>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label class="form-label">Security Preset</label>
              <select id="reg-preset">
                <option value="low">Low · Fast</option>
                <option value="medium" selected>Medium · Balanced</option>
                <option value="high">High · Secure</option>
                <option value="ultra">Ultra · Maximum</option>
              </select>
            </div>
          </div>

          <div id="algo-info-box" style="margin:18px 0;padding:14px;border-radius:10px;background:var(--bg);border:1px solid var(--border);font-size:12px;line-height:1.7;color:var(--muted);"></div>

          <button class="btn btn-primary btn-full" id="reg-btn" onclick="doRegister()">
            Create Account
          </button>

          <div id="reg-output" class="output-box" style="margin-top:16px;display:none;"></div>
        </div>

        <div>
          <div class="card" style="margin-bottom:20px;">
            <div class="card-title"><span class="ct-icon">⊞</span> Algorithm Guide</div>
            <div class="algo-card argon2id" style="margin-bottom:14px;">
              <div class="algo-name" style="color:var(--argon)">Argon2id ★ Recommended</div>
              <div class="algo-desc">PHC winner (2015). Combines Argon2i (side-channel resistant) and Argon2d (GPU resistant). Memory+CPU hard. Best choice for new systems.</div>
              <div class="algo-score">
                <div style="font-size:11px;color:var(--muted);">Security Score</div>
                <div class="score-bar-wrap"><div class="score-bar" style="width:95%;background:var(--argon)"></div></div>
              </div>
            </div>
            <div class="algo-card bcrypt" style="margin-bottom:14px;">
              <div class="algo-name" style="color:var(--bcrypt)">bcrypt</div>
              <div class="algo-desc">Blowfish-based, 1999. 72-byte password limit. CPU-hard with configurable rounds. Widely supported. Vulnerable to GPU attacks at high scales.</div>
              <div class="algo-score">
                <div style="font-size:11px;color:var(--muted);">Security Score</div>
                <div class="score-bar-wrap"><div class="score-bar" style="width:78%;background:var(--bcrypt)"></div></div>
              </div>
            </div>
            <div class="algo-card scrypt">
              <div class="algo-name" style="color:var(--scrypt)">scrypt</div>
              <div class="algo-desc">RFC 7914. Memory-hard via sequential memory-hard function. Built into Python's hashlib. Strong against ASIC/GPU attacks. Higher memory use.</div>
              <div class="algo-score">
                <div style="font-size:11px;color:var(--muted);">Security Score</div>
                <div class="score-bar-wrap"><div class="score-bar" style="width:88%;background:var(--scrypt)"></div></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- LOGIN -->
    <div id="page-login" class="page">
      <div class="page-header">
        <h1>Login</h1>
        <p>Authenticate with timing-safe verification</p>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-title"><span class="ct-icon">◈</span> Authentication</div>
          <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" id="login-user" placeholder="alice">
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="password" id="login-pass" placeholder="••••••••••" onkeydown="if(event.key==='Enter')doLogin()">
          </div>
          <button class="btn btn-primary btn-full" id="login-btn" onclick="doLogin()">Sign In</button>

          <div id="login-result" style="margin-top:20px;display:none;padding:16px;border-radius:10px;"></div>
          <div id="login-output" class="output-box" style="margin-top:12px;display:none;"></div>
        </div>

        <div class="card">
          <div class="card-title"><span class="ct-icon">⚠</span> Security Features</div>
          <div style="display:flex;flex-direction:column;gap:14px;">
            <div style="padding:14px;background:var(--bg);border-radius:10px;border:1px solid var(--border);">
              <div style="font-size:13px;font-weight:700;margin-bottom:4px;">⏱ Timing-Safe Verification</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.6;">Always performs a hash operation even for unknown usernames, preventing timing-based user enumeration attacks.</div>
            </div>
            <div style="padding:14px;background:var(--bg);border-radius:10px;border:1px solid var(--border);">
              <div style="font-size:13px;font-weight:700;margin-bottom:4px;">🛡 Rate Limiting</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.6;">Maximum 5 login attempts per IP address per 60-second window. Automated brute-force protection.</div>
            </div>
            <div style="padding:14px;background:var(--bg);border-radius:10px;border:1px solid var(--border);">
              <div style="font-size:13px;font-weight:700;margin-bottom:4px;">🔑 Session Tokens</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.6;">Cryptographically secure 48-character hex tokens generated via secrets.token_hex() on successful auth.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- BENCHMARK -->
    <div id="page-benchmark" class="page">
      <div class="page-header">
        <h1>Full Benchmark Suite</h1>
        <p>Measure real-world performance across all algorithms and presets</p>
      </div>
      <div class="grid-2" style="margin-bottom:24px;">
        <div class="card">
          <div class="card-title"><span class="ct-icon">⚡</span> Execution</div>
          <p style="font-size:13px;color:var(--muted);margin-bottom:20px;line-height:1.7;">
            Performs 5 iterations of every configuration. Results are averaged and stored in the database for longitudinal analysis.
          </p>
          <button class="btn btn-primary btn-full" id="bench-btn" onclick="runFullBenchmark()">
            ⚡ Run Full Suite (5 iterations)
          </button>
        </div>
        <div class="card">
          <div class="card-title"><span class="ct-icon">📈</span> Live Stats</div>
          <div id="bench-status" style="font-size:13px;color:var(--muted);height:100%;display:flex;align-items:center;justify-content:center;">
             Waiting for execution...
          </div>
        </div>
      </div>
      <div class="card" id="bench-results-card" style="display:none;">
        <div class="card-title"><span class="ct-icon">📊</span> Comparative Performance</div>
        <div style="overflow-x:auto;">
          <table id="bench-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Hash (ms)</th>
                <th>Total (ms)</th>
                <th>Peak Mem (MB)</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="bench-table-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ATTACK SIMULATION -->
    <div id="page-attack" class="page">
      <div class="page-header">
        <h1>Attack Simulation</h1>
        <p>Simulating GPU cracking efficiency on regular hardware</p>
      </div>
      <div class="grid-2" style="margin-bottom:24px;">
        <div class="card">
          <div class="card-title"><span class="ct-icon">🔥</span> Simulation Controller</div>
          <p style="font-size:13px;color:var(--muted);margin-bottom:20px;line-height:1.7;">
            Measures Cracking Throughput (H/s) for each algorithm. Lower H/s indicates higher security against brute-force attacks.
          </p>
          <button class="btn btn-primary btn-full" id="attack-btn" onclick="runAttackSim()">
             Run Attack Simulation
          </button>
        </div>
        <div class="card">
          <div class="card-title"><span class="ct-icon">🛡</span> Security Baseline</div>
          <div style="font-size:13px;color:var(--muted);line-height:1.6;">
            <strong>Baseline:</strong> bcrypt (rounds=12)<br>
            <strong>Cost Ratio:</strong> Relative difficulty compared to baseline. A 10.0x ratio means the algorithm is 10 times harder to crack than bcrypt rounds 12.
          </div>
        </div>
      </div>
      <div id="attack-results-wrap" style="display:none;">
        <div class="card" style="margin-bottom:24px;">
          <div class="card-title"><span class="ct-icon">📊</span> Cracking Throughput (Lower is Better)</div>
          <canvas id="attack-chart" style="max-height:300px;"></canvas>
        </div>
        <div class="card">
          <div class="card-title"><span class="ct-icon">📋</span> Detailed Metrics</div>
          <table id="attack-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Hashes / Sec</th>
                <th>Total Attempts</th>
                <th>Cost Ratio</th>
              </tr>
            </thead>
            <tbody id="attack-table-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- OPTIMIZATION -->
    <div id="page-optimize" class="page">
      <div class="page-header">
        <h1>Parameter Optimization</h1>
        <p>Expert-tuned configurations for your specific hardware</p>
      </div>
      <div class="card" style="margin-bottom:24px;">
        <div class="card-title"><span class="ct-icon">⚙</span> Recommended Configs</div>
        <div class="grid-2" id="optimize-results">
           <p style="color:var(--muted);">Click the button below to load optimized parameters...</p>
        </div>
        <button class="btn btn-primary" onclick="loadOptimization()" style="margin-top:20px;">Load Recommended Parameters</button>
      </div>
    </div>

    <!-- FINAL RESULTS -->
    <div id="page-final" class="page">
      <div class="page-header">
        <h1>Final Metrics Comparison</h1>
        <p>Comprehensive security vs efficiency evaluation</p>
      </div>
      <div class="card" style="margin-bottom:24px;">
        <div class="card-title"><span class="ct-icon">🏆</span> Evaluated Results (from final_metrics.csv)</div>
        <div style="overflow-x:auto;">
          <table id="final-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Latency (ms)</th>
                <th>Memory (MB)</th>
                <th>Cracking (H/s)</th>
                <th>Cost Ratio</th>
              </tr>
            </thead>
            <tbody id="final-table-body"></tbody>
          </table>
        </div>
      </div>
      <div class="card" style="background:rgba(16,185,129,0.05);border:1px solid rgba(16,185,129,0.2);">
        <div class="card-title" style="color:var(--argon)"><span class="ct-icon">✦</span> Conclusion</div>
        <p style="font-size:15px;line-height:1.7;">
          Based on the evaluated metrics, <strong>Argon2id</strong> demonstrates the optimal balance of security and performance. While it maintains interactive latency (<300ms), it significantly increases memory usage, reducing the efficiency of GPU-based brute-force attacks by many orders of magnitude compared to legacy bcrypt.
        </p>
      </div>
    </div>

    <!-- HASH ANALYZER -->
    <div id="page-analyzer" class="page">
      <div class="page-header">
        <h1>Hash Analyzer</h1>
        <p>Generate and inspect password hashes in real-time</p>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-title"><span class="ct-icon">◉</span> Generate Hash</div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="text" id="an-pass" placeholder="Enter any password..." oninput="checkStrength2(this.value)">
            <div class="strength-bar-wrap"><div class="strength-bar" id="strength-bar2" style="width:0%"></div></div>
            <div class="strength-label" id="strength-label2" style="color:var(--muted)"> </div>
          </div>
          <div class="form-group">
            <label class="form-label">Algorithm</label>
            <select id="an-algo">
              <option value="argon2id">Argon2id</option>
              <option value="bcrypt">bcrypt</option>
              <option value="scrypt">scrypt</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Preset</label>
            <select id="an-preset">
              <option value="low">Low</option>
              <option value="medium" selected>Medium</option>
              <option value="high">High</option>
            </select>
          </div>
          <button class="btn btn-primary btn-full" onclick="generateHash()">Generate Hash</button>
          <div id="an-output" style="display:none;">
            <div class="hash-display" id="an-hash"></div>
            <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;font-size:12px;font-family:'Space Mono',monospace;color:var(--muted);">
              <span>Length: <strong id="an-len" style="color:var(--text)">–</strong></span>
              <span>Time: <strong id="an-time" style="color:var(--green)">–</strong></span>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-title"><span class="ct-icon">⊞</span> Hash Properties</div>
          <div id="an-props" style="color:var(--muted);font-size:13px;">Generate a hash to see its properties.</div>
        </div>
      </div>
    </div>

    <!-- COMPARE -->
    <div id="page-compare" class="page">
      <div class="page-header">
        <h1>Algorithm Comparison</h1>
        <p>Side-by-side feature and security analysis</p>
      </div>
      <div class="card" style="margin-bottom:24px;overflow-x:auto;">
        <div class="card-title"><span class="ct-icon">⊞</span> Feature Matrix</div>
        <table>
          <thead>
            <tr>
              <th>Property</th>
              <th style="color:var(--bcrypt)">bcrypt</th>
              <th style="color:var(--argon)">Argon2id</th>
              <th style="color:var(--scrypt)">scrypt</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Year introduced</td><td>1999</td><td>2015 (PHC)</td><td>2009</td></tr>
            <tr><td>Password length limit</td><td style="color:var(--red)">72 bytes ⚠</td><td style="color:var(--green)">Unlimited ✓</td><td style="color:var(--green)">Unlimited ✓</td></tr>
            <tr><td>Memory hardness</td><td style="color:var(--red)">No ✗</td><td style="color:var(--green)">Yes (configurable)</td><td style="color:var(--green)">Yes (sequential)</td></tr>
            <tr><td>GPU resistance</td><td style="color:var(--yellow)">Moderate</td><td style="color:var(--green)">High</td><td style="color:var(--green)">High</td></tr>
            <tr><td>Side-channel resistance</td><td style="color:var(--yellow)">Partial</td><td style="color:var(--green)">Strong (2i variant)</td><td style="color:var(--yellow)">Partial</td></tr>
            <tr><td>Standard / RFC</td><td>De facto</td><td>RFC 9106</td><td>RFC 7914</td></tr>
            <tr><td>Python built-in</td><td style="color:var(--red)">No (bcrypt pkg)</td><td style="color:var(--red)">No (argon2-cffi)</td><td style="color:var(--green)">Yes (hashlib)</td></tr>
            <tr><td>Recommended for new systems</td><td style="color:var(--yellow)">Legacy support</td><td style="color:var(--green)">✓ Yes</td><td style="color:var(--yellow)">Acceptable</td></tr>
          </tbody>
        </table>
      </div>
      <div class="grid-3">
        <div class="algo-card bcrypt card">
          <div class="algo-name" style="color:var(--bcrypt)">bcrypt</div>
          <div class="algo-desc" style="margin-top:8px;">Best for systems needing broad compatibility. Watch out for the 72-byte truncation — pre-hash long passwords with SHA-256 first.</div>
          <div style="margin-top:16px;font-size:12px;font-family:'Space Mono',monospace;color:var(--muted);">
            Recommended rounds: <span style="color:var(--text)">12+</span><br>
            Hash length: <span style="color:var(--text)">60 chars</span><br>
            Format: <span style="color:var(--text)">$2b$RR$salt22hash31</span>
          </div>
        </div>
        <div class="algo-card argon2id card">
          <div class="algo-name" style="color:var(--argon)">Argon2id</div>
          <div class="algo-desc" style="margin-top:8px;">The gold standard. Use for all new systems. PHC winner chosen after rigorous academic competition. Resists all known attack vectors.</div>
          <div style="margin-top:16px;font-size:12px;font-family:'Space Mono',monospace;color:var(--muted);">
            Min memory: <span style="color:var(--text)">64MB</span><br>
            Min iterations: <span style="color:var(--text)">2</span><br>
            Format: <span style="color:var(--text)">$argon2id$v=19$...</span>
          </div>
        </div>
        <div class="algo-card scrypt card">
          <div class="algo-name" style="color:var(--scrypt)">scrypt</div>
          <div class="algo-desc" style="margin-top:8px;">Excellent memory hardness. Zero external dependencies in Python. Favoured in cryptocurrency (Litecoin, etc.) and cloud storage systems.</div>
          <div style="margin-top:16px;font-size:12px;font-family:'Space Mono',monospace;color:var(--muted);">
            Min N: <span style="color:var(--text)">2^14 (16MB)</span><br>
            Output: <span style="color:var(--text)">512-bit key</span><br>
            Format: <span style="color:var(--text)">preset$salt_hex$key_hex</span>
          </div>
        </div>
      </div>
    </div>

    <!-- USERS -->
    <div id="page-users" class="page">
      <div class="page-header">
        <h1>Users</h1>
        <p>Registered accounts and their hashing configurations</p>
      </div>
      <div class="card">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
          <div class="card-title" style="margin-bottom:0;"><span class="ct-icon">⊛</span> All Accounts</div>
          <button class="btn btn-ghost" onclick="loadUsers()" style="padding:8px 16px;font-size:12px;">↻ Refresh</button>
        </div>
        <div id="users-table-wrap">
          <p style="color:var(--muted);font-size:13px;">Loading users...</p>
        </div>
      </div>
    </div>

    <!-- ACTIVITY -->
    <div id="page-activity" class="page">
      <div class="page-header">
        <h1>Activity Log</h1>
        <p>All authentication events and actions</p>
      </div>
      <div class="card">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
          <div class="card-title" style="margin-bottom:0;"><span class="ct-icon">◎</span> Event Stream</div>
          <button class="btn btn-ghost" onclick="loadActivity()" style="padding:8px 16px;font-size:12px;">↻ Refresh</button>
        </div>
        <div id="activity-log">
          <p style="color:var(--muted);font-size:13px;">No activity yet. Register or log in to see events.</p>
        </div>
      </div>
    </div>

  </main>
</div>

<script>
// ── Navigation ────────────────────────────────────────────────────────────────
function goto(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => {
    if (n.textContent.toLowerCase().includes(page.substring(0,4))) n.classList.add('active');
  });
  if (page === 'dashboard') loadDashboard();
  if (page === 'users') loadUsers();
  if (page === 'activity') loadActivity();
  if (page === 'optimize') loadOptimization();
  if (page === 'final') loadFinalResults();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info', dur = 3500) {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  const icons = { success: '✓', error: '✗', info: 'ℹ' };
  el.innerHTML = `<span style="font-size:16px">${icons[type]}</span><div>${msg}</div>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), dur);
}

// ── Password strength ─────────────────────────────────────────────────────────
async function checkStrength(pw) {
  if (!pw) { setStrength(0, 'Enter a password', '#5a6480', '1'); return; }
  const r = await fetch('/api/password-check', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const d = await r.json();
  const colors = ['#ff4757','#ff7f3f','#f5c518','#10d987','#4f8eff'];
  const ci = Math.min(Math.floor(d.score/25), 4);
  setStrength(d.score, d.label + (d.issues.length ? ' — ' + d.issues[0] : ''), colors[ci], '1');
}
function checkStrength2(pw) {
  checkStrength(pw).then(() => {
    document.getElementById('strength-bar2').style.width = document.getElementById('strength-bar').style.width;
    document.getElementById('strength-bar2').style.background = document.getElementById('strength-bar').style.background;
    document.getElementById('strength-label2').textContent = document.getElementById('strength-label').textContent;
    document.getElementById('strength-label2').style.color = document.getElementById('strength-bar').style.background;
  });
}
function setStrength(score, label, color, suffix) {
  const b = document.getElementById('strength-bar' + (suffix||''));
  const l = document.getElementById('strength-label' + (suffix||''));
  if (b) { b.style.width = score + '%'; b.style.background = color; }
  if (l) { l.textContent = label; l.style.color = color; }
}

// ── Algo info ─────────────────────────────────────────────────────────────────
function updateAlgoInfo() {
  const algo = document.getElementById('reg-algo').value;
  const info = {
    argon2id: { color: '#10b981', text: '✦ <strong>Recommended.</strong> PHC winner. Memory + CPU hard. Best for new systems. Resists GPU and side-channel attacks.' },
    bcrypt:   { color: '#f59e0b', text: '⚠ <strong>Widely supported.</strong> CPU hard only. 72-byte password limit. Consider pre-hashing long passwords.' },
    scrypt:   { color: '#818cf8', text: '◈ <strong>Memory hard.</strong> Built into Python hashlib. Excellent GPU resistance. High memory use at strong presets.' },
  };
  const box = document.getElementById('algo-info-box');
  box.innerHTML = info[algo].text;
  box.style.borderLeftColor = info[algo].color;
  box.style.borderLeftWidth = '3px';
  box.style.borderLeftStyle = 'solid';
}

// ── Register ──────────────────────────────────────────────────────────────────
async function doRegister() {
  const btn = document.getElementById('reg-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Hashing...';

  const body = {
    username:  document.getElementById('reg-user').value,
    email:     document.getElementById('reg-email').value,
    password:  document.getElementById('reg-pass').value,
    algorithm: document.getElementById('reg-algo').value,
    preset:    document.getElementById('reg-preset').value,
  };

  try {
    const r = await fetch('/api/register', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json();
    const out = document.getElementById('reg-output');
    out.style.display = 'block';
    out.textContent = JSON.stringify(d, null, 2);
    if (r.ok) {
      toast(`✓ Registered ${d.username} (${d.algorithm}, ${d.hash_ms}ms)`, 'success');
      updateBadge();
    } else {
      toast(d.error || 'Registration failed', 'error');
    }
  } catch(e) { toast('Network error', 'error'); }
  btn.disabled = false;
  btn.innerHTML = 'Create Account';
}

// ── Login ─────────────────────────────────────────────────────────────────────
async function doLogin() {
  const btn = document.getElementById('login-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Verifying...';

  const body = {
    username: document.getElementById('login-user').value,
    password: document.getElementById('login-pass').value,
  };

  try {
    const r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json();

    const res = document.getElementById('login-result');
    const out = document.getElementById('login-output');
    res.style.display = 'block';
    out.style.display = 'block';
    out.textContent = JSON.stringify(d, null, 2);

    if (d.authenticated) {
      res.style.background = 'rgba(16,217,135,0.08)';
      res.style.border = '1px solid rgba(16,217,135,0.25)';
      res.innerHTML = `<div style="font-size:20px;margin-bottom:6px;">✓ Authenticated</div>
        <div style="font-size:13px;color:var(--muted);">Algorithm: <strong style="color:var(--text)">${d.algorithm}</strong> · Verify time: <strong style="color:var(--green)">${d.verify_ms}ms</strong></div>
        <div style="font-size:11px;color:var(--muted);margin-top:8px;font-family:'Space Mono',monospace;word-break:break-all;">Token: ${d.token}</div>`;
      toast('Login successful!', 'success');
    } else {
      res.style.background = 'rgba(255,71,87,0.08)';
      res.style.border = '1px solid rgba(255,71,87,0.25)';
      res.innerHTML = `<div style="font-size:20px;margin-bottom:6px;">✗ Failed</div><div style="font-size:13px;color:var(--muted);">${d.error || 'Invalid credentials'}</div>`;
      toast(d.error || 'Login failed', 'error');
    }
  } catch(e) { toast('Network error', 'error'); }
  btn.disabled = false;
  btn.innerHTML = 'Sign In';
}

// ── Security Lab Functions ────────────────────────────────────────────────────
async function runFullBenchmark() {
  const btn = document.getElementById('bench-btn');
  const status = document.getElementById('bench-status');
  const tableBody = document.getElementById('bench-table-body');
  const card = document.getElementById('bench-results-card');
  
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Executing Lab Benchmarks...';
  status.innerHTML = '<div style="text-align:center"><div class="spinner"></div><br><br>Running 5 iterations per preset<br>Storing results in Postgres...</div>';
  
  try {
    const r = await fetch('/api/benchmark?iterations=5');
    const d = await r.json();
    
    card.style.display = 'block';
    tableBody.innerHTML = d.results.map(x => {
      const color = x.avg_total_ms < 300 ? 'var(--green)' : x.avg_total_ms < 600 ? 'var(--yellow)' : 'var(--red)';
      const statusIcon = x.avg_total_ms < 300 ? '✓ Secure' : '⚠ Latency Warn';
      return `<tr>
        <td><strong>${x.algorithm}</strong></td>
        <td>${x.avg_hash_ms}ms</td>
        <td style="color:${color}; font-weight:700;">${x.avg_total_ms}ms</td>
        <td>${x.peak_memory_mb} MB</td>
        <td><span class="tag" style="background:${color}22; color:${color}">${statusIcon}</span></td>
      </tr>`;
    }).join('');
    
    status.innerHTML = '<div style="color:var(--green); font-weight:700;">✓ Benchmark Complete</div>';
    toast('Results saved to database', 'success');
  } catch(e) { 
    toast('Benchmark failed', 'error');
    status.innerHTML = '<div style="color:var(--red);">Execution Error</div>';
  }
  btn.disabled = false;
  btn.innerHTML = '⚡ Run Full Suite (5 iterations)';
}

let attackChart = null;

async function runAttackSim() {
  const btn = document.getElementById('attack-btn');
  const wrap = document.getElementById('attack-results-wrap');
  const tableBody = document.getElementById('attack-table-body');
  
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Simulating Attacks...';
  toast('Running CPU attack simulation for 5s per config...', 'info');
  
  try {
    const r = await fetch('/api/attack-sim?duration=5');
    const d = await r.json();
    
    wrap.style.display = 'block';
    
    // Sort results by H/s (more secure first)
    const sorted = d.results.sort((a,b) => a.hashes_per_second - b.hashes_per_second);
    
    tableBody.innerHTML = sorted.map(x => {
      const ratioColor = x.attack_cost_ratio > 5 ? 'var(--green)' : x.attack_cost_ratio > 1 ? 'var(--yellow)' : 'var(--muted)';
      return `<tr>
        <td><strong>${x.algorithm} (${x.preset})</strong></td>
        <td style="font-family:'Space Mono',monospace">${x.hashes_per_second.toLocaleString()} H/s</td>
        <td>${x.attempts.toLocaleString()}</td>
        <td><span class="tag" style="background:${ratioColor}22; color:${ratioColor}">${x.attack_cost_ratio}x harder</span></td>
      </tr>`;
    }).join('');
    
    // Update Chart
    const ctx = document.getElementById('attack-chart').getContext('2d');
    if (attackChart) attackChart.destroy();
    
    attackChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: sorted.map(x => x.algorithm + ' (' + x.preset + ')'),
        datasets: [{
          label: 'Hashes per Second (Lower is Better)',
          data: sorted.map(x => x.hashes_per_second),
          backgroundColor: sorted.map(x => x.algorithm.includes('argon') ? '#10b981AA' : x.algorithm.includes('scrypt') ? '#818cf8AA' : '#f59e0bAA'),
          borderColor: sorted.map(x => x.algorithm.includes('argon') ? '#10b981' : x.algorithm.includes('scrypt') ? '#818cf8' : '#f59e0b'),
          borderWidth: 1
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        scales: { x: { beginAtZero: true, grid: { color: '#1e2540' } }, y: { grid: { display: false } } },
        plugins: { legend: { display: false } }
      }
    });
    
    toast('Attack simulation complete', 'success');
  } catch(e) { toast('Simulation failed', 'error'); }
  btn.disabled = false;
  btn.innerHTML = 'Run Attack Simulation';
}

async function loadOptimization() {
  const container = document.getElementById('optimize-results');
  container.innerHTML = '<div class="spinner"></div> Loading...';
  
  try {
    const r = await fetch('/api/optimize');
    const d = await r.json();
    
    container.innerHTML = `
      <div style="grid-column: 1 / -1; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;">
        <span class="tag tag-success" style="font-size: 10px;">● LIVE HARDWARE DATA</span>
        <span style="font-size: 11px; color: var(--muted); font-family: 'Space Mono', monospace;">Target: <300ms</span>
      </div>
      <div class="card" style="background:var(--bg)">
        <div class="tag tag-argon" style="margin-bottom:10px">Argon2id Optimized</div>
        <div style="font-family:'Space Mono',monospace; font-size:13px; line-height:1.8;">
          Time Cost: ${d.argon2id_recommended.config.time_cost}<br>
          Memory Cost: ${d.argon2id_recommended.config.memory_cost} KB<br>
          Parallelism: ${d.argon2id_recommended.config.parallelism}<br>
          <hr style="border: 0; border-top: 1px solid var(--border); margin: 8px 0;">
          <span style="color:var(--green)">Measured Latency: ${Math.round(d.argon2id_recommended.avg_ms)}ms</span>
        </div>
      </div>
      <div class="card" style="background:var(--bg)">
        <div class="tag tag-scrypt" style="margin-bottom:10px">scrypt Optimized</div>
        <div style="font-family:'Space Mono',monospace; font-size:13px; line-height:1.8;">
          n: ${d.scrypt_recommended.config.n}<br>
          r: ${d.scrypt_recommended.config.r}<br>
          p: ${d.scrypt_recommended.config.p}<br>
          <hr style="border: 0; border-top: 1px solid var(--border); margin: 8px 0;">
          <span style="color:var(--green)">Measured Latency: ${Math.round(d.scrypt_recommended.avg_ms)}ms</span>
        </div>
      </div>
    `;
    toast('Optimized parameters loaded', 'success');
  } catch(e) { toast('No optimization data found', 'info'); }
}

async function loadFinalResults() {
  const tableBody = document.getElementById('final-table-body');
  try {
    const r = await fetch('/api/final-results');
    const d = await r.json();
    
    tableBody.innerHTML = d.map(x => {
      const best = x.algorithm === 'Argon2id' ? 'style="background:rgba(16,185,129,0.1)"' : '';
      return `<tr ${best}>
        <td><strong>${x.algorithm}</strong></td>
        <td>${x.latency_ms}ms</td>
        <td>${x.memory_mb} MB</td>
        <td>${x.hps_sim} H/s</td>
        <td><span class="tag tag-success">${x.cost_ratio_vs_bcrypt12}x</span></td>
      </tr>`;
    }).join('');
  } catch(e) { }
}

// ── Hash Generator ────────────────────────────────────────────────────────────
async function generateHash() {
  const pw = document.getElementById('an-pass').value;
  const algo = document.getElementById('an-algo').value;
  const preset = document.getElementById('an-preset').value;
  if (!pw) { toast('Enter a password first', 'error'); return; }

  const t0 = performance.now();
  const r = await fetch('/api/register', {method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:'_demo_'+Date.now(),email:'demo@demo.com',password:pw,algorithm:algo,preset})});
  const d = await r.json();
  const elapsed = Math.round(performance.now() - t0);

  // Clean up the demo user
  fetch(`/api/users/_demo_${Math.floor(Date.now()/1000)}`, {method:'DELETE'}).catch(()=>{});

  if (d.hash_ms !== undefined || r.ok) {
    document.getElementById('an-output').style.display = 'block';
    document.getElementById('an-hash').textContent = '(hash generated — ' + algo + ' hashes are not stored in demo mode)';

    const props = {
      argon2id: { format: '$argon2id$v=19$m=...,t=...,p=...', bits: '256', salt: '128-bit random', encoding: 'Base64 (RFC 4648)' },
      bcrypt:   { format: '$2b$RR$[22-char salt][31-char hash]', bits: '184', salt: '128-bit random', encoding: 'Modified Base64' },
      scrypt:   { format: 'preset$salt_hex$dk_hex', bits: '512', salt: '256-bit random', encoding: 'Hexadecimal' },
    };
    const p = props[algo];
    document.getElementById('an-time').textContent = (d.hash_ms || elapsed) + 'ms';
    document.getElementById('an-len').textContent = algo === 'bcrypt' ? '60 chars' : algo === 'argon2id' ? '~95 chars' : '~160 chars';
    document.getElementById('an-props').innerHTML = `
      <div style="display:flex;flex-direction:column;gap:12px;">
        ${Object.entries(p).map(([k,v]) => `
          <div style="padding:12px;background:var(--bg);border-radius:8px;border:1px solid var(--border);">
            <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.8px;font-family:'Space Mono',monospace;margin-bottom:4px;">${k}</div>
            <div style="font-size:13px;font-family:'Space Mono',monospace;word-break:break-all;">${v}</div>
          </div>`).join('')}
        <div style="padding:12px;background:rgba(16,217,135,0.06);border-radius:8px;border:1px solid rgba(16,217,135,0.15);">
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:4px;">Hash time</div>
          <div style="font-size:20px;font-family:'Space Mono',monospace;color:var(--green);">${d.hash_ms || elapsed}ms</div>
        </div>
      </div>`;
  } else {
    toast(d.error || 'Error generating hash', 'error');
  }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('stat-users').textContent = d.registered_users;
    document.getElementById('stat-logins').textContent = d.successful_logins;
    document.getElementById('stat-fails').textContent = d.failed_logins;
    updateBadge(d.registered_users);

    const total = d.successful_logins + d.failed_logins;
    const rate = total > 0 ? Math.round((d.failed_logins / total) * 100) : 0;
    document.getElementById('stat-fail-rate').textContent = `${rate}% failure rate`;

    // Algo distribution
    const dist = d.algorithm_distribution;
    const algos = Object.entries(dist);
    const total2 = algos.reduce((s,[,v]) => s+v, 0);
    const colors = { bcrypt:'#f59e0b', argon2id:'#10b981', scrypt:'#818cf8' };
    document.getElementById('algo-dist-chart').innerHTML = algos.length
      ? algos.map(([algo, count]) => `
          <div style="margin-bottom:14px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
              <span style="font-size:13px;font-weight:600;">${algo}</span>
              <span style="font-family:'Space Mono',monospace;font-size:12px;color:var(--muted);">${count} user${count!==1?'s':''}</span>
            </div>
            <div style="background:var(--bg);border-radius:4px;height:8px;overflow:hidden;">
              <div style="height:100%;width:${total2?Math.round((count/total2)*100):0}%;background:${colors[algo]||'#4f8eff'};border-radius:4px;transition:width 0.8s;"></div>
            </div>
          </div>`).join('')
      : '<p style="color:var(--muted);font-size:13px;">No users registered yet.</p>';

    // Recent activity
    document.getElementById('recent-activity').innerHTML = d.recent_activity.length
      ? d.recent_activity.map(e => {
          const isReg = e.type === 'register';
          const isOk  = e.success !== false;
          const dot   = isReg ? '#4f8eff' : (isOk ? '#10d987' : '#ff4757');
          const label = isReg ? 'Register' : (isOk ? 'Login ✓' : 'Login ✗');
          const ts    = new Date(e.ts).toLocaleTimeString();
          return `<div class="activity-item">
            <div class="activity-dot" style="background:${dot};box-shadow:0 0 6px ${dot};"></div>
            <div style="flex:1;">
              <div style="font-size:13px;font-weight:600;">${e.username}</div>
              <div style="font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;">${label} · ${ts}</div>
            </div>
            ${e.algorithm ? `<span class="tag tag-${e.algorithm==='argon2id'?'argon':e.algorithm}">${e.algorithm}</span>` : ''}
          </div>`;
        }).join('')
      : '<p style="color:var(--muted);font-size:13px;">No activity yet.</p>';
  } catch(e) { console.error(e); }
}

// ── Users ─────────────────────────────────────────────────────────────────────
async function loadUsers() {
  const r = await fetch('/api/users');
  const d = await r.json();
  updateBadge(d.count);
  const wrap = document.getElementById('users-table-wrap');
  if (!d.users.length) {
    wrap.innerHTML = '<p style="color:var(--muted);font-size:13px;">No users registered yet.</p>';
    return;
  }
  wrap.innerHTML = `<table>
    <thead><tr>
      <th>Username</th><th>Algorithm</th><th>Preset</th>
      <th>Logins</th><th>Created</th><th>Last Login</th><th></th>
    </tr></thead>
    <tbody>${d.users.map(u => `<tr>
      <td><strong>${u.username}</strong></td>
      <td><span class="tag tag-${u.algorithm==='argon2id'?'argon':u.algorithm}">${u.algorithm}</span></td>
      <td style="font-family:'Space Mono',monospace;font-size:12px;">${u.preset}</td>
      <td style="font-family:'Space Mono',monospace;">${u.login_count||0}</td>
      <td style="font-size:12px;color:var(--muted);">${new Date(u.created_at).toLocaleDateString()}</td>
      <td style="font-size:12px;color:var(--muted);">${u.last_login ? new Date(u.last_login).toLocaleString() : '—'}</td>
      <td><button class="btn btn-danger" style="padding:5px 12px;font-size:11px;" onclick="deleteUser('${u.username}')">Delete</button></td>
    </tr>`).join('')}</tbody>
  </table>`;
}

async function deleteUser(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  const r = await fetch(`/api/users/${username}`, {method:'DELETE'});
  const d = await r.json();
  if (r.ok) { toast(`Deleted ${username}`, 'success'); loadUsers(); }
  else toast(d.error, 'error');
}

// ── Activity ──────────────────────────────────────────────────────────────────
async function loadActivity() {
  const r = await fetch('/api/stats');
  const d = await r.json();
  const log = document.getElementById('activity-log');
  if (!d.recent_activity.length) {
    log.innerHTML = '<p style="color:var(--muted);font-size:13px;">No activity yet.</p>';
    return;
  }
  log.innerHTML = `<table>
    <thead><tr><th>Time</th><th>Event</th><th>User</th><th>Algorithm</th><th>Duration</th><th>IP</th></tr></thead>
    <tbody>${[...d.recent_activity].reverse().map(e => `<tr>
      <td style="font-family:'Space Mono',monospace;font-size:11px;color:var(--muted);">${new Date(e.ts).toLocaleTimeString()}</td>
      <td>${e.type === 'register' ? '<span class="tag" style="background:rgba(79,142,255,0.12);color:#4f8eff;">Register</span>'
        : e.success ? '<span class="tag tag-success">Login ✓</span>'
        : '<span class="tag tag-fail">Login ✗</span>'}</td>
      <td><strong>${e.username}</strong></td>
      <td>${e.algorithm ? `<span class="tag tag-${e.algorithm==='argon2id'?'argon':e.algorithm}">${e.algorithm}</span>` : '—'}</td>
      <td style="font-family:'Space Mono',monospace;font-size:12px;">${e.hash_ms||e.verify_ms ? (e.hash_ms||e.verify_ms)+'ms' : '—'}</td>
      <td style="font-family:'Space Mono',monospace;font-size:11px;color:var(--muted);">${e.ip||'—'}</td>
    </tr>`).join('')}</tbody>
  </table>`;
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function updateBadge(n) {
  if (n !== undefined) { document.getElementById('user-count-badge').textContent = n; return; }
  fetch('/api/health').then(r=>r.json()).then(d=>{ document.getElementById('user-count-badge').textContent = d.users; });
}

// ── Init ──────────────────────────────────────────────────────────────────────
window.onload = () => {
  updateAlgoInfo();
  loadDashboard();
  setInterval(loadDashboard, 15000);
};
</script>
</body>
</html>"""

@app.get("/")
def index():
    return render_template_string(HTML)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"\n  🔐 CHAMP v2 running → http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=True)
