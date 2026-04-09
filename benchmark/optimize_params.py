"""
CHAMP Parameter Optimization Script
Finds the best Argon2id and scrypt parameters that:
  1. Keep authentication latency < 300ms
  2. Maximize memory usage (= harder to crack)

Run this on your target production server to find optimal parameters.
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from auth import argon2_auth, scrypt_auth, bcrypt_auth

TARGET_MAX_MS = 300    # Maximum acceptable auth latency
SAFETY_MARGIN = 0.85   # Use 85% of max to leave headroom
PASSWORD = "OptimizationTestPass@2024"
ITERATIONS = 5         # Per config — increase for more accuracy


# ── Argon2id sweep ────────────────────────────────────────────────────────────

ARGON2_CONFIGS = [
    {"time_cost": 1, "memory_cost": 65536,  "parallelism": 1},   # 64MB
    {"time_cost": 1, "memory_cost": 65536,  "parallelism": 2},
    {"time_cost": 2, "memory_cost": 65536,  "parallelism": 2},
    {"time_cost": 1, "memory_cost": 131072, "parallelism": 2},   # 128MB
    {"time_cost": 2, "memory_cost": 131072, "parallelism": 2},
    {"time_cost": 3, "memory_cost": 131072, "parallelism": 4},
    {"time_cost": 1, "memory_cost": 262144, "parallelism": 2},   # 256MB
    {"time_cost": 2, "memory_cost": 262144, "parallelism": 4},
    {"time_cost": 3, "memory_cost": 262144, "parallelism": 4},
    {"time_cost": 1, "memory_cost": 524288, "parallelism": 4},   # 512MB
    {"time_cost": 2, "memory_cost": 524288, "parallelism": 4},
]

SCRYPT_CONFIGS = [
    {"n": 2**14, "r": 8, "p": 1},   # 16MB
    {"n": 2**15, "r": 8, "p": 1},   # 32MB
    {"n": 2**16, "r": 8, "p": 1},   # 64MB
    {"n": 2**16, "r": 8, "p": 2},
    {"n": 2**17, "r": 8, "p": 1},   # 128MB
    {"n": 2**17, "r": 8, "p": 2},
    {"n": 2**18, "r": 8, "p": 1},   # 256MB
    {"n": 2**19, "r": 8, "p": 1},   # 512MB
]


def measure_latency(hash_fn, verify_fn, params: dict, n: int = ITERATIONS) -> float:
    """Return average total (hash + verify) latency in ms."""
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        h = hash_fn(PASSWORD, **params)
        verify_fn(PASSWORD, h, **params)
        times.append((time.perf_counter() - t0) * 1000)
    return sum(times) / len(times)


def sweep_argon2():
    print("\n" + "=" * 70)
    print("  Argon2id Parameter Sweep")
    print("  Target: <300ms  |  Safety margin: 85%")
    print("=" * 70)

    valid = []
    for cfg in ARGON2_CONFIGS:
        mem_mb = cfg["memory_cost"] // 1024
        label = f"t={cfg['time_cost']} m={mem_mb}MB p={cfg['parallelism']}"
        print(f"  Testing {label}...", end="", flush=True)
        try:
            ms = measure_latency(argon2_auth.hash_password, argon2_auth.verify_password, cfg)
            status = "✓" if ms <= TARGET_MAX_MS * SAFETY_MARGIN else "✗ SLOW"
            print(f" {ms:.1f}ms  {status}")
            if ms <= TARGET_MAX_MS * SAFETY_MARGIN:
                valid.append({"config": cfg, "avg_ms": ms, "memory_mb": mem_mb})
        except Exception as e:
            print(f" ERROR: {e}")

    if valid:
        best = max(valid, key=lambda x: x["memory_mb"])
        print(f"\n  ★ RECOMMENDED Argon2id config:")
        print(f"    {best['config']}")
        print(f"    Latency: {best['avg_ms']:.1f}ms  |  Memory: {best['memory_mb']}MB")
        return best
    else:
        print("\n  No valid configs found under 300ms on this hardware.")
        return None


def sweep_scrypt():
    print("\n" + "=" * 70)
    print("  scrypt Parameter Sweep")
    print("  Target: <300ms  |  Safety margin: 85%")
    print("=" * 70)

    valid = []
    for cfg in SCRYPT_CONFIGS:
        mem_mb = round(128 * cfg["n"] * cfg["r"] / 1024 / 1024)
        label = f"N={cfg['n']} r={cfg['r']} p={cfg['p']} (~{mem_mb}MB)"
        print(f"  Testing {label}...", end="", flush=True)

        # Wrap scrypt to accept **kwargs
        def _hash(password, **kw):
            import hashlib, os as _os
            salt = _os.urandom(32)
            dk = hashlib.scrypt(password.encode(), salt=salt, **kw, dklen=64, maxmem=0x7fffffff)
            return salt.hex() + "$" + dk.hex()

        def _verify(password, stored, **kw):
            import hashlib, hmac
            salt_hex, dk_hex = stored.split("$")
            salt = bytes.fromhex(salt_hex)
            dk = hashlib.scrypt(password.encode(), salt=salt, **kw, dklen=64, maxmem=0x7fffffff)
            return hmac.compare_digest(dk.hex(), dk_hex)

        try:
            ms = measure_latency(_hash, _verify, cfg, n=max(2, ITERATIONS // 2))
            status = "✓" if ms <= TARGET_MAX_MS * SAFETY_MARGIN else "✗ SLOW"
            print(f" {ms:.1f}ms  {status}")
            if ms <= TARGET_MAX_MS * SAFETY_MARGIN:
                valid.append({"config": cfg, "avg_ms": ms, "memory_mb": mem_mb})
        except Exception as e:
            print(f" ERROR: {e}")

    if valid:
        best = max(valid, key=lambda x: x["memory_mb"])
        print(f"\n  ★ RECOMMENDED scrypt config:")
        print(f"    {best['config']}")
        print(f"    Latency: {best['avg_ms']:.1f}ms  |  Memory: {best['memory_mb']}MB")
        return best
    else:
        print("\n  No valid configs found under 300ms on this hardware.")
        return None


def bcrypt_baseline():
    print("\n" + "=" * 70)
    print("  bcrypt Baseline (for comparison)")
    print("=" * 70)
    for rounds in [10, 12, 14]:
        times = []
        for _ in range(ITERATIONS):
            t0 = time.perf_counter()
            h = bcrypt_auth.hash_password(PASSWORD, rounds=rounds)
            bcrypt_auth.verify_password(PASSWORD, h)
            times.append((time.perf_counter() - t0) * 1000)
        avg = sum(times) / len(times)
        print(f"  bcrypt rounds={rounds}: {avg:.1f}ms")


def save_recommendations(argon2_best, scrypt_best):
    report = {
        "argon2id_recommended": argon2_best,
        "scrypt_recommended": scrypt_best,
        "target_max_ms": TARGET_MAX_MS,
        "note": "Run on your production hardware for accurate results.",
    }
    path = os.path.join(os.path.dirname(__file__), "optimal_params.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[Saved] Recommendations written to {path}")


if __name__ == "__main__":
    print("\nCHAMP Parameter Optimizer")
    print("Running on this machine to find optimal parameters...")
    bcrypt_baseline()
    a = sweep_argon2()
    s = sweep_scrypt()
    if a or s:
        save_recommendations(a, s)