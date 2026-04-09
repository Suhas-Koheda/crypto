"""
bcrypt Authentication Module
Baseline implementation for comparison with memory-hard functions.
"""

import bcrypt
import time
import tracemalloc


def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hash a password using bcrypt.
    rounds=12 is recommended minimum for production.
    """
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against its bcrypt hash.
    Returns True if match, False otherwise.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def benchmark(password: str = "TestPassword@123", iterations: int = 10, rounds: int = 12):
    """
    Benchmark bcrypt hashing and verification.
    Returns dict with avg latency (ms) and peak memory (MB).
    """
    hash_times = []
    verify_times = []
    peak_mems = []

    for _ in range(iterations):
        # --- Hash ---
        tracemalloc.start()
        t0 = time.perf_counter()
        h = hash_password(password, rounds=rounds)
        hash_time = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # --- Verify ---
        t1 = time.perf_counter()
        verify_password(password, h)
        verify_time = (time.perf_counter() - t1) * 1000

        hash_times.append(hash_time)
        verify_times.append(verify_time)
        peak_mems.append(peak / 1024 / 1024)

    return {
        "algorithm": f"bcrypt (rounds={rounds})",
        "avg_hash_ms": round(sum(hash_times) / len(hash_times), 2),
        "avg_verify_ms": round(sum(verify_times) / len(verify_times), 2),
        "avg_total_ms": round((sum(hash_times) + sum(verify_times)) / len(hash_times), 2),
        "peak_memory_mb": round(max(peak_mems), 3),
        "iterations": iterations,
    }


if __name__ == "__main__":
    print("=== bcrypt Benchmark ===")
    result = benchmark(iterations=5)
    for k, v in result.items():
        print(f"  {k}: {v}")