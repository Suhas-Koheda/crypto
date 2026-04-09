"""
Argon2id Authentication Module
Memory-hard hashing — PHC winner, recommended over bcrypt/scrypt for new systems.

Parameters:
    time_cost   — number of iterations (higher = slower, more secure)
    memory_cost — memory usage in KB (65536 = 64MB, 262144 = 256MB)
    parallelism — number of parallel threads
"""

import time
import tracemalloc
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


# ── Preset configurations ──────────────────────────────────────────────────────
PRESETS = {
    "low":    {"time_cost": 1, "memory_cost": 65536,  "parallelism": 2},   # 64 MB
    "medium": {"time_cost": 2, "memory_cost": 131072, "parallelism": 2},   # 128 MB
    "high":   {"time_cost": 3, "memory_cost": 262144, "parallelism": 4},   # 256 MB
    "ultra":  {"time_cost": 4, "memory_cost": 524288, "parallelism": 4},   # 512 MB
}


def get_hasher(time_cost: int = 2, memory_cost: int = 65536, parallelism: int = 2) -> PasswordHasher:
    """Return a configured Argon2 PasswordHasher instance."""
    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        salt_len=16,
    )


def hash_password(password: str, preset: str = "medium", **kwargs) -> str:
    """
    Hash a password using Argon2id.

    Usage:
        hash_password("mypassword")                        # use preset
        hash_password("mypassword", preset="high")         # stronger preset
        hash_password("mypassword", time_cost=3, memory_cost=131072, parallelism=2)  # custom
    """
    if kwargs:
        ph = get_hasher(**kwargs)
    else:
        ph = get_hasher(**PRESETS[preset])
    return ph.hash(password)


def verify_password(password: str, hashed: str, preset: str = "medium", **kwargs) -> bool:
    """
    Verify a password against its Argon2id hash.
    Returns True if match, False otherwise.
    """
    if kwargs:
        ph = get_hasher(**kwargs)
    else:
        ph = get_hasher(**PRESETS[preset])
    try:
        return ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str, preset: str = "medium", **kwargs) -> bool:
    """
    Check if the stored hash needs to be upgraded (e.g., after changing parameters).
    Call this after a successful login and rehash if True.
    """
    if kwargs:
        ph = get_hasher(**kwargs)
    else:
        ph = get_hasher(**PRESETS[preset])
    return ph.check_needs_rehash(hashed)


def benchmark(password: str = "TestPassword@123", iterations: int = 5, preset: str = "medium"):
    """
    Benchmark Argon2id hashing and verification.
    Returns dict with timing and memory stats.
    """
    params = PRESETS[preset]
    hash_times = []
    verify_times = []
    peak_mems = []

    for _ in range(iterations):
        tracemalloc.start()
        t0 = time.perf_counter()
        h = hash_password(password, **params)
        hash_time = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        t1 = time.perf_counter()
        verify_password(password, h, **params)
        verify_time = (time.perf_counter() - t1) * 1000

        hash_times.append(hash_time)
        verify_times.append(verify_time)
        peak_mems.append(peak / 1024 / 1024)

    return {
        "algorithm": f"Argon2id ({preset})",
        "params": params,
        "avg_hash_ms": round(sum(hash_times) / len(hash_times), 2),
        "avg_verify_ms": round(sum(verify_times) / len(verify_times), 2),
        "avg_total_ms": round((sum(hash_times) + sum(verify_times)) / len(hash_times), 2),
        "peak_memory_mb": round(max(peak_mems), 3),
        "iterations": iterations,
    }


if __name__ == "__main__":
    print("=== Argon2id Benchmark (all presets) ===")
    for preset in PRESETS:
        result = benchmark(iterations=3, preset=preset)
        print(f"\n  Preset: {preset}")
        for k, v in result.items():
            print(f"    {k}: {v}")