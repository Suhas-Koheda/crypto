"""
scrypt Authentication Module
Memory-hard hashing using Python's built-in hashlib.scrypt (RFC 7914).

Parameters:
    n — CPU/memory cost (must be power of 2). Higher = more memory and time.
        n=2^14 (16384)  = ~16 MB
        n=2^17 (131072) = ~128 MB
        n=2^20 (1048576)= ~1 GB
    r — block size (affects memory bandwidth). Default 8.
    p — parallelism factor. Default 1.

Memory formula: ~128 * n * r bytes
"""

import hashlib
import os
import time
import tracemalloc


# ── Preset configurations ──────────────────────────────────────────────────────
PRESETS = {
    "low":    {"n": 2**14, "r": 8, "p": 1},   # ~16 MB
    "medium": {"n": 2**16, "r": 8, "p": 1},   # ~64 MB
    "high":   {"n": 2**17, "r": 8, "p": 1},   # ~128 MB
    "ultra":  {"n": 2**18, "r": 8, "p": 1},   # ~256 MB
}

SALT_SIZE = 32   # 256-bit salt
KEY_LEN   = 64   # 512-bit derived key
SEPARATOR = "$"


def hash_password(password: str, preset: str = "medium", **kwargs) -> str:
    """
    Hash a password using scrypt.
    Returns a string: <salt_hex>$<dk_hex>

    Usage:
        hash_password("mypassword")
        hash_password("mypassword", preset="high")
        hash_password("mypassword", n=2**17, r=8, p=1)  # custom
    """
    params = kwargs if kwargs else PRESETS[preset]
    salt = os.urandom(SALT_SIZE)
    try:
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=params["n"],
            r=params["r"],
            p=params["p"],
            dklen=KEY_LEN,
            maxmem=0x7fffffff,
        )
    except (ValueError, MemoryError):
        return "Skipped due to memory constraints"
    # Store: preset$salt_hex$dk_hex  so we can re-derive with same params
    preset_label = preset if not kwargs else "custom"
    return f"{preset_label}{SEPARATOR}{salt.hex()}{SEPARATOR}{dk.hex()}"


def verify_password(password: str, stored: str, **kwargs) -> bool:
    """
    Verify a password against a stored scrypt hash string.
    Automatically detects preset from stored hash.
    Returns True if match, False otherwise.
    """
    if "Skipped" in stored:
        return False
    try:
        parts = stored.split(SEPARATOR)
        if len(parts) != 3:
            return False
        preset_label, salt_hex, dk_hex = parts
        salt = bytes.fromhex(salt_hex)

        if kwargs:
            params = kwargs
        elif preset_label in PRESETS:
            params = PRESETS[preset_label]
        else:
            return False

        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=params["n"],
            r=params["r"],
            p=params["p"],
            dklen=KEY_LEN,
            maxmem=0x7fffffff,
        )
        # Constant-time comparison to prevent timing attacks
        return hmac_compare(dk.hex(), dk_hex)
    except (ValueError, MemoryError):
        return False
    except Exception:
        return False


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


def benchmark(password: str = "TestPassword@123", iterations: int = 3, preset: str = "medium"):
    """
    Benchmark scrypt hashing and verification.
    Returns dict with timing and memory stats.
    """
    params = PRESETS[preset]
    hash_times = []
    verify_times = []
    peak_mems = []

    for _ in range(iterations):
        tracemalloc.start()
        t0 = time.perf_counter()
        h = hash_password(password, preset=preset)
        hash_time = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        t1 = time.perf_counter()
        verify_password(password, h)
        verify_time = (time.perf_counter() - t1) * 1000

        hash_times.append(hash_time)
        verify_times.append(verify_time)
        peak_mems.append(peak / 1024 / 1024)

    return {
        "algorithm": f"scrypt ({preset})",
        "params": params,
        "avg_hash_ms": round(sum(hash_times) / len(hash_times), 2),
        "avg_verify_ms": round(sum(verify_times) / len(verify_times), 2),
        "avg_total_ms": round((sum(hash_times) + sum(verify_times)) / len(hash_times), 2),
        "peak_memory_mb": round(max(peak_mems), 3),
        "iterations": iterations,
    }


if __name__ == "__main__":
    print("=== scrypt Benchmark (all presets) ===")
    for preset in PRESETS:
        result = benchmark(iterations=2, preset=preset)
        print(f"\n  Preset: {preset}")
        for k, v in result.items():
            print(f"    {k}: {v}")