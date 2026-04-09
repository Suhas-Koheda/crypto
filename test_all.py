"""
CHAMP Quick Test — Run this first to verify all modules work correctly.
No database or Hashcat required.

Usage:  python test_all.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from auth import bcrypt_auth, argon2_auth, scrypt_auth

PASS_CORRECT = "MySecurePass@123"
PASS_WRONG   = "wrongpassword"
PASS_FAIL_COUNT = 0
PASS_OK_COUNT   = 0


def check(label: str, result: bool, expected: bool):
    global PASS_FAIL_COUNT, PASS_OK_COUNT
    status = "✓ PASS" if result == expected else "✗ FAIL"
    if result != expected:
        PASS_FAIL_COUNT += 1
    else:
        PASS_OK_COUNT += 1
    print(f"  {status}  {label}")


def test_bcrypt():
    print("\n── bcrypt ──────────────────────────────────────")
    h = bcrypt_auth.hash_password(PASS_CORRECT, rounds=10)
    print(f"  Hash (first 40 chars): {h[:40]}...")
    check("Correct password verifies", bcrypt_auth.verify_password(PASS_CORRECT, h), True)
    check("Wrong password rejected",  bcrypt_auth.verify_password(PASS_WRONG, h),   False)
    check("Hash starts with $2b$",    h.startswith("$2b$"),                          True)


def test_argon2():
    print("\n── Argon2id ────────────────────────────────────")
    for preset in ["low", "medium", "high"]:
        params = argon2_auth.PRESETS[preset]
        t0 = time.perf_counter()
        h = argon2_auth.hash_password(PASS_CORRECT, **params)
        ms = (time.perf_counter() - t0) * 1000
        print(f"  [{preset}] Hash time: {ms:.1f}ms | {h[:50]}...")
        check(f"[{preset}] Correct password verifies",
              argon2_auth.verify_password(PASS_CORRECT, h, **params), True)
        check(f"[{preset}] Wrong password rejected",
              argon2_auth.verify_password(PASS_WRONG, h, **params),   False)


def test_scrypt():
    print("\n── scrypt ──────────────────────────────────────")
    for preset in ["low", "medium"]:
        t0 = time.perf_counter()
        h = scrypt_auth.hash_password(PASS_CORRECT, preset=preset)
        ms = (time.perf_counter() - t0) * 1000
        print(f"  [{preset}] Hash time: {ms:.1f}ms | {h[:50]}...")
        check(f"[{preset}] Correct password verifies",
              scrypt_auth.verify_password(PASS_CORRECT, h), True)
        check(f"[{preset}] Wrong password rejected",
              scrypt_auth.verify_password(PASS_WRONG, h),   False)
        check(f"[{preset}] Hash has 3 parts (preset$salt$dk)",
              len(h.split("$")) == 3, True)


def test_benchmark():
    print("\n── Quick Benchmark (3 iterations each) ────────")
    r1 = bcrypt_auth.benchmark(iterations=3, rounds=10)
    print(f"  bcrypt r10:   {r1['avg_total_ms']}ms  |  {r1['peak_memory_mb']}MB")

    r2 = argon2_auth.benchmark(iterations=2, preset="low")
    print(f"  Argon2id low: {r2['avg_total_ms']}ms  |  {r2['peak_memory_mb']}MB")

    r3 = scrypt_auth.benchmark(iterations=2, preset="low")
    print(f"  scrypt low:   {r3['avg_total_ms']}ms  |  {r3['peak_memory_mb']}MB")


if __name__ == "__main__":
    print("=" * 50)
    print("  CHAMP — Module Test Suite")
    print("=" * 50)

    test_bcrypt()
    test_argon2()
    test_scrypt()
    test_benchmark()

    print("\n" + "=" * 50)
    print(f"  Results: {PASS_OK_COUNT} passed, {PASS_FAIL_COUNT} failed")
    if PASS_FAIL_COUNT == 0:
        print("  All tests passed! ✓")
    else:
        print("  Some tests failed. Check output above.")
    print("=" * 50)
    sys.exit(PASS_FAIL_COUNT)
