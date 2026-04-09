"""
CHAMP Benchmark Module
Compares bcrypt, Argon2id, and scrypt across all presets.
Outputs a formatted table and optionally saves results to CSV and DB.
"""

import csv
import time
import tracemalloc
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from auth import bcrypt_auth, argon2_auth, scrypt_auth

TEST_PASSWORD = "BenchmarkPass@2024!"
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "benchmark_results.csv")


# ── Individual runner ──────────────────────────────────────────────────────────

def run_single(name: str, hash_fn, verify_fn, iterations: int = 5, params: dict = None) -> dict:
    """Run hash+verify benchmark for one algorithm/config."""
    hash_times, verify_times, peak_mems = [], [], []

    for i in range(iterations):
        tracemalloc.start()
        t0 = time.perf_counter()
        if params:
            h = hash_fn(TEST_PASSWORD, **params)
        else:
            h = hash_fn(TEST_PASSWORD)
        hash_time = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        t1 = time.perf_counter()
        if params:
            verify_fn(TEST_PASSWORD, h, **params)
        else:
            verify_fn(TEST_PASSWORD, h)
        verify_time = (time.perf_counter() - t1) * 1000

        hash_times.append(hash_time)
        verify_times.append(verify_time)
        peak_mems.append(peak / 1024 / 1024)
        print(f"    iter {i+1}/{iterations}: hash={hash_time:.1f}ms  verify={verify_time:.1f}ms  mem={peak_mems[-1]:.2f}MB")

    return {
        "algorithm": name,
        "avg_hash_ms": round(sum(hash_times) / len(hash_times), 2),
        "avg_verify_ms": round(sum(verify_times) / len(verify_times), 2),
        "avg_total_ms": round((sum(hash_times) + sum(verify_times)) / len(hash_times), 2),
        "peak_memory_mb": round(max(peak_mems), 3),
        "iterations": iterations,
        "params": params or {},
    }


# ── Full benchmark suite ───────────────────────────────────────────────────────

def run_all(iterations: int = 5):
    results = []

    # ── bcrypt rounds 10, 12, 14 ──────────────────────────────────────────────
    for rounds in [10, 12, 14]:
        print(f"\n[bcrypt rounds={rounds}]")
        r = run_single(
            name=f"bcrypt (rounds={rounds})",
            hash_fn=lambda p, r=rounds: bcrypt_auth.hash_password(p, rounds=r),
            verify_fn=bcrypt_auth.verify_password,
            iterations=iterations,
        )
        r["algorithm_family"] = "bcrypt"
        r["preset"] = f"rounds={rounds}"
        results.append(r)

    # ── Argon2id presets ──────────────────────────────────────────────────────
    for preset, params in argon2_auth.PRESETS.items():
        print(f"\n[Argon2id preset={preset}] params={params}")
        r = run_single(
            name=f"Argon2id ({preset})",
            hash_fn=argon2_auth.hash_password,
            verify_fn=argon2_auth.verify_password,
            iterations=iterations,
            params=params,
        )
        r["algorithm_family"] = "argon2id"
        r["preset"] = preset
        results.append(r)

    # ── scrypt presets ────────────────────────────────────────────────────────
    for preset, params in scrypt_auth.PRESETS.items():
        print(f"\n[scrypt preset={preset}] params={params}")
        r = run_single(
            name=f"scrypt ({preset})",
            hash_fn=lambda p, pr=preset: scrypt_auth.hash_password(p, preset=pr),
            verify_fn=scrypt_auth.verify_password,
            iterations=iterations,
        )
        r["algorithm_family"] = "scrypt"
        r["preset"] = preset
        results.append(r)

    return results


# ── Display table ──────────────────────────────────────────────────────────────

def print_table(results: list):
    col_w = [32, 12, 14, 14, 14]
    headers = ["Algorithm", "Preset", "Hash (ms)", "Total (ms)", "Peak Mem (MB)"]
    sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"

    print("\n" + "=" * 90)
    print("  CHAMP BENCHMARK RESULTS")
    print("=" * 90)
    print(sep)
    print("| " + " | ".join(h.ljust(col_w[i]) for i, h in enumerate(headers)) + " |")
    print(sep)

    for r in results:
        row = [
            r["algorithm"],
            r.get("preset", "-"),
            str(r["avg_hash_ms"]),
            str(r["avg_total_ms"]),
            str(r["peak_memory_mb"]),
        ]
        print("| " + " | ".join(v.ljust(col_w[i]) for i, v in enumerate(row)) + " |")

    print(sep)
    print()

    # Attack cost ratio vs bcrypt-12 baseline
    baseline = next((r for r in results if "bcrypt" in r["algorithm"] and "rounds=12" in r["algorithm"]), None)
    if baseline:
        print("  Attack Cost Ratio vs bcrypt (rounds=12) baseline:")
        print("  (Higher = harder to crack = better)")
        print()
        for r in results:
            if "bcrypt" in r["algorithm"] and "rounds=12" in r["algorithm"]:
                continue
            ratio = r["avg_hash_ms"] / baseline["avg_hash_ms"] if baseline["avg_hash_ms"] > 0 else 0
            bar = "█" * min(int(ratio * 5), 50)
            print(f"  {r['algorithm']:<35} {ratio:>5.1f}×  {bar}")
        print()


# ── Save to CSV ────────────────────────────────────────────────────────────────

def save_csv(results: list, path: str = OUTPUT_CSV):
    fieldnames = ["algorithm", "preset", "avg_hash_ms", "avg_verify_ms",
                  "avg_total_ms", "peak_memory_mb", "iterations"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    print(f"[CSV] Results saved to {path}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CHAMP Benchmark Suite")
    parser.add_argument("--iterations", "-n", type=int, default=3,
                        help="Number of iterations per algorithm (default: 3)")
    parser.add_argument("--csv", action="store_true", help="Save results to CSV")
    args = parser.parse_args()

    print(f"\nRunning benchmark with {args.iterations} iterations per config...")
    results = run_all(iterations=args.iterations)
    print_table(results)

    if args.csv:
        save_csv(results)
