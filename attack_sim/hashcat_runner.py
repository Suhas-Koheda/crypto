"""
CHAMP Attack Simulation Module
Generates hash files and runs Hashcat to measure GPU cracking throughput.
Compares cracking speed across bcrypt, Argon2id, and scrypt.

Requirements:
    - Hashcat installed (https://hashcat.net/hashcat/)
    - A wordlist file (e.g. rockyou.txt)
    - GPU drivers installed (optional — CPU mode works too)

Usage:
    python attack_sim/hashcat_runner.py --wordlist /path/to/rockyou.txt
"""

import os
import subprocess
import sys
import json
import time
import re
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from auth import bcrypt_auth, argon2_auth, scrypt_auth

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "hashcat_files")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Test passwords to hash (mix of weak and medium strength)
TEST_PASSWORDS = [
    "password",
    "123456",
    "letmein",
    "admin123",
    "qwerty",
]

# Hashcat mode IDs
# https://hashcat.net/wiki/doku.php?id=hashcat
HASHCAT_MODES = {
    "bcrypt":   "3200",   # bcrypt $2*$
    "argon2id": "35",     # Argon2id  (requires hashcat 6.2.6+)
    # scrypt has no native hashcat mode — we simulate via custom attack
}


# ── Step 1: Generate hash files ────────────────────────────────────────────────

def generate_bcrypt_hashes(rounds: int = 12) -> str:
    """Generate bcrypt hashes for test passwords. Returns path to hash file."""
    path = os.path.join(OUTPUT_DIR, f"bcrypt_r{rounds}_hashes.txt")
    with open(path, "w") as f:
        for pwd in TEST_PASSWORDS:
            h = bcrypt_auth.hash_password(pwd, rounds=rounds)
            f.write(h + "\n")
    print(f"[+] bcrypt hashes written to {path}")
    return path


def generate_argon2_hashes(preset: str = "medium") -> str:
    """Generate Argon2id hashes for test passwords. Returns path to hash file."""
    path = os.path.join(OUTPUT_DIR, f"argon2id_{preset}_hashes.txt")
    params = argon2_auth.PRESETS[preset]
    with open(path, "w") as f:
        for pwd in TEST_PASSWORDS:
            h = argon2_auth.hash_password(pwd, **params)
            f.write(h + "\n")
    print(f"[+] Argon2id hashes written to {path}")
    return path


def generate_scrypt_hashes(preset: str = "medium") -> str:
    """Generate scrypt hashes for test passwords. Returns path to hash file."""
    path = os.path.join(OUTPUT_DIR, f"scrypt_{preset}_hashes.txt")
    with open(path, "w") as f:
        for pwd in TEST_PASSWORDS:
            h = scrypt_auth.hash_password(pwd, preset=preset)
            f.write(h + "\n")
    print(f"[+] scrypt hashes written to {path}")
    return path


# ── Step 2: Run Hashcat ────────────────────────────────────────────────────────

def run_hashcat(hash_file: str, wordlist: str, mode: str,
                timeout: int = 60) -> dict:
    """
    Run Hashcat against a hash file and return cracking stats.

    Returns dict with:
        - hashes_per_second (H/s)
        - cracked_count
        - total_hashes
        - time_elapsed
        - raw_output
    """
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found: {wordlist}")
        return {"error": "Wordlist not found"}

    hashcat_bin = _find_hashcat()
    if not hashcat_bin:
        print("[!] Hashcat not found. Install from https://hashcat.net/hashcat/")
        return {"error": "Hashcat not installed"}

    cmd = [
        hashcat_bin,
        "-m", mode,                     # hash type
        hash_file,                      # hashes to crack
        wordlist,                       # wordlist
        "--status",                     # enable status output
        "--status-timer", "5",          # print status every 5 sec
        "--runtime", str(timeout),      # max runtime
        "--potfile-disable",            # don't save cracked to potfile
        "--outfile-format", "2",        # output: hash:plain
        "-O",                           # optimized kernels
        "--force",                      # ignore warnings (for testing)
    ]

    print(f"\n[Hashcat] Running: {' '.join(cmd)}")
    start = time.time()

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 10
        )
        elapsed = time.time() - start
        output = result.stdout + result.stderr
        stats = _parse_hashcat_output(output, elapsed)
        stats["mode"] = mode
        stats["hash_file"] = hash_file
        return stats
    except subprocess.TimeoutExpired:
        return {"error": "Hashcat timed out", "time_elapsed": timeout}
    except Exception as e:
        return {"error": str(e)}


def _find_hashcat() -> str | None:
    """Find hashcat binary in PATH."""
    for name in ["hashcat", "hashcat.bin", "hashcat64.bin"]:
        path = subprocess.run(["which", name], capture_output=True, text=True).stdout.strip()
        if path:
            return path
    return None


def _parse_hashcat_output(output: str, elapsed: float) -> dict:
    """Parse Hashcat stdout for H/s and cracked count."""
    stats = {"time_elapsed": round(elapsed, 2), "raw_output": output[-2000:]}

    # Extract speed (e.g., "Speed.#1.....: 1234 H/s")
    speed_match = re.search(r"Speed\.#\d+\.+:\s+([\d.]+)\s+([KMG]?H/s)", output)
    if speed_match:
        value, unit = speed_match.group(1), speed_match.group(2)
        multiplier = {"H/s": 1, "kH/s": 1_000, "MH/s": 1_000_000, "GH/s": 1_000_000_000}
        stats["hashes_per_second"] = float(value) * multiplier.get(unit, 1)
        stats["speed_str"] = f"{value} {unit}"
    else:
        stats["hashes_per_second"] = None
        stats["speed_str"] = "N/A"

    # Extract cracked count
    cracked_match = re.search(r"Recovered\.+:\s+(\d+)/(\d+)", output)
    if cracked_match:
        stats["cracked"] = int(cracked_match.group(1))
        stats["total"]   = int(cracked_match.group(2))
    else:
        stats["cracked"] = 0
        stats["total"]   = len(TEST_PASSWORDS)

    return stats


# ── Step 3: Simulate without Hashcat (CPU estimation) ─────────────────────────

def simulate_attack_cpu(algorithm: str, preset: str = "medium",
                        duration_seconds: int = 10, custom_params: dict = None) -> dict:
    """
    Simulate an attack by trying many hashes using Python (CPU-only).
    Useful when Hashcat is not installed.
    Returns estimated H/s.
    """
    import random, string

    def random_password(length=8):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    target_hash = None
    count = 0
    start = time.time()
    deadline = start + duration_seconds

    # Pick hash function
    if algorithm == "bcrypt":
        bcrypt_rounds = {"low": 10, "medium": 12, "high": 14}.get(preset, 12)
        target_hash = bcrypt_auth.hash_password("password123", rounds=bcrypt_rounds)
        fn = lambda p: bcrypt_auth.verify_password(p, target_hash)
    elif algorithm == "argon2id":
        params = custom_params if custom_params else argon2_auth.PRESETS[preset]
        target_hash = argon2_auth.hash_password("password123", **params)
        fn = lambda p: argon2_auth.verify_password(p, target_hash, **params)
    elif algorithm == "scrypt":
        if custom_params:
            target_hash = _scrypt_hash("password123", **custom_params)
            fn = lambda p: _scrypt_verify(p, target_hash, **custom_params)
        else:
            target_hash = scrypt_auth.hash_password("password123", preset=preset)
            fn = lambda p: scrypt_auth.verify_password(p, target_hash)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    print(f"\n[CPU Sim] Attacking {algorithm} ({preset}) for {duration_seconds}s...")
    while time.time() < deadline:
        fn(random_password())
        count += 1

    elapsed = time.time() - start
    hps = count / elapsed

    return {
        "algorithm": algorithm,
        "preset": preset,
        "attempts": count,
        "duration_s": round(elapsed, 2),
        "hashes_per_second": round(hps, 2),
        "mode": "CPU simulation",
    }

def _scrypt_hash(password, **kw):
    import hashlib, os as _os
    salt = _os.urandom(32)
    dk = hashlib.scrypt(password.encode(), salt=salt, **kw, dklen=64, maxmem=0x7fffffff)
    return salt.hex() + "$" + dk.hex()

def _scrypt_verify(password, stored, **kw):
    import hashlib, hmac
    salt_hex, dk_hex = stored.split("$")
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.scrypt(password.encode(), salt=salt, **kw, dklen=64, maxmem=0x7fffffff)
    return hmac.compare_digest(dk.hex(), dk_hex)


# ── Step 4: Print attack comparison ───────────────────────────────────────────

def print_attack_comparison(results: list):
    print("\n" + "=" * 80)
    print("  ATTACK THROUGHPUT COMPARISON")
    print("=" * 80)

    baseline_hps = None
    for r in results:
        hps = r.get("hashes_per_second")
        if hps and "bcrypt" in r.get("algorithm", ""):
            baseline_hps = hps
            break

    print(f"\n{'Algorithm':<35} {'H/s':<15} {'vs bcrypt baseline'}")
    print("-" * 70)
    for r in results:
        alg = r.get("algorithm", "unknown")
        hps = r.get("hashes_per_second", 0) or 0
        hps_str = f"{hps:,.0f}"
        if baseline_hps and baseline_hps > 0:
            ratio = hps / baseline_hps
            ratio_str = f"{ratio:.2f}×"
        else:
            ratio_str = "N/A"
        print(f"{alg:<35} {hps_str:<15} {ratio_str}")
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CHAMP Attack Simulation")
    parser.add_argument("--wordlist", "-w", default="/usr/share/wordlists/rockyou.txt",
                        help="Path to Hashcat wordlist (default: rockyou.txt)")
    parser.add_argument("--cpu-sim", action="store_true",
                        help="Use CPU simulation instead of Hashcat")
    parser.add_argument("--duration", type=int, default=10,
                        help="CPU simulation duration in seconds (default: 10)")
    args = parser.parse_args()

    if args.cpu_sim:
        results = []
        # Standard presets
        for alg in ["bcrypt", "argon2id", "scrypt"]:
            for preset in ["low", "medium", "high"]:
                r = simulate_attack_cpu(alg, preset, duration_seconds=args.duration)
                r["algorithm"] = f"{alg} ({preset})"
                results.append(r)
                print(f"  → {r['hashes_per_second']} H/s")
        
        # Optimized configs
        opt_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "benchmark", "optimal_params.json")
        if os.path.exists(opt_path):
            with open(opt_path) as f:
                opt = json.load(f)
            
            print("\n[CPU Sim] Running RECOMMENDED configs...")
            
            # Argon2 Recommended
            a_cfg = opt["argon2id_recommended"]["config"]
            r_a = simulate_attack_cpu("argon2id", duration_seconds=args.duration, custom_params=a_cfg)
            r_a["algorithm"] = "Argon2id (recommended)"
            results.append(r_a)
            print(f"  → {r_a['hashes_per_second']} H/s")

            # scrypt Recommended
            s_cfg = opt["scrypt_recommended"]["config"]
            r_s = simulate_attack_cpu("scrypt", duration_seconds=args.duration, custom_params=s_cfg)
            r_s["algorithm"] = "scrypt (recommended)"
            results.append(r_s)
            print(f"  → {r_s['hashes_per_second']} H/s")

        print_attack_comparison(results)

    else:
        # Generate hashes and run Hashcat
        bcrypt_file = generate_bcrypt_hashes(rounds=12)
        argon2_file = generate_argon2_hashes(preset="medium")

        results = []

        r1 = run_hashcat(bcrypt_file, args.wordlist, mode=HASHCAT_MODES["bcrypt"])
        r1["algorithm"] = "bcrypt (rounds=12)"
        results.append(r1)

        r2 = run_hashcat(argon2_file, args.wordlist, mode=HASHCAT_MODES["argon2id"])
        r2["algorithm"] = "Argon2id (medium)"
        results.append(r2)

        print_attack_comparison(results)
        print("[+] Raw results saved to:", OUTPUT_DIR)