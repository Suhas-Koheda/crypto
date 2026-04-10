# CHAMP — Secure Password Storage Beyond bcrypt
### Final Year Project | Memory-Hard Hashing Optimization Under GPU Attack Models

---

## Project Structure

```
champ-project/
├── auth/
│   ├── __init__.py          ← Package exports
│   ├── bcrypt_auth.py       ← bcrypt baseline module
│   ├── argon2_auth.py       ← Argon2id memory-hard module
│   └── scrypt_auth.py       ← scrypt memory-hard module
├── benchmark/
│   ├── benchmark.py         ← Full benchmark suite (all algorithms × presets)
│   └── optimize_params.py   ← Parameter optimizer (finds best config for <300ms)
├── attack_sim/
│   └── hashcat_runner.py    ← GPU attack simulation via Hashcat
├── db/
│   ├── schema.sql           ← PostgreSQL schema
│   └── database.py          ← DB connection + CRUD helpers
├── app.py                   ← Flask REST API + demo UI
├── test_all.py              ← Quick test (run first!)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

## Running with Docker (Recommended)

The entire CHAMP laboratory (Flask API + PostgreSQL Database) can be launched instantly using Docker Compose. This ensures all dependencies and the database schema are correctly configured.

### 1. Launch the Stack
```bash
# Build and start the containers in the background
docker-compose up --build -d
```

### 2. Verify the Installation
- **Web Dashboard:** Open [http://localhost:5000](http://localhost:5000) in your browser.
- **Health Check:** `curl http://localhost:5000/api/health`
- **Database:** The database is available on `localhost:5434` for external database tools.

### 3. Management Commands
```bash
# View real-time logs for the API
docker-compose logs -f api

# Stop all services
docker-compose stop

# Remove containers (keeps database data)
docker-compose down

# Reset everything (wipes database volumes)
docker-compose down -v
```

---

## Week-by-Week Setup

### Week 1–2: Install & Test

```bash
# 1. Clone / create project folder
mkdir champ-project && cd champ-project

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the quick test — confirms all modules work
python test_all.py
```

Expected output:
```
All tests passed! ✓
```

---

### Week 3: bcrypt Baseline

```bash
# Run bcrypt module standalone
python auth/bcrypt_auth.py

# Expected output:
# bcrypt avg time: ~250ms  (rounds=12)
```

---

### Week 4: Argon2id + scrypt Integration

```bash
# Run Argon2id module standalone
python auth/argon2_auth.py

# Run scrypt module standalone
python auth/scrypt_auth.py
```

---

### Week 5: Benchmarking + Attack Simulation

```bash
# Full benchmark (3 iterations — increase for accuracy)
python benchmark/benchmark.py --iterations 3

# Save results to CSV
python benchmark/benchmark.py --iterations 5 --csv

# CPU-based attack simulation (no Hashcat required)
python attack_sim/hashcat_runner.py --cpu-sim --duration 15

# With Hashcat (if installed)
python attack_sim/hashcat_runner.py --wordlist /usr/share/wordlists/rockyou.txt
```

---

### Week 6: Optimization + Flask API

```bash
# Find optimal parameters for your machine
python benchmark/optimize_params.py

# Start Flask API (requires local PostgreSQL)
python app.py
# Open: http://localhost:5000

# OR use Docker (recommended for consistency)
# See "Running with Docker" section above.
```

---

## API Endpoints

| Method | Endpoint         | Description                        |
|--------|------------------|------------------------------------|
| POST   | /api/register    | Register user (pick algorithm)     |
| POST   | /api/login       | Authenticate user                  |
| GET    | /api/benchmark   | Run live benchmark                 |
| GET    | /api/users       | List registered users (demo only)  |
| GET    | /api/health      | Health check                       |
| GET    | /                | Demo web UI                        |

### Example: Register
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@test.com","password":"SecurePass@1","algorithm":"argon2id","preset":"medium"}'
```

### Example: Login
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePass@1"}'
```

---

## Argon2id Parameters

| Preset | time_cost | memory_cost | Parallelism | Memory  |
|--------|-----------|-------------|-------------|---------|
| low    | 1         | 65536       | 2           | 64 MB   |
| medium | 2         | 131072      | 2           | 128 MB  |
| high   | 3         | 262144      | 4           | 256 MB  |
| ultra  | 4         | 524288      | 4           | 512 MB  |

## scrypt Parameters

| Preset | N      | r | p | Memory  |
|--------|--------|---|---|---------|
| low    | 16384  | 8 | 1 | ~16 MB  |
| medium | 65536  | 8 | 1 | ~64 MB  |
| high   | 131072 | 8 | 1 | ~128 MB |
| ultra  | 262144 | 8 | 1 | ~256 MB |

---

## Measurable Objectives Checklist

- [ ] 5× increase in attack cost vs bcrypt baseline (measured via Hashcat H/s)
- [ ] Authentication latency < 300ms under normal load
- [ ] Memory configurations from 64 MB to 1 GB evaluated
- [ ] Reduction in GPU cracking throughput demonstrated

---

## Hashcat Modes Reference

| Algorithm | Hashcat Mode |
|-----------|-------------|
| bcrypt    | -m 3200     |
| Argon2id  | -m 35       |
| scrypt    | No native mode — use cpu-sim |

```bash
# Install Hashcat on Ubuntu
sudo apt install hashcat

# Download rockyou wordlist
sudo apt install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```
