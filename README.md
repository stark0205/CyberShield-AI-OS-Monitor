# CyberShield AI

College project: OS monitoring + MySQL + simple AI threat labels + dashboard.

Team Rocket — DBMS / OS course project.

## What it does

1. Reads process events (sample JSON or C monitor on macOS)
2. Stores them in MySQL (`sec_event`)
3. AI labels each event: Normal / Suspicious / High Risk
4. Admin logs in and can investigate + respond

## Folders

```
CyberShield_AI/
├── sql/           MySQL create + seed + demo queries
├── backend/       FastAPI + auth + collector
├── ai/            training CSV + train_model.py
├── os_monitor/    C monitor (macOS) + sample_events.json
├── frontend/      HTML / CSS / JS dashboard
└── docs/          PRD
```

## Setup (macOS)

```bash
# 1. MySQL running
brew services start mysql

# 2. Python venv
cd CyberShield_AI
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# 3. copy env
cp backend/.env.example backend/.env
# Set DB_PASS and generate JWT_SECRET with: openssl rand -hex 32
# Do not commit backend/.env. Use a dedicated least-privilege DB account.

# 4. create DB + admin user
cd backend
python setup_db.py
# Enter a unique 12-72 byte password when prompted.
# For non-interactive setup, set BOOTSTRAP_ADMIN_PASSWORD in the environment.

# 5. train AI model
cd ..
python -m ai.train_model

# 6. run the local development server (reload is disabled by default)
cd backend
uvicorn main:app --port 8000
```

Open: http://127.0.0.1:8000/login

The initial account name is `admin`; setup prompts for its password and never
creates a public default credential. The backend refuses to start until
`JWT_SECRET` contains at least 32 bytes.
For an existing database that may still use the old demo password, set
`RESET_ADMIN_PASSWORD=true` before rerunning setup to reset it interactively.

Database setup also installs the investigation summary view, transactional
stored procedures, and audit triggers used by the API. The DBMS learning
examples are in `sql/03_queries.sql` through `sql/06_dbms_features.sql`.

For production, configure a dedicated MySQL account with only the required
application privileges, restrict `CS_ALLOWED_ORIGINS` to exact trusted origins,
set `CS_ENV=production`, and terminate HTTPS at a trusted proxy or configure TLS
directly on the ASGI server. Configure either `CS_HTTPS_ENFORCED_BY_PROXY=true`
or `CS_FORCE_HTTPS=true`; the production app refuses to start without one. Set
`CS_FORCE_HTTPS=true` only when requests reach the app as HTTPS. Use
`DB_SETUP_USER`/`DB_SETUP_PASS` for privileged schema setup and a separate
`DB_USER`/`DB_PASS` with only runtime permissions. Keep reload disabled. The
built-in rate limiter is process-local; use a shared gateway limiter if running
multiple workers or instances.

Security controls and remaining deployment actions are documented in
[`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).

## Optional: build OS monitor

```bash
cd os_monitor
make
./os_monitor --out events.json --watch watch_dir

# Python second path (same JSON schema)
python py_monitor.py --out events_py.json --watch watch_dir
```

Dashboard **Source** selector: Sample JSON / C live / Python (`psutil`). See `os_monitor/README.md`.

## Optional: train with public endpoint telemetry

The default `ai/events_train.csv` is a reproducible synthetic classroom
dataset, not verified threat ground truth. For instructions on regenerating
it or preparing and evaluating a manually labeled subset of DARPA OpTC
telemetry, see [`ai/README.md`](ai/README.md). The raw public dataset is large
and is not included in this repository.

## Demo checklist

1. Login
2. Click **Collect sample events**
3. See Events + Threats with AI labels
4. Open investigation from Threats
5. Add a response
6. Check Audit log
