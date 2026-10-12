# CyberShield AI OS Monitor

An educational security operations console that collects operating-system activity, labels event risk, and helps an administrator investigate and record responses.

## Problem statement

Process and file activity can produce a large volume of low-level events that are difficult to review manually. This project demonstrates a small end-to-end monitoring workflow: collect operating-system events, store them centrally, assign a risk label, and provide a console for reviewing alerts and tracking investigations.

## Team

- **Pallavi Semwal** — Team Lead
- **Sarthak Tyagi** — Team Member
- **Neeraj Rathour** — Team Member
- **Ayush Bhardwaj** — Team Member

## Technology stack

- **Operating-system monitoring:** C on macOS, with a Python/psutil collection path
- **Backend:** Python, FastAPI, Uvicorn
- **Database:** MySQL
- **Risk classification:** Python, pandas, scikit-learn, joblib (Random Forest)
- **Frontend:** HTML, CSS, JavaScript

## Tools used

- macOS
- Python virtual environments and pip
- MySQL
- `make` and a C compiler for the native monitor
- Git and GitHub
- Visual Studio Code

## Major features

- Collects sample events or live process and file activity through the C and Python monitor paths.
- Records process, memory, CPU, and watched-directory file-event data in a common JSON format.
- Stores collected events in MySQL through the FastAPI backend.
- Classifies events as **Normal**, **Suspicious**, or **High Risk**.
- Provides dashboard views for events, threats, investigations, and audit history.
- Supports opening investigations, recording responses, and closing cases.
- Demonstrates OS concepts including process management, resource monitoring, file I/O, threads, mutexes, and signal-based shutdown.

## Project setup

### Requirements

- macOS
- Python 3
- MySQL
- A C compiler and `make` (for the native OS monitor)

### Install and configure

```bash
# Start MySQL
brew services start mysql

# Create and activate a virtual environment from the project root
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# Configure the database connection
cp backend/.env.example backend/.env
# Edit backend/.env for your local MySQL credentials

# Create the database and demo administrator
cd backend
python setup_db.py

# Train the event risk model
cd ../ai
python train_model.py

# Start the web application
cd ../backend
uvicorn main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/login` in a browser. The local demo credentials documented by the project are `admin` / `admin123`; change or disable demo credentials before using this project outside a local classroom demonstration.

### Optional: build the native monitor

```bash
cd os_monitor
make
./os_monitor --out events.json --watch watch_dir
```

The dashboard also supports sample JSON and the Python/psutil collector. The project is a course demonstration, not a production endpoint security product.
