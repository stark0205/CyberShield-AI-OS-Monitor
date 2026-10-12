# read OS monitor JSON (or sample file) and insert into MySQL
import json
import subprocess
import sys
from pathlib import Path
from models.db import run_query
from ai.classifier import predict_risk

ROOT = Path(__file__).resolve().parents[2]
OS_DIR = ROOT / "os_monitor"
SAMPLE = OS_DIR / "sample_events.json"
C_EVENTS = OS_DIR / "events.json"
PY_EVENTS = OS_DIR / "events_py.json"
C_BINARY = OS_DIR / "os_monitor"
PY_MONITOR = OS_DIR / "py_monitor.py"

SOURCES = {
    "sample": SAMPLE,
    "c": C_EVENTS,
    "python": PY_EVENTS,
}


def classify_event(proc):
    if proc.get("is_new"):
        return "new_proc"
    if proc.get("cpu_pct", 0) > 80:
        return "high_cpu"
    if proc.get("mem_mb", 0) > 1024:
        return "mem_spike"
    name = (proc.get("name") or "").lower()
    if "unknown" in name or "fake" in name or "miner" in name:
        return "new_proc"
    return "normal"


def read_events(filepath):
    with open(filepath, "r") as f:
        return json.load(f)


def insert_event(did, etype, proc, details=None):
    return run_query(
        """
        INSERT INTO sec_event
            (did, etype, details, pid, ppid, proc_state, cpu_pct, mem_mb, exe_name)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            did,
            etype,
            details or f"Process {proc.get('name')} flagged as {etype}",
            proc.get("pid"),
            proc.get("ppid"),
            proc.get("state"),
            proc.get("cpu_pct"),
            proc.get("mem_mb"),
            proc.get("name"),
        ),
    )


def insert_file_event(did, fevent):
    path = fevent.get("path") or ""
    action = fevent.get("action") or "modified"
    details = f"File {action}: {path}"
    return run_query(
        """
        INSERT INTO sec_event
            (did, etype, details, pid, ppid, proc_state, cpu_pct, mem_mb, exe_name)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            did,
            "file_mod",
            details,
            fevent.get("pid") if fevent.get("pid", -1) >= 0 else None,
            None,
            None,
            0.0,
            0.0,
            Path(path).name if path else None,
        ),
    )


def _run_c_monitor():
    if not C_BINARY.exists():
        return False, "C binary not found — run `make` in os_monitor/"
    try:
        subprocess.run(
            [str(C_BINARY), "--out", str(C_EVENTS), "--watch", str(OS_DIR / "watch_dir")],
            check=True,
            cwd=str(OS_DIR),
            timeout=30,
        )
        return True, None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        return False, str(e)


def _run_py_monitor():
    if not PY_MONITOR.exists():
        return False, "py_monitor.py not found"
    try:
        subprocess.run(
            [
                sys.executable,
                str(PY_MONITOR),
                "--out",
                str(PY_EVENTS),
                "--watch",
                str(OS_DIR / "watch_dir"),
            ],
            check=True,
            cwd=str(OS_DIR),
            timeout=60,
        )
        return True, None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        return False, str(e)


def resolve_source(source="sample", refresh=True):
    """Return path for source; optionally refresh live monitors first."""
    key = (source or "sample").lower()
    if key not in SOURCES:
        return None, f"unknown source '{source}' (use sample|c|python)"

    if key == "c" and refresh:
        ok, err = _run_c_monitor()
        if not ok:
            return None, err
    elif key == "python" and refresh:
        ok, err = _run_py_monitor()
        if not ok:
            return None, err

    return SOURCES[key], None


def collect(filepath=None, did=1, run_ai=True, source="sample", refresh=True):
    if filepath:
        path = Path(filepath)
        err = None
    else:
        path, err = resolve_source(source, refresh=refresh)

    if err:
        return {"ok": False, "error": err, "source": source}
    if not path.exists():
        return {"ok": False, "error": f"file not found: {path}", "source": source}

    data = read_events(path)
    procs = data.get("procs", [])
    file_events = data.get("file_events", [])
    created = []

    for proc in procs:
        etype = classify_event(proc)
        eid = insert_event(did, etype, proc)
        risk, conf = None, None
        if run_ai:
            risk, conf = predict_risk(proc.get("cpu_pct"), proc.get("mem_mb"), etype)
            run_query(
                "INSERT INTO threat (eid, confidence, risk_lvl) VALUES (%s, %s, %s)",
                (eid, conf, risk),
            )
        created.append(
            {
                "eid": eid,
                "etype": etype,
                "risk_lvl": risk,
                "confidence": conf,
                "state": proc.get("state"),
                "ppid": proc.get("ppid"),
            }
        )

    for fe in file_events:
        eid = insert_file_event(did, fe)
        risk, conf = None, None
        if run_ai:
            risk, conf = predict_risk(0, 0, "file_mod")
            run_query(
                "INSERT INTO threat (eid, confidence, risk_lvl) VALUES (%s, %s, %s)",
                (eid, conf, risk),
            )
        created.append(
            {
                "eid": eid,
                "etype": "file_mod",
                "risk_lvl": risk,
                "confidence": conf,
                "path": fe.get("path"),
            }
        )

    return {
        "ok": True,
        "count": len(created),
        "events": created,
        "source": source if not filepath else "file",
        "mem_total_mb": data.get("mem_total_mb"),
        "mem_used_mb": data.get("mem_used_mb"),
    }
