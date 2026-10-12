# load model and predict risk for one event
import os
from pathlib import Path
import joblib

# model lives in project ai/ folder
ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "ai" / "threat_model.pkl"

_model = None

ETYPE_MAP = {
    "normal": 0,
    "new_proc": 1,
    "file_mod": 2,
    "mem_spike": 3,
    "high_cpu": 4,
}

def load_model():
    global _model
    if _model is None and MODEL_PATH.exists():
        _model = joblib.load(MODEL_PATH)
    return _model

def encode_etype(etype: str) -> int:
    return ETYPE_MAP.get((etype or "normal").lower(), 1)

def predict_risk(cpu_pct, mem_mb, etype, hour_of_day=12, is_sys_dir=0, proc_count=1):
    """
    returns (risk_lvl, confidence)
    if model missing, use simple rules so demo still works
    """
    model = load_model()
    features = [[
        float(cpu_pct or 0),
        float(mem_mb or 0),
        encode_etype(etype),
        int(hour_of_day),
        int(is_sys_dir),
        int(proc_count),
    ]]

    if model is not None:
        pred = model.predict(features)[0]
        conf = 0.75
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(features)[0]
            conf = float(max(probs))
        return str(pred), round(conf, 3)

    # simple fallback rules (no model yet)
    cpu = float(cpu_pct or 0)
    mem = float(mem_mb or 0)
    et = (etype or "").lower()
    if cpu > 80 or et == "high_cpu":
        return "High Risk", 0.85
    if mem > 1500 or et in ("mem_spike", "new_proc", "file_mod"):
        return "Suspicious", 0.7
    return "Normal", 0.9
