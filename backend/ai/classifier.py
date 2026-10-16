# load model and predict risk for one event
from pathlib import Path
import joblib
import math

# model lives in project ai/ folder
ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "ai" / "threat_model.pkl"
OPTC_MODEL_PATH = ROOT / "ai" / "threat_model_optc.pkl"

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
    if _model is None:
        if OPTC_MODEL_PATH.exists():
            _model = joblib.load(OPTC_MODEL_PATH)
        elif MODEL_PATH.exists():
            _model = joblib.load(MODEL_PATH)
    return _model

def encode_etype(etype: str) -> int:
    return ETYPE_MAP.get((etype or "normal").lower(), 1)


def validate_inference_input(cpu_pct, mem_mb, etype, exe_name=None, ppid=None):
    if not isinstance(etype, str) or etype.lower() not in ETYPE_MAP:
        raise ValueError("unsupported event type for classification")
    for value, field, maximum in (
        (cpu_pct, "cpu_pct", 10_000),
        (mem_mb, "mem_mb", 1_000_000_000),
    ):
        if value is None:
            continue
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= maximum
        ):
            raise ValueError(f"invalid {field} for classification")
    if ppid is not None and (
        isinstance(ppid, bool) or not isinstance(ppid, int) or ppid < 0
    ):
        raise ValueError("invalid ppid for classification")
    if exe_name is not None and (
        not isinstance(exe_name, str) or len(exe_name) > 255
    ):
        raise ValueError("invalid process name for classification")


def predict_risk(
    cpu_pct,
    mem_mb,
    etype,
    hour_of_day=12,
    is_sys_dir=0,
    proc_count=1,
    exe_name=None,
    ppid=None,
):
    """
    returns (risk_lvl, confidence)
    if model missing, use simple rules so demo still works
    """
    validate_inference_input(cpu_pct, mem_mb, etype, exe_name, ppid)
    model = load_model()
    if isinstance(model, dict):
        if model.get("schema_version") != 1:
            raise ValueError("unsupported OpTC model schema version")
        process_name = str(exe_name or "").strip().replace("\\", "/").rstrip("/")
        process_name = process_name.rsplit("/", 1)[-1].lower()
        try:
            has_parent = int(int(ppid) > 0)
        except (TypeError, ValueError):
            has_parent = 0
        features = model["vectorizer"].transform(
            [
                {
                    "event_type": str(etype or "normal").lower(),
                    "process_name": process_name,
                    "has_parent": has_parent,
                }
            ]
        )
        classifier = model["classifier"]
        pred = classifier.predict(features)[0]
        probs = classifier.predict_proba(features)[0]
        return str(pred), round(float(max(probs)), 3)

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
