from fastapi import APIRouter, Depends, HTTPException
from models.db import run_query
from auth.deps import get_user
from ai.classifier import predict_risk

router = APIRouter(tags=["threats"])

@router.get("/threats/summary")
def threat_summary(user=Depends(get_user)):
    rows = run_query(
        "SELECT risk_lvl, COUNT(*) AS cnt FROM threat GROUP BY risk_lvl",
        fetch=True,
    )
    out = {"Normal": 0, "Suspicious": 0, "High Risk": 0, "total": 0}
    for r in rows:
        out[r["risk_lvl"]] = r["cnt"]
        out["total"] += r["cnt"]
    return out

@router.get("/threats")
def list_threats(user=Depends(get_user)):
    rows = run_query(
        """
        SELECT t.*, e.etype, e.exe_name, e.cpu_pct, e.mem_mb, e.ts
        FROM threat t
        JOIN sec_event e ON t.eid = e.eid
        ORDER BY t.detected_at DESC
        """,
        fetch=True,
    )
    return {"threats": rows}

@router.get("/threats/{tid}")
def one_threat(tid: int, user=Depends(get_user)):
    row = run_query(
        """
        SELECT t.*, e.etype, e.exe_name, e.cpu_pct, e.mem_mb, e.details
        FROM threat t
        JOIN sec_event e ON t.eid = e.eid
        WHERE t.tid=%s
        """,
        (tid,),
        fetch=True,
        one=True,
    )
    if not row:
        raise HTTPException(status_code=404, detail="threat not found")
    return row

@router.post("/threats/classify/{eid}")
def classify_one(eid: int, user=Depends(get_user)):
    # run AI on one event and save / update threat row
    ev = run_query(
        "SELECT * FROM sec_event WHERE eid=%s",
        (eid,),
        fetch=True,
        one=True,
    )
    if not ev:
        raise HTTPException(status_code=404, detail="event not found")

    risk, conf = predict_risk(ev["cpu_pct"], ev["mem_mb"], ev["etype"])
    existing = run_query(
        "SELECT tid FROM threat WHERE eid=%s",
        (eid,),
        fetch=True,
        one=True,
    )
    if existing:
        run_query(
            "UPDATE threat SET risk_lvl=%s, confidence=%s WHERE eid=%s",
            (risk, conf, eid),
        )
        tid = existing["tid"]
    else:
        tid = run_query(
            "INSERT INTO threat (eid, confidence, risk_lvl) VALUES (%s, %s, %s)",
            (eid, conf, risk),
        )
    return {"tid": tid, "eid": eid, "risk_lvl": risk, "confidence": conf}
