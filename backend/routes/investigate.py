from fastapi import APIRouter, Depends, HTTPException
from models.db import run_query
from models.schemas import InvestigateIn, InvestigateUp
from auth.deps import get_user

router = APIRouter(tags=["investigate"])

@router.get("/investigations")
def list_inv(user=Depends(get_user)):
    rows = run_query(
        """
        SELECT i.*, t.risk_lvl, e.exe_name
        FROM investigation i
        JOIN threat t ON i.tid = t.tid
        JOIN sec_event e ON t.eid = e.eid
        ORDER BY i.started_at DESC
        """,
        fetch=True,
    )
    return {"investigations": rows}

@router.post("/investigate")
def open_inv(body: InvestigateIn, user=Depends(get_user)):
    thr = run_query(
        "SELECT tid FROM threat WHERE tid=%s",
        (body.tid,),
        fetch=True,
        one=True,
    )
    if not thr:
        raise HTTPException(status_code=404, detail="threat not found")

    inv_id = run_query(
        "INSERT INTO investigation (tid, uid, status, notes) VALUES (%s, %s, 'Open', %s)",
        (body.tid, user["uid"], body.notes or ""),
    )
    run_query(
        "INSERT INTO audit_log (uid, action, detail) VALUES (%s, %s, %s)",
        (user["uid"], "OPEN_INVESTIGATION", f"inv_id={inv_id} tid={body.tid}"),
    )
    return {"ok": True, "inv_id": inv_id}

@router.put("/investigate/{inv_id}")
def update_inv(inv_id: int, body: InvestigateUp, user=Depends(get_user)):
    row = run_query(
        "SELECT inv_id FROM investigation WHERE inv_id=%s",
        (inv_id,),
        fetch=True,
        one=True,
    )
    if not row:
        raise HTTPException(status_code=404, detail="investigation not found")

    if body.status:
        if body.status == "Closed":
            run_query(
                "UPDATE investigation SET status=%s, closed_at=NOW() WHERE inv_id=%s",
                (body.status, inv_id),
            )
        else:
            run_query(
                "UPDATE investigation SET status=%s WHERE inv_id=%s",
                (body.status, inv_id),
            )
    if body.notes is not None:
        run_query(
            "UPDATE investigation SET notes=%s WHERE inv_id=%s",
            (body.notes, inv_id),
        )

    run_query(
        "INSERT INTO audit_log (uid, action, detail) VALUES (%s, %s, %s)",
        (user["uid"], "UPDATE_INVESTIGATION", f"inv_id={inv_id}"),
    )
    return {"ok": True}
