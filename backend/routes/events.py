from fastapi import APIRouter, Depends, HTTPException
from models.db import run_query
from auth.deps import get_user

router = APIRouter(tags=["events"])

# stats route MUST be above /{eid} or FastAPI treats "stats" as an id
@router.get("/events/stats")
def event_stats(user=Depends(get_user)):
    by_type = run_query(
        "SELECT etype, COUNT(*) AS cnt FROM sec_event GROUP BY etype",
        fetch=True,
    )
    total = run_query("SELECT COUNT(*) AS total FROM sec_event", fetch=True, one=True)
    return {"total": total["total"] if total else 0, "by_type": by_type}

@router.get("/events")
def list_events(limit: int = 50, offset: int = 0, user=Depends(get_user)):
    rows = run_query(
        """
        SELECT e.*, t.risk_lvl, t.confidence
        FROM sec_event e
        LEFT JOIN threat t ON e.eid = t.eid
        ORDER BY e.ts DESC
        LIMIT %s OFFSET %s
        """,
        (limit, offset),
        fetch=True,
    )
    return {"events": rows}

@router.get("/events/{eid}")
def one_event(eid: int, user=Depends(get_user)):
    row = run_query(
        """
        SELECT e.*, t.risk_lvl, t.confidence, t.tid
        FROM sec_event e
        LEFT JOIN threat t ON e.eid = t.eid
        WHERE e.eid=%s
        """,
        (eid,),
        fetch=True,
        one=True,
    )
    if not row:
        raise HTTPException(status_code=404, detail="event not found")
    return row
