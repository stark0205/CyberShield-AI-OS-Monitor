from fastapi import APIRouter, Depends, HTTPException
from models.db import run_query
from models.schemas import RespondIn
from auth.deps import get_user

router = APIRouter(tags=["respond"])

@router.post("/respond")
def add_response(body: RespondIn, user=Depends(get_user)):
    inv = run_query(
        "SELECT inv_id FROM investigation WHERE inv_id=%s",
        (body.inv_id,),
        fetch=True,
        one=True,
    )
    if not inv:
        raise HTTPException(status_code=404, detail="investigation not found")

    raid = run_query(
        "INSERT INTO resp_action (inv_id, action_type, description) VALUES (%s, %s, %s)",
        (body.inv_id, body.action_type, body.description or ""),
    )
    run_query(
        "INSERT INTO audit_log (uid, action, detail) VALUES (%s, %s, %s)",
        (user["uid"], "ADD_RESPONSE", f"raid={raid} type={body.action_type}"),
    )
    return {"ok": True, "raid": raid}
