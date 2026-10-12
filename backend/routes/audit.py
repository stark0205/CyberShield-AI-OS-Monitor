from fastapi import APIRouter, Depends
from models.db import run_query
from auth.deps import get_user

router = APIRouter(tags=["audit"])

@router.get("/audit")
def list_audit(limit: int = 100, user=Depends(get_user)):
    rows = run_query(
        """
        SELECT a.*, u.uname
        FROM audit_log a
        LEFT JOIN usr u ON a.uid = u.uid
        ORDER BY a.ts DESC
        LIMIT %s
        """,
        (limit,),
        fetch=True,
    )
    return {"audit": rows}
