from fastapi import APIRouter, Depends, Query
from auth.deps import get_user
from collector.collector import collect
from models.db import run_query

router = APIRouter(tags=["collect"])

@router.post("/collect")
def collect_now(
    source: str = Query("sample", description="sample | c | python"),
    refresh: bool = Query(True, description="re-run live monitor before ingest"),
    user=Depends(get_user),
):
    # use first device, or create one
    dev = run_query("SELECT did FROM device LIMIT 1", fetch=True, one=True)
    if not dev:
        did = run_query(
            "INSERT INTO device (uid, dname, os_type, ip_addr) VALUES (%s, %s, %s, %s)",
            (user["uid"], "demo-mac", "macOS", "127.0.0.1"),
        )
    else:
        did = dev["did"]

    result = collect(did=did, run_ai=True, source=source, refresh=refresh)
    run_query(
        "INSERT INTO audit_log (uid, action, detail) VALUES (%s, %s, %s)",
        (
            user["uid"],
            "COLLECT",
            f"source={source} count={result.get('count', 0)} ok={result.get('ok')}",
        ),
    )
    return result
