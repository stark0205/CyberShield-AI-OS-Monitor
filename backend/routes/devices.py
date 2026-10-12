from fastapi import APIRouter, Depends
from models.db import run_query
from models.schemas import DeviceIn
from auth.deps import get_user

router = APIRouter(tags=["devices"])

@router.get("/devices")
def list_devices(user=Depends(get_user)):
    rows = run_query("SELECT * FROM device ORDER BY reg_at DESC", fetch=True)
    return {"devices": rows}

@router.post("/devices")
def add_device(body: DeviceIn, user=Depends(get_user)):
    did = run_query(
        "INSERT INTO device (uid, dname, os_type, ip_addr) VALUES (%s, %s, %s, %s)",
        (user["uid"], body.dname, body.os_type, body.ip_addr),
    )
    run_query(
        "INSERT INTO audit_log (uid, action, detail) VALUES (%s, %s, %s)",
        (user["uid"], "ADD_DEVICE", f"did={did} name={body.dname}"),
    )
    return {"ok": True, "did": did}
