from fastapi import APIRouter, Depends, HTTPException
from models.db import run_query
from models.schemas import LoginIn
from auth.hashing import check_pwd
from auth.token import make_token
from auth.deps import get_user

router = APIRouter(tags=["auth"])

@router.post("/login")
def login(body: LoginIn):
    row = run_query(
        "SELECT uid, uname, pwd_hash FROM usr WHERE uname=%s",
        (body.uname,),
        fetch=True,
        one=True,
    )
    if not row or not check_pwd(body.password, row["pwd_hash"]):
        raise HTTPException(status_code=401, detail="wrong username or password")

    token = make_token(row["uid"], row["uname"])
    return {"ok": True, "token": token, "uid": row["uid"], "uname": row["uname"]}

@router.post("/logout")
def logout(user=Depends(get_user)):
    # JWT: frontend just deletes the token
    return {"ok": True, "msg": "delete token on client"}
