import os
from datetime import datetime, timedelta
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()

SECRET = os.getenv("JWT_SECRET", "change-this-secret")
ALGO = "HS256"
HOURS = int(os.getenv("JWT_HOURS", "8"))

def make_token(uid: int, uname: str) -> str:
    data = {
        "uid": uid,
        "uname": uname,
        "exp": datetime.utcnow() + timedelta(hours=HOURS),
    }
    return jwt.encode(data, SECRET, algorithm=ALGO)

def read_token(token: str):
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGO])
    except JWTError:
        return None
