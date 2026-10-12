# simple request / response shapes
from pydantic import BaseModel
from typing import Optional

class LoginIn(BaseModel):
    uname: str
    password: str

class InvestigateIn(BaseModel):
    tid: int
    notes: Optional[str] = ""

class InvestigateUp(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None

class RespondIn(BaseModel):
    inv_id: int
    action_type: str
    description: Optional[str] = ""

class DeviceIn(BaseModel):
    dname: str
    os_type: str
    ip_addr: Optional[str] = None
