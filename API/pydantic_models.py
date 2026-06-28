from pydantic import BaseModel
from typing import Optional
import datetime
# --- Pydantic Models (For API input/output validation) ---

class UserCreate(BaseModel):
    username: str
    master_password: str


class ItemCreate(BaseModel):
    title: str
    folder: str = "uncategorised"
    username: str
    password: str
    totp_secret: Optional[str] = None


class ItemUpdate(BaseModel):
    title: Optional[str] = None
    folder: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    totp_secret: Optional[str] = None


class ItemResponse(BaseModel):
    id: str
    title: str
    folder: str
    username: str
    password: str
    totp_secret: Optional[str] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime