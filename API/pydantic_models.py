from pydantic import BaseModel, Field
from typing import Optional
import datetime

# --- Specific Item Data Structures (For reference and future client validation) ---

class LoginData(BaseModel):
    username: str
    password: str
    totp_secret: Optional[str] = None

class CreditCardData(BaseModel):
    card_number: str
    cardholder_name: str
    expiration_date: str
    cvv: str

class SecureNoteData(BaseModel):
    note: str

class SSHKeyData(BaseModel):
    public_key: Optional[str] = None
    private_key: str
    passphrase: Optional[str] = None

class IdentityData(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: Optional[str] = None
    address: Optional[str] = None

# --- Main API Models ---

class UserCreate(BaseModel):
    username: str
    salt: str # Client will generate and send this
    auth_token: str # Client will encrypt AUTH_TOKEN_MESSAGE and send this

class ItemCreate(BaseModel):
    title: str
    folder: str = "uncategorised"
    item_type: str = Field(..., description="E.g., 'login', 'card', 'note', 'identity', 'ssh_key'")
    item_data: str  # This will now be the encrypted JSON string

class ItemUpdate(BaseModel):
    title: Optional[str] = None
    folder: Optional[str] = None
    item_type: Optional[str] = None
    item_data: Optional[str] = None # This will now be the encrypted JSON string

class ItemResponse(BaseModel):
    id: str
    title: str
    folder: str
    item_type: str
    item_data: str # This will now be the encrypted JSON string
    created_at: datetime.datetime
    updated_at: datetime.datetime