from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import sqlite3
import os
import hashlib
import base64
import uuid
from cryptography.fernet import Fernet, InvalidToken

DB_FILE = '../database/vault.db'
AUTH_TOKEN_MESSAGE = b"VAULT_AUTH_SUCCESS"

app = FastAPI(title="Multi-User Vault API")
security = HTTPBasic()


# --- Pydantic Models (For API input/output validation) ---

class UserCreate(BaseModel):
    username: str
    master_password: str


class ItemCreate(BaseModel):
    title: str
    folder: str = "Uncategorized"
    username: str
    password: str


class ItemResponse(BaseModel):
    id: str
    title: str
    folder: str
    username: str
    password: str


# --- Database Setup ---

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


@app.on_event("startup")
def setup_database():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT,
                auth_token TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                owner TEXT,
                title TEXT,
                folder TEXT,
                username TEXT,
                password TEXT
            )
        ''')


# --- Security Functions ---

def derive_key(password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)


def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    """
    This runs on every protected API call.
    It checks the database, derives the key, and returns the cipher if successful.
    """
    username = credentials.username.strip().lower()

    with get_db() as conn:
        user_row = conn.execute("SELECT salt, auth_token FROM users WHERE username = ?", (username,)).fetchone()

    if not user_row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    salt = base64.b64decode(user_row['salt'].encode())
    auth_token = user_row['auth_token'].encode()

    key = derive_key(credentials.password, salt)
    f = Fernet(key)

    try:
        if f.decrypt(auth_token) == AUTH_TOKEN_MESSAGE:
            # Authentication successful! Return the username and the tool to decrypt their items
            return {"username": username, "cipher": f}
    except InvalidToken:
        pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect password",
        headers={"WWW-Authenticate": "Basic"},
    )


# --- API Endpoints ---

@app.post("/register", status_code=201)
def register_user(user: UserCreate):
    username = user.username.strip().lower()

    with get_db() as conn:
        existing_user = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")

    salt = os.urandom(16)
    key = derive_key(user.master_password, salt)
    f = Fernet(key)
    auth_token = f.encrypt(AUTH_TOKEN_MESSAGE)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, salt, auth_token) VALUES (?, ?, ?)",
            (username, base64.b64encode(salt).decode(), auth_token.decode())
        )
        conn.commit()

    return {"message": f"User '{username}' created successfully."}


@app.post("/items", response_model=ItemResponse)
def add_item(item: ItemCreate, auth: dict = Depends(authenticate_user)):
    username = auth["username"]
    cipher = auth["cipher"]

    enc_username = cipher.encrypt(item.username.encode()).decode()
    enc_password = cipher.encrypt(item.password.encode()).decode()
    item_id = str(uuid.uuid4())

    with get_db() as conn:
        conn.execute(
            "INSERT INTO items (id, owner, title, folder, username, password) VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, username, item.title, item.folder, enc_username, enc_password)
        )
        conn.commit()

    return {
        "id": item_id,
        "title": item.title,
        "folder": item.folder,
        "username": item.username,
        "password": item.password
    }


@app.get("/items", response_model=list[ItemResponse])
def get_vault(auth: dict = Depends(authenticate_user)):
    username = auth["username"]
    cipher = auth["cipher"]

    with get_db() as conn:
        items = conn.execute(
            "SELECT * FROM items WHERE owner = ? ORDER BY folder, title",
            (username,)
        ).fetchall()

    results = []
    for item in items:
        results.append({
            "id": item["id"],
            "title": item["title"],
            "folder": item["folder"],
            "username": cipher.decrypt(item["username"].encode()).decode(),
            "password": cipher.decrypt(item["password"].encode()).decode()
        })

    return results


@app.get("/search", response_model=list[ItemResponse])
def search_vault(query: str, auth: dict = Depends(authenticate_user)):
    username = auth["username"]
    cipher = auth["cipher"]

    with get_db() as conn:
        items = conn.execute(
            "SELECT * FROM items WHERE owner = ? AND title LIKE ?",
            (username, f'%{query}%')
        ).fetchall()

    results = []
    for item in items:
        results.append({
            "id": item["id"],
            "title": item["title"],
            "folder": item["folder"],
            "username": cipher.decrypt(item["username"].encode()).decode(),
            "password": cipher.decrypt(item["password"].encode()).decode()
        })

    return results