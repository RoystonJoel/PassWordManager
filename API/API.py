import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from contextlib import asynccontextmanager
import sqlite3
import hashlib
import base64
import uuid
from cryptography.fernet import Fernet, InvalidToken
import pydantic_models as model

DB_FILE = 'database/vault.db'
AUTH_TOKEN_MESSAGE = b"VAULT_AUTH_SUCCESS"


security = HTTPBasic()

# --- Database Setup ---

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@asynccontextmanager
async def lifespan(app: FastAPI):
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT,
                auth_hash TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                owner TEXT,
                item_type TEXT,
                encrypted_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS trash (
                id TEXT PRIMARY KEY,
                owner TEXT,
                item_type TEXT,
                encrypted_data TEXT,
                created_at TEXT,
                updated_at TEXT,
                deleted_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    print("Application is starting up...")
    yield
    # Everything AFTER yield runs on SHUTDOWN
    print("Application is shutting down...")

app = FastAPI(title="Multi-User Vault API", lifespan=lifespan)


# --- Security Functions ---

# Server-side derive_key and Fernet are now ONLY for auth_token verification
def derive_key_for_auth(password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username.strip().lower()

    with get_db() as conn:
        user_row = conn.execute("SELECT auth_hash FROM users WHERE username = ?", (username,)).fetchone()

    if not user_row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Compute a fast SHA-256 hash of the incoming Key B string
    incoming_key_b = credentials.password
    computed_hash = hashlib.sha256(incoming_key_b.encode()).hexdigest()

    # Instant verification, completely eliminating CPU DoS vulnerabilities
    if computed_hash == user_row['auth_hash']:
        return {"username": username}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect password",
        headers={"WWW-Authenticate": "Basic"},
    )


# --- API Endpoints ---

@app.post("/register", status_code=201)
def register_user(user: model.UserCreate):
    username = user.username.strip().lower()

    with get_db() as conn:
        existing_user = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")

        conn.execute(
            "INSERT INTO users (username, salt, auth_hash) VALUES (?, ?, ?)",
            (username, user.salt, user.auth_hash)
        )
        conn.commit()

    return {"message": f"User '{username}' created successfully."}

@app.get("/user/salt/{username}")
def get_user_salt(username: str):
    # This endpoint is now public so clients can obtain the salt needed to derive keys locally
    with get_db() as conn:
        user_row = conn.execute("SELECT salt FROM users WHERE username = ?", (username,)).fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")
        return {"username": username, "salt": user_row["salt"]}


@app.post("/items", response_model=model.ItemResponse, status_code=201)
def add_item(item: model.ItemCreate, auth: dict = Depends(authenticate_user)):
    username = auth["username"]
    enc_data = item.item_data
    item_id = str(uuid.uuid4())
    current_time = datetime.datetime.now().isoformat()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO items (id, owner, item_type, encrypted_data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, username, item.item_type, enc_data, current_time, current_time)
        )
        conn.commit()

    return {
        "id": item_id,
        "item_type": item.item_type,
        "item_data": item.item_data,
        "created_at": datetime.datetime.fromisoformat(current_time),
        "updated_at": datetime.datetime.fromisoformat(current_time)
    }


@app.patch("/items/{item_id}", response_model=model.ItemResponse)
def update_item(item_id: str, item_update: model.ItemUpdate, auth: dict = Depends(authenticate_user)):
    username = auth["username"]

    with get_db() as conn:
        existing_item = conn.execute(
            "SELECT * FROM items WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        if not existing_item:
            raise HTTPException(status_code=404, detail="Item not found or not owned by user")

        update_fields = {}
        if item_update.item_type is not None:
            update_fields["item_type"] = item_update.item_type
        if item_update.item_data is not None:
            update_fields["encrypted_data"] = item_update.item_data

        if not update_fields:
            return {
                "id": existing_item["id"],
                "item_type": existing_item["item_type"],
                "item_data": existing_item["encrypted_data"],
                "created_at": datetime.datetime.fromisoformat(existing_item["created_at"]),
                "updated_at": datetime.datetime.fromisoformat(existing_item["updated_at"])
            }

        update_fields["updated_at"] = datetime.datetime.now().isoformat()

        set_clauses = [f"{k} = ?" for k in update_fields.keys()]
        values = list(update_fields.values())
        values.extend([item_id, username])

        conn.execute(
            f"UPDATE items SET {', '.join(set_clauses)} WHERE id = ? AND owner = ?",
            values
        )
        conn.commit()

        updated_item_row = conn.execute(
            "SELECT * FROM items WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        return {
            "id": updated_item_row["id"],
            "item_type": updated_item_row["item_type"],
            "item_data": updated_item_row["encrypted_data"],
            "created_at": datetime.datetime.fromisoformat(updated_item_row["created_at"]),
            "updated_at": datetime.datetime.fromisoformat(updated_item_row["updated_at"])
        }


@app.get("/items", response_model=list[model.ItemResponse])
def get_vault(auth: dict = Depends(authenticate_user)):
    username = auth["username"]

    with get_db() as conn:
        items = conn.execute(
            "SELECT * FROM items WHERE owner = ? ORDER BY created_at DESC",
            (username,)
        ).fetchall()

    return [{
        "id": item["id"],
        "item_type": item["item_type"],
        "item_data": item["encrypted_data"],
        "created_at": datetime.datetime.fromisoformat(item["created_at"]),
        "updated_at": datetime.datetime.fromisoformat(item["updated_at"])
    } for item in items]

@app.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: str, auth: dict = Depends(authenticate_user)):
    username = auth["username"]

    with get_db() as conn:
        item_to_delete = conn.execute(
            "SELECT id, owner, item_type, encrypted_data, created_at, updated_at FROM items WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        if not item_to_delete:
            raise HTTPException(status_code=404, detail="Item not found or not owned by user")

        conn.execute(
            """
            INSERT INTO trash (id, owner, item_type, encrypted_data, created_at, updated_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_to_delete["id"], item_to_delete["owner"], item_to_delete["item_type"],
                item_to_delete["encrypted_data"], item_to_delete["created_at"],
                item_to_delete["updated_at"], datetime.datetime.now().isoformat()
            )
        )
        conn.execute("DELETE FROM items WHERE id = ? AND owner = ?", (item_id, username))
        conn.commit()

    return {"message": "Item moved to trash successfully"}


@app.post("/cleanup_trash", status_code=200)
def cleanup_trash():
    """
    Permanently deletes items from the trash table that are older than 30 days.
    This endpoint should ideally be called by a scheduled job, not directly by users.
    """
    with get_db() as conn:
        # Calculate the date 30 days ago
        thirty_days_ago = (datetime.datetime.now() - datetime.timedelta(days=30)).isoformat()

        cursor = conn.execute(
            "DELETE FROM trash WHERE deleted_at < ?",
            (thirty_days_ago,)
        )
        conn.commit()

    return {"message": f"Cleaned up {cursor.rowcount} items from trash older than 30 days."}

@app.post("/trash/restore/{item_id}", status_code=200)
def restore_item_from_trash(item_id: str, auth: dict = Depends(authenticate_user)):
    username = auth["username"]

    with get_db() as conn:
        item_to_restore = conn.execute(
            "SELECT id, owner, item_type, encrypted_data, created_at, updated_at FROM trash WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        if not item_to_restore:
            raise HTTPException(status_code=404, detail="Item not found in trash or not owned by user")

        existing_active_item = conn.execute("SELECT id FROM items WHERE id = ?", (item_to_restore["id"],)).fetchone()
        if existing_active_item:
            raise HTTPException(status_code=409, detail="An active item with this ID already exists.")

        conn.execute(
            """
            INSERT INTO items (id, owner, item_type, encrypted_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                item_to_restore["id"], item_to_restore["owner"], item_to_restore["item_type"],
                item_to_restore["encrypted_data"], item_to_restore["created_at"], datetime.datetime.now().isoformat()
            )
        )
        conn.execute("DELETE FROM trash WHERE id = ? AND owner = ?", (item_id, username))
        conn.commit()

    return {"message": f"Item '{item_id}' restored successfully from trash."}


@app.get("/trash/items")
def get_trash_items(auth: dict = Depends(authenticate_user)):
    username = auth["username"]

    with get_db() as conn:
        items = conn.execute(
            "SELECT * FROM trash WHERE owner = ? ORDER BY deleted_at DESC",
            (username,)
        ).fetchall()

    return [{
        "id": item["id"],
        "item_type": item["item_type"],
        "item_data": item["encrypted_data"],
        "created_at": datetime.datetime.fromisoformat(item["created_at"]),
        "updated_at": datetime.datetime.fromisoformat(item["updated_at"]),
        "deleted_at": datetime.datetime.fromisoformat(item["deleted_at"])
    } for item in items]


@app.delete("/trash/permanent_delete/{item_id}", status_code=204)
def permanent_delete_item_from_trash(item_id: str, auth: dict = Depends(authenticate_user)):
    username = auth["username"]

    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM trash WHERE id = ? AND owner = ?",
            (item_id, username)
        )
        conn.commit()

    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found in trash or not owned by user")

    return {"message": "Item permanently deleted from trash successfully"}