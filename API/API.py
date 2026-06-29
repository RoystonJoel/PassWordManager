import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from contextlib import asynccontextmanager

import sqlite3
import os
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
    # Everything BEFORE yield runs on STARTUP
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
                password TEXT,
                totp_secret TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    print("Application is starting up...")
    yield
    # Everything AFTER yield runs on SHUTDOWN
    print("Application is shutting down...")

app = FastAPI(title="Multi-User Vault API", lifespan=lifespan)


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
def register_user(user: model.UserCreate):
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


@app.post("/items", response_model=model.ItemResponse)
def add_item(item: model.ItemCreate, auth: dict = Depends(authenticate_user)):
    username = auth["username"]
    cipher = auth["cipher"]

    enc_username = cipher.encrypt(item.username.encode()).decode()
    enc_password = cipher.encrypt(item.password.encode()).decode()
    enc_totp_secret = cipher.encrypt(item.totp_secret.encode()).decode() if item.totp_secret else None
    item_id = str(uuid.uuid4())
    current_time = datetime.datetime.now().isoformat()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO items (id, owner, title, folder, username, password, totp_secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, username, item.title, item.folder, enc_username, enc_password, enc_totp_secret, current_time, current_time)
        )
        conn.commit()

    return {
        "id": item_id,
        "title": item.title,
        "folder": item.folder,
        "username": item.username,
        "password": item.password,
        "totp_secret": item.totp_secret,
        "created_at": datetime.datetime.fromisoformat(current_time),
        "updated_at": datetime.datetime.fromisoformat(current_time)
    }


@app.patch("/items/{item_id}", response_model=model.ItemResponse)
def update_item(item_id: str, item_update: model.ItemUpdate, auth: dict = Depends(authenticate_user)):
    username = auth["username"]
    cipher = auth["cipher"]

    with get_db() as conn:
        existing_item = conn.execute(
            "SELECT * FROM items WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        if not existing_item:
            raise HTTPException(status_code=404, detail="Item not found or not owned by user")

        update_fields = {}
        if item_update.title is not None:
            update_fields["title"] = item_update.title
        if item_update.folder is not None:
            update_fields["folder"] = item_update.folder
        if item_update.username is not None:
            update_fields["username"] = cipher.encrypt(item_update.username.encode()).decode()
        if item_update.password is not None:
            update_fields["password"] = cipher.encrypt(item_update.password.encode()).decode()
        if item_update.totp_secret is not None:
            update_fields["totp_secret"] = cipher.encrypt(item_update.totp_secret.encode()).decode()
        elif "totp_secret" in item_update.dict(exclude_unset=True) and item_update.totp_secret is None:
            # Allow setting totp_secret to None to clear it
            update_fields["totp_secret"] = None


        if not update_fields:
            return {
                "id": existing_item["id"],
                "title": existing_item["title"],
                "folder": existing_item["folder"],
                "username": cipher.decrypt(existing_item["username"].encode()).decode(),
                "password": cipher.decrypt(existing_item["password"].encode()).decode(),
                "totp_secret": cipher.decrypt(existing_item["totp_secret"].encode()).decode() if existing_item["totp_secret"] else None,
                "created_at": datetime.datetime.fromisoformat(existing_item["created_at"]),
                "updated_at": datetime.datetime.fromisoformat(existing_item["updated_at"])
            }

        update_fields["updated_at"] = datetime.datetime.now().isoformat()

        set_clauses = [f"{k} = ?" for k in update_fields.keys()]
        values = list(update_fields.values())
        values.append(item_id)
        values.append(username)

        conn.execute(
            f"UPDATE items SET {', '.join(set_clauses)} WHERE id = ? AND owner = ?",
            values
        )
        conn.commit()

        # Fetch the updated item to return
        updated_item_row = conn.execute(
            "SELECT * FROM items WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        return {
            "id": updated_item_row["id"],
            "title": updated_item_row["title"],
            "folder": updated_item_row["folder"],
            "username": cipher.decrypt(updated_item_row["username"].encode()).decode(),
            "password": cipher.decrypt(updated_item_row["password"].encode()).decode(),
            "totp_secret": cipher.decrypt(updated_item_row["totp_secret"].encode()).decode() if updated_item_row["totp_secret"] else None,
            "created_at": datetime.datetime.fromisoformat(updated_item_row["created_at"]),
            "updated_at": datetime.datetime.fromisoformat(updated_item_row["updated_at"])
        }


@app.get("/items", response_model=list[model.ItemResponse])
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
            "password": cipher.decrypt(item["password"].encode()).decode(),
            "totp_secret": cipher.decrypt(item["totp_secret"].encode()).decode() if item["totp_secret"] else None,
            "created_at": datetime.datetime.fromisoformat(item["created_at"]),
            "updated_at": datetime.datetime.fromisoformat(item["updated_at"])
        })

    return results


@app.get("/search", response_model=list[model.ItemResponse])
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
            "password": cipher.decrypt(item["password"].encode()).decode(),
            "totp_secret": cipher.decrypt(item["totp_secret"].encode()).decode() if item["totp_secret"] else None,
            "created_at": datetime.datetime.fromisoformat(item["created_at"]),
            "updated_at": datetime.datetime.fromisoformat(item["updated_at"])
        })

    return results


@app.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: str, auth: dict = Depends(authenticate_user)):
    username = auth["username"]

    with get_db() as conn:
        # First, retrieve the item to be "deleted"
        item_to_delete = conn.execute(
            "SELECT id, owner, title, folder, username, password, totp_secret, created_at, updated_at FROM items WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        if not item_to_delete:
            raise HTTPException(status_code=404, detail="Item not found or not owned by user")

        # Insert the item into the trash table
        conn.execute(
            """
            INSERT INTO trash (id, owner, title, folder, username, password, totp_secret, created_at, updated_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_to_delete["id"],
                item_to_delete["owner"],
                item_to_delete["title"],
                item_to_delete["folder"],
                item_to_delete["username"],
                item_to_delete["password"],
                item_to_delete["totp_secret"],
                item_to_delete["created_at"],
                item_to_delete["updated_at"],
                datetime.datetime.now().isoformat() # Add the deleted_at timestamp
            )
        )

        # Now, delete the item from the active items table
        conn.execute(
            "DELETE FROM items WHERE id = ? AND owner = ?",
            (item_id, username)
        )
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
        # Retrieve the item from the trash table
        item_to_restore = conn.execute(
            "SELECT id, owner, title, folder, username, password, totp_secret, created_at, updated_at FROM trash WHERE id = ? AND owner = ?",
            (item_id, username)
        ).fetchone()

        if not item_to_restore:
            raise HTTPException(status_code=404, detail="Item not found in trash or not owned by user")

        # Check if an item with the same ID already exists in the active items table
        # This is to prevent primary key conflicts if an item with the same ID was recreated
        existing_active_item = conn.execute(
            "SELECT id FROM items WHERE id = ?", (item_to_restore["id"],)
        ).fetchone()

        if existing_active_item:
            raise HTTPException(status_code=409, detail=f"An active item with ID '{item_to_restore['id']}' already exists. Cannot restore.")

        # Insert the item back into the active items table
        conn.execute(
            """
            INSERT INTO items (id, owner, title, folder, username, password, totp_secret, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_to_restore["id"],
                item_to_restore["owner"],
                item_to_restore["title"],
                item_to_restore["folder"],
                item_to_restore["username"],
                item_to_restore["password"],
                item_to_restore["totp_secret"],
                item_to_restore["created_at"],
                datetime.datetime.now().isoformat(), # Update updated_at to current time
            )
        )

        # Delete the item from the trash table
        conn.execute(
            "DELETE FROM trash WHERE id = ? AND owner = ?",
            (item_id, username)
        )
        conn.commit()

    return {"message": f"Item '{item_id}' restored successfully from trash."}


@app.get("/trash/items", response_model=list[model.ItemResponse])
def get_trash_items(auth: dict = Depends(authenticate_user)):
    username = auth["username"]
    cipher = auth["cipher"]

    with get_db() as conn:
        items = conn.execute(
            "SELECT id, owner, title, folder, username, password, totp_secret, created_at, updated_at, deleted_at FROM trash WHERE owner = ? ORDER BY deleted_at DESC",
            (username,)
        ).fetchall()

    results = []
    for item in items:
        results.append({
            "id": item["id"],
            "title": item["title"],
            "folder": item["folder"],
            "username": cipher.decrypt(item["username"].encode()).decode(),
            "password": cipher.decrypt(item["password"].encode()).decode(),
            "totp_secret": cipher.decrypt(item["totp_secret"].encode()).decode() if item["totp_secret"] else None,
            "created_at": datetime.datetime.fromisoformat(item["created_at"]),
            "updated_at": datetime.datetime.fromisoformat(item["updated_at"]),
            "deleted_at": datetime.datetime.fromisoformat(item["deleted_at"]) # Include deleted_at for trash items
        })

    return results


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