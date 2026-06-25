import sqlite3
import os
import getpass
import hashlib
import base64
import uuid
from cryptography.fernet import Fernet, InvalidToken

DB_FILE = 'database/multi_vault.db'
AUTH_TOKEN_MESSAGE = b"VAULT_AUTH_SUCCESS"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def setup_database():
    """Creates the necessary tables for multiple users if they don't exist yet."""
    with get_db() as conn:
        # Table to store different users and their login security data
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT,
                auth_token TEXT
            )
        ''')

        # Table to store items, now with an 'owner' column to keep them separate
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


def derive_key(password: str, salt: bytes) -> bytes:
    """Turns the master password into a strong key."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)


def create_user():
    """Registers a new user in the database."""
    print("\n--- Create New User ---")
    username = input("Enter a new username: ").strip().lower()

    with get_db() as conn:
        existing_user = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            print("[-] That username already exists. Please try logging in.")
            return

    master_pw = getpass.getpass("Create a Master Password: ")
    confirm_pw = getpass.getpass("Confirm Master Password: ")

    if master_pw != confirm_pw:
        print("[-] Passwords do not match.")
        return

    salt = os.urandom(16)
    key = derive_key(master_pw, salt)
    f = Fernet(key)

    auth_token = f.encrypt(AUTH_TOKEN_MESSAGE)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, salt, auth_token) VALUES (?, ?, ?)",
            (username, base64.b64encode(salt).decode(), auth_token.decode())
        )
        conn.commit()

    print(f"\n[+] User '{username}' created successfully! You can now log in.")


def login_user():
    """Attempts to log a user in and returns their specific decryption key."""
    print("\n--- User Login ---")
    username = input("Username: ").strip().lower()

    with get_db() as conn:
        user_row = conn.execute("SELECT salt, auth_token FROM users WHERE username = ?", (username,)).fetchone()

    if not user_row:
        print("[-] User not found.")
        return None, None

    attempts = 3
    while attempts > 0:
        password = getpass.getpass(f"Master Password ({attempts} attempts left): ")

        salt = base64.b64decode(user_row['salt'].encode())
        auth_token = user_row['auth_token'].encode()

        key = derive_key(password, salt)
        f = Fernet(key)

        try:
            # Try to decrypt the validation message
            if f.decrypt(auth_token) == AUTH_TOKEN_MESSAGE:
                print(f"\n[+] Welcome back, {username}!")
                return username, f
        except InvalidToken:
            pass  # Decryption failed, wrong password

        print("[-] Incorrect password.")
        attempts -= 1

    print("\n[-] Access denied.")
    return None, None


def display_folders(current_user: str, cipher: Fernet):
    """Shows only the items belonging to the current user."""
    with get_db() as conn:
        items = conn.execute(
            "SELECT id, title, folder, username FROM items WHERE owner = ? ORDER BY folder, title",
            (current_user,)
        ).fetchall()

    if not items:
        print("\n[-] Your vault is empty.")
        return

    folders = {}
    for item in items:
        folder = item["folder"]
        if folder not in folders:
            folders[folder] = []
        folders[folder].append(item)

    print("\n--- Your Vault Contents ---")
    for folder, folder_items in folders.items():
        print(f"\n📁 {folder}:")
        for idx, item in enumerate(folder_items, 1):
            decrypted_user = cipher.decrypt(item['username'].encode()).decode()
            print(f"   {idx}. {item['title']} (Username: {decrypted_user}) - ID: {item['id'][:8]}")
    print("---------------------------")


def add_item(current_user: str, cipher: Fernet):
    print("\n--- Add New Item ---")
    title = input("Title (e.g., Gmail): ")
    folder = input("Folder (e.g., Personal, Work): ")
    username = input("Username/Email: ")
    password = input("Password: ")

    folder = folder if folder else "Uncategorized"

    enc_username = cipher.encrypt(username.encode()).decode()
    enc_password = cipher.encrypt(password.encode()).decode()
    item_id = str(uuid.uuid4())

    with get_db() as conn:
        # Note the 'current_user' is saved in the 'owner' column
        conn.execute(
            "INSERT INTO items (id, owner, title, folder, username, password) VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, current_user, title, folder, enc_username, enc_password)
        )
        conn.commit()

    print(f"\n[+] '{title}' added to your vault.")


def search_vault(current_user: str, cipher: Fernet):
    print("\n--- Search Vault ---")
    query = input("Enter title search term: ")

    with get_db() as conn:
        # Only search items owned by the current user
        results = conn.execute(
            "SELECT * FROM items WHERE owner = ? AND title LIKE ?",
            (current_user, f'%{query}%')
        ).fetchall()

    if not results:
        print("\n[-] No matches found.")
    else:
        print(f"\nFound {len(results)} match(es):")
        for item in results:
            dec_username = cipher.decrypt(item['username'].encode()).decode()
            dec_password = cipher.decrypt(item['password'].encode()).decode()

            print(f"\nTitle: {item['title']}")
            print(f"Folder: {item['folder']}")
            print(f"Username: {dec_username}")
            print(f"Password: {dec_password}")


def vault_menu(current_user: str, cipher: Fernet):
    """The menu shown after a successful login."""
    while True:
        print(f"\n--- {current_user}'s Vault ---")
        print("1. View Vault")
        print("2. Search Vault")
        print("3. Add New Item")
        print("4. Log Out")

        choice = input("\nSelect an option (1-4): ")

        if choice == '1':
            display_folders(current_user, cipher)
        elif choice == '2':
            search_vault(current_user, cipher)
        elif choice == '3':
            add_item(current_user, cipher)
        elif choice == '4':
            print("\nLogging out and locking vault.")
            break
        else:
            print("\n[-] Invalid choice.")
