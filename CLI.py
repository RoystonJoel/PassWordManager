import requests
import getpass
import sys
import os
import datetime
import pyotp
import hashlib
import base64
import json
from cryptography.fernet import Fernet, InvalidToken

#BASE_URL = "http://localhost:8000"
BASE_URL = "http://127.0.0.1:8000"
AUTH_TOKEN_MESSAGE = b"VAULT_AUTH_SUCCESS"

# --- Client-side Encryption Utilities ---
def derive_key(password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def check_server():
    """Ensure the API server is reachable before starting."""
    try:
        requests.get(f"{BASE_URL}/docs", timeout=2)
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please make sure 'uvicorn api_vault:app' is running in another terminal.")
        sys.exit(1)


def register_user():
    print("\n--- Create New User ---")
    username = input("Enter a new username: ").strip().lower()
    master_pw = getpass.getpass("Create a Master Password: ")
    confirm_pw = getpass.getpass("Confirm Master Password: ")

    if master_pw != confirm_pw:
        print("[-] Passwords do not match.")
        return

    # Client-side key derivation and auth_token encryption
    salt = os.urandom(16)
    key = derive_key(master_pw, salt)
    f = Fernet(key)
    auth_token = f.encrypt(AUTH_TOKEN_MESSAGE)

    payload = {
        "username": username,
        "salt": base64.b64encode(salt).decode(),
        "auth_token": auth_token.decode()
    }

    try:
        response = requests.post(f"{BASE_URL}/register", json=payload)

        if response.status_code == 201:
            print(f"\n[+] User '{username}' created successfully! You can now log in.")
        else:
            error_detail = response.json().get("detail", "Unknown error")
            print(f"\n[-] Registration failed: {error_detail}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")


def login_user():
    """
    Authenticates the user and retrieves their salt to create a client-side cipher.
    The auth_tuple will now include the cipher instance.
    """
    print("\n--- User Login ---")
    username = input("Username: ").strip().lower()

    attempts = 3
    while attempts > 0:
        password = getpass.getpass(f"Master Password ({attempts} attempts left): ")
        auth_header = (username, password)

        try:
            # First, attempt to get the user's salt using basic auth
            salt_response = requests.get(f"{BASE_URL}/user/salt/{username}", auth=auth_header)

            if salt_response.status_code == 200:
                user_salt_b64 = salt_response.json()["salt"]
                user_salt = base64.b64decode(user_salt_b64.encode())
                key = derive_key(password, user_salt)
                cipher = Fernet(key)

                # Now, verify the master password by trying to fetch items
                # This implicitly uses the basic auth header (username, password)
                # and the server's authenticate_user will verify the auth_token
                # using the provided password and stored salt.
                test_auth_response = requests.get(f"{BASE_URL}/items", auth=auth_header)

                if test_auth_response.status_code == 200:
                    print(f"\n[+] Welcome back, {username}!")
                    return (username, password, cipher) # auth_tuple now includes the cipher
                elif test_auth_response.status_code == 401:
                    print("[-] Incorrect password or user not found.")
                    attempts -= 1
                else:
                    print(f"[-] Server error during authentication: {test_auth_response.status_code}")
                    return None

            elif salt_response.status_code == 401:
                print("[-] Incorrect password or user not found.")
                attempts -= 1
            elif salt_response.status_code == 404:
                print("[-] User not found.")
                attempts -= 1
            else:
                print(f"[-] Server error while fetching salt: {salt_response.status_code}")
                return None
        except requests.exceptions.ConnectionError:
            print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
            print("    Please ensure the server is running.")
            return None

    print("\n[-] Access denied.")
    return None


def display_folders(auth_tuple: tuple):
    username, password, cipher = auth_tuple
    auth_header = (username, password)
    try:
        response = requests.get(f"{BASE_URL}/items", auth=auth_header)

        if response.status_code != 200:
            print("[-] Failed to fetch vault.")
            return None

        items = response.json()

        if not items:
            print("\n[-] Your vault is empty.")
            return None

        folders = {}
        item_list = []
        count = 1
        for item in items:
            try:
                # Decrypt item_data first (Metadata is hidden inside the ciphertext string)
                decrypted_data_str = cipher.decrypt(item["item_data"].encode()).decode()
                item_data_dict = json.loads(decrypted_data_str)
                item["item_data"] = item_data_dict # Replace encrypted string with decrypted dict

                # Extract title and folder from the decrypted internal fields
                title = item_data_dict.get("title", "Untitled")
                folder = item_data_dict.get("folder", "uncategorised")

                if folder not in folders:
                    folders[folder] = []
                folders[folder].append((item, title))

                item_list.append(item) # Add decrypted item to list
            except InvalidToken:
                print(f"[-] Warning: Could not decrypt item ID: {item['id']}. Possible master password mismatch or corrupted data.")
                continue # Skip this item if decryption fails

        print("\n--- Your Vault Contents ---")
        for folder, folder_items in folders.items():
            print(f"\n📁 {folder}:")
            for item, title in folder_items:
                item_data = item.get("item_data", {})
                item_type = item.get("item_type", "unknown")

                print(f"   {count}. {title} [{item_type.upper()}] [ID: {item['id']}]")

                # Dynamically display summary info based on type
                if item_type == "login":
                    print(f"      Username: {item_data.get('username')}")
                    totp_status = "Configured" if item_data.get('totp_secret') else "Not Configured"
                    print(f"      TOTP: {totp_status}")
                elif item_type == "credit_card":
                    card_num = item_data.get('card_number', '0000')
                    print(f"      Card: **** **** **** {card_num[-4:]}")

                count += 1
        print("---------------------------")
        return item_list
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server.")
        return None


def add_item(auth_tuple: tuple):
    username, password, cipher = auth_tuple
    auth_header = (username, password)

    print("\n--- Add New Item ---")
    title = input("Title (e.g., Gmail, Chase Sapphire): ")
    folder = input("Folder (e.g., Personal, Work): ")

    print("\nItem Types:")
    print("1. Login")
    print("2. Credit Card")
    print("3. Secure Note")
    type_choice = input("Select item type (1-3): ")

    item_type = "unknown"
    item_data_dict = {} # This will be the dictionary to encrypt
    item_data_dict["title"] = title
    item_data_dict["folder"] = folder if folder else "uncategorised"

    if type_choice == '1':
        item_type = "login"
        item_data_dict["username"] = input("Username/Email: ")
        item_data_dict["password"] = getpass.getpass("Password: ")
        totp_secret = input("TOTP Secret (leave blank if none): ").strip()
        if totp_secret:
            item_data_dict["totp_secret"] = totp_secret

    elif type_choice == '2':
        item_type = "credit_card"
        item_data_dict["cardholder_name"] = input("Cardholder Name: ")
        item_data_dict["card_number"] = input("Card Number: ")
        item_data_dict["expiration_date"] = input("Expiration Date (MM/YY): ")
        item_data_dict["cvv"] = input("CVV: ")

    elif type_choice == '3':
        item_type = "secure_note"
        item_data_dict["note"] = input("Enter your secure note: ")
    else:
        print("[-] Invalid choice. Aborting.")
        return

    # Encrypt item_data_dict before sending to API
    encrypted_item_data = cipher.encrypt(json.dumps(item_data_dict).encode()).decode()

    payload = {
        "item_type": item_type,
        "item_data": encrypted_item_data # Send encrypted string
    }

    try:
        response = requests.post(f"{BASE_URL}/items", json=payload, auth=auth_header)

        if response.status_code == 201:
            print(f"\n[+] '{title}' added to your vault.")
        else:
            print(f"\n[-] Failed to add item: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")


def edit_item(auth_tuple: tuple):
    username, password, cipher = auth_tuple
    auth_header = (username, password)

    print("\n--- Edit Item ---")
    items = display_folders(auth_tuple)  # This returns items with decrypted item_data dicts

    if not items:
        return

    item_id = input("\nEnter the ID of the item you want to edit: ").strip()
    item = next((i for i in items if i['id'] == item_id), None)

    if not item:
        print("[-] Item not found.")
        return

    # Extract current decrypted item data structure
    updated_item_data_dict = item.get('item_data', {})

    # Safely look up metadata from within the decrypted dictionary
    current_title = updated_item_data_dict.get('title', 'Untitled')
    current_folder = updated_item_data_dict.get('folder', 'uncategorised')

    print(f"\nEditing: {current_title} [{item.get('item_type', 'unknown').upper()}]")
    print("Tip: Leave a field blank and press Enter to keep the current value.")

    item_data_updates = {}

    # 1. Edit the core metadata (saved inside the encrypted payload)
    new_title = input(f"New Title ({current_title}): ").strip()
    if new_title:
        item_data_updates['title'] = new_title

    new_folder = input(f"New Folder ({current_folder}): ").strip()
    if new_folder:
        item_data_updates['folder'] = new_folder

    # 2. Edit the specific item details dynamically
    print("\n--- Editing Specific Details ---")
    for key, current_value in updated_item_data_dict.items():
        # Skip metadata attributes to avoid duplicate prompt inputs
        if key in ["title", "folder"]:
            continue

        if key in ["password", "cvv", "totp_secret", "private_key"]:
            display_value = "********"
        else:
            display_value = current_value

        new_val = input(f"Update '{key.capitalize()}' ({display_value}): ").strip()
        if new_val:
            item_data_updates[key] = new_val

    # 3. Allow the user to add brand-new custom fields
    print("\n--- Add Custom Details ---")
    while True:
        add_new = input("Do you want to add a new custom field to this item? (y/n): ").strip().lower()
        if add_new != 'y':
            break

        new_key = input("Enter new field name (e.g., 'website', 'pin_code'): ").strip().lower().replace(" ", "_")
        if new_key:
            if new_key in ["title", "folder"]:
                print("[-] Reserved keyword field name. Choose a different label.")
                continue

            is_secret = input("Is this a hidden secret? (y/n): ").strip().lower()
            if is_secret == 'y':
                new_val = getpass.getpass(f"Enter secret value for '{new_key}': ").strip()
            else:
                new_val = input(f"Enter value for '{new_key}': ").strip()

            if new_val:
                item_data_updates[new_key] = new_val

    if not item_data_updates:
        print("\n[-] No changes were made.")
        return

    # Merge updates into our localized target mapping dictionary
    updated_item_data_dict.update(item_data_updates)

    # Encrypt the entire updated item_data dictionary payload (Strategy 1)
    # The API schema only accepts item_type and item_data at the top-level
    payload = {
        'item_data': cipher.encrypt(json.dumps(updated_item_data_dict).encode()).decode()
    }

    try:
        response = requests.patch(f"{BASE_URL}/items/{item_id}", json=payload, auth=auth_header)

        if response.status_code == 200:
            print(f"\n[+] Item updated successfully.")
        else:
            print(f"\n[-] Failed to update item: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server.")


def delete_item_cli(auth_tuple: tuple):
    username, password, cipher = auth_tuple
    auth_header = (username, password)

    print("\n--- Delete Item ---")
    items = display_folders(auth_tuple) # This returns items with already decrypted item_data dicts

    if not items:
        return

    item_id = input("\nEnter the ID of the item you want to delete (moves to trash): ").strip()
    item = next((i for i in items if i['id'] == item_id), None)

    if not item:
        print("[-] Item not found.")
        return

    # Extract title from the decrypted inner item_data dictionary
    title = item.get('item_data', {}).get('title', 'Untitled')

    confirm = input(f"Are you sure you want to delete '{title}'? (y/n): ").strip().lower()
    if confirm != 'y':
        print("[-] Deletion cancelled.")
        return

    try:
        response = requests.delete(f"{BASE_URL}/items/{item_id}", auth=auth_header)

        if response.status_code == 204:
            print(f"\n[+] Item '{title}' moved to trash successfully.")
        elif response.status_code == 404:
            print("[-] Item not found or not owned by user.")
        else:
            print(f"[-] Failed to delete item: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server.")


def view_trash_cli(auth_tuple: tuple):
    username, password, cipher = auth_tuple
    auth_header = (username, password)

    print("\n--- View Trash ---")
    try:
        response = requests.get(f"{BASE_URL}/trash/items", auth=auth_header)

        if response.status_code != 200:
            print("[-] Failed to fetch trash items.")
            return

        trash_items = response.json()

        if not trash_items:
            print("\n[-] Your trash is empty.")
            return

        print("\n--- Items in Trash ---")
        decrypted_trash_items = []
        for item in trash_items:
            try:
                # Decrypt item_data payload completely
                decrypted_data_str = cipher.decrypt(item["item_data"].encode()).decode()
                item_data_dict = json.loads(decrypted_data_str)
                item["item_data"] = item_data_dict  # Replace encrypted string with decrypted dict

                # Fetch title from inside the decrypted block
                title = item_data_dict.get('title', 'Untitled')
                decrypted_trash_items.append(item)

                print(f"Title: {title} [ID: {item['id']}] (Deleted: {item['deleted_at']})")
            except InvalidToken:
                print(f"[-] Warning: Could not decrypt trash item ID: {item['id']}. Skipping corrupted item.")
                continue
        print("----------------------")

        while True:
            print("\nTrash Options:")
            print("1. Restore Item")
            print("2. Permanently Delete Item")
            print("3. Back to Main Menu")
            trash_choice = input("\nSelect an option (1-3): ").strip()

            if trash_choice == '1':
                item_id = input("Enter the ID of the item to restore: ").strip()
                item_to_restore = next((i for i in decrypted_trash_items if i['id'] == item_id), None)

                if not item_to_restore:
                    print("[-] Item not found in trash.")
                    continue

                # Safely capture metadata from inside the decrypted dict
                restore_data_dict = item_to_restore["item_data"]
                title = restore_data_dict.get('title', 'Untitled')

                # Re-encrypt the full dictionary containing everything back into item_data (Strategy 1)
                encrypted_item_data_for_restore = cipher.encrypt(json.dumps(restore_data_dict).encode()).decode()

                # Cleaned payload matching your modified non-metadata leaking API endpoints
                restore_payload = {
                    "id": item_to_restore["id"],
                    "item_type": item_to_restore["item_type"],
                    "item_data": encrypted_item_data_for_restore,
                    "created_at": item_to_restore["created_at"],
                    "updated_at": item_to_restore["updated_at"]
                }

                try:
                    restore_response = requests.post(f"{BASE_URL}/trash/restore/{item_id}", json=restore_payload,
                                                     auth=auth_header)
                    if restore_response.status_code == 200:
                        print(f"[+] Item '{title}' restored successfully.")
                        return
                    elif restore_response.status_code == 404:
                        print("[-] Item not found in trash or not owned by user.")
                    elif restore_response.status_code == 409:
                        print(
                            f"[-] Cannot restore: {restore_response.json().get('detail', 'An active item with this ID already exists.')}")
                    else:
                        print(f"[-] Failed to restore item: {restore_response.text}")
                except requests.exceptions.ConnectionError:
                    print(f"\n[-] Error: Could not connect to the API server.")

            elif trash_choice == '2':
                item_id = input("Enter the ID of the item to permanently delete: ").strip()
                item_to_delete = next((i for i in decrypted_trash_items if i['id'] == item_id), None)
                if not item_to_delete:
                    print("[-] Item not found in trash.")
                    continue

                title = item_to_delete["item_data"].get('title', 'Untitled')

                confirm = input(
                    f"WARNING: This will permanently delete item '{title}'. Are you sure? (y/n): ").strip().lower()
                if confirm == 'y':
                    try:
                        delete_response = requests.delete(f"{BASE_URL}/trash/permanent_delete/{item_id}",
                                                          auth=auth_header)
                        if delete_response.status_code == 204:
                            print(f"[+] Item '{title}' permanently deleted.")
                            return
                        elif delete_response.status_code == 404:
                            print("[-] Item not found in trash or not owned by user.")
                        else:
                            print(f"[-] Failed to permanently delete item: {delete_response.text}")
                    except requests.exceptions.ConnectionError:
                        print(f"\n[-] Error: Could not connect to the API server.")
                else:
                    print("[-] Permanent deletion cancelled.")

            elif trash_choice == '3':
                return
            else:
                print("\n[-] Invalid choice.")

    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server.")


def generate_totp_code(auth_tuple: tuple):
    username, password, cipher = auth_tuple
    auth_header = (username, password)

    print("\n--- Generate TOTP Code ---")
    items = display_folders(auth_tuple) # This returns decrypted items

    if not items:
        return

    item_id_for_totp = input("Enter the ID of the item for which to generate TOTP: ").strip()
    found_item = next((item for item in items if item['id'] == item_id_for_totp), None)

    if not found_item:
        print("[-] Item not found with the given ID.")
        return

    # Extract totp_secret from the nested item_data dictionary (already decrypted)
    item_data = found_item.get('item_data', {})
    title = item_data.get('title', 'Untitled')
    totp_secret = item_data.get('totp_secret')

    if not totp_secret:
        print(f"[-] Item '{title}' does not have a TOTP secret configured.")
        return

    try:
        totp = pyotp.TOTP(totp_secret)
        print(f"\n[+] Current TOTP code for '{title}': {totp.now()}")
        print("    (Code is valid for 30 seconds)")
    except Exception as e:
        print(f"[-] Error generating TOTP code: {e}")


def search_vault(auth_tuple: tuple):
    username, password, cipher = auth_tuple
    auth_header = (username, password)

    print("\n--- Search Vault ---")
    query = input("Enter title search term: ").strip().lower()

    if not query:
        print("[-] Search term cannot be empty.")
        return

    try:
        # Fetch all items securely from the vault endpoint
        response = requests.get(f"{BASE_URL}/items", auth=auth_header)

        if response.status_code != 200:
            print("[-] Failed to fetch vault items for searching.")
            return

        all_items = response.json()

        if not all_items:
            print("\n[-] Your vault is empty. Nothing to search.")
            return

        matches = []

        # Local, in-memory decryption and case-insensitive matching
        for item in all_items:
            try:
                # Decrypt the item data payload locally
                decrypted_data_str = cipher.decrypt(item["item_data"].encode()).decode()
                item_data_dict = json.loads(decrypted_data_str)
                item["item_data"] = item_data_dict  # Replace ciphertext string with decrypted dict

                # Fetch title from decrypted object
                title = item_data_dict.get("title", "Untitled")

                # Check if search term matches the decrypted title
                if query in title.lower():
                    matches.append((item, title))

            except InvalidToken:
                print(f"[-] Warning: Could not decrypt item ID: {item['id']}. Skipping.")
                continue

        if not matches:
            print(f"\n[-] No matches found for '{query}'.")
        else:
            print(f"\n[+] Found {len(matches)} match(es):")
            for item, title in matches:
                item_type = item.get('item_type', 'unknown')
                item_data = item.get('item_data', {})
                folder = item_data.get('folder', 'uncategorised')

                print(f"\n========================================")
                print(f"Title: {title} [{item_type.upper()}]")
                print(f"Folder: {folder}")
                print(f"ID: {item['id']}")
                print(f"----------------------------------------")

                # Print out internal nested fields dynamically
                for key, value in item_data.items():
                    # Skip rendering metadata parameters as redundant custom fields
                    if key in ["title", "folder"]:
                        continue

                    # Obfuscate credentials preview securely in CLI output
                    if key in ["password", "cvv", "totp_secret"] and len(str(value)) > 0:
                        print(f"{key.capitalize()}: ********")
                    else:
                        print(f"{key.capitalize()}: {value}")
            print(f"========================================")

    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server.")

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def vault_menu(auth_tuple: tuple):
    username = auth_tuple[0]
    while True:
        print(f"\n--- {username}'s Vault ---")
        print("1. View Vault")
        print("2. Search Vault")
        print("3. Add New Item")
        print("4. Edit Item")
        print("5. Delete Item")
        print("6. View Trash")
        print("7. Generate TOTP Code")
        print("8. Log Out")

        choice = input("\nSelect an option (1-8): ")

        if choice == '1':
            display_folders(auth_tuple)
        elif choice == '2':
            search_vault(auth_tuple)
        elif choice == '3':
            add_item(auth_tuple)
        elif choice == '4':
            edit_item(auth_tuple)
        elif choice == '5':
            delete_item_cli(auth_tuple)
        elif choice == '6':
            view_trash_cli(auth_tuple)
        elif choice == '7':
            generate_totp_code(auth_tuple)
        elif choice == '8':
            clear_console()
            print("\nLogging out. Your credentials have been cleared from memory.")
            return True
        else:
            print("\n[-] Invalid choice.")
    return False


def main():
    check_server()

    print("====================================")
    print("      API Vault - CLI Client        ")
    print("====================================")

    while True:
        print("\n--- Welcome ---")
        print("1. Log In")
        print("2. Create New User")
        print("3. Exit Program")

        choice = input("\nSelect an option (1-3): ")

        if choice == '1':
            auth_tuple = login_user()
            if auth_tuple:
                logged_out = vault_menu(auth_tuple)
                if logged_out:
                    auth_tuple = None
        elif choice == '2':
            register_user()
        elif choice == '3':
            print("\nGoodbye!")
            break
        else:
            print("\n[-] Invalid choice.")


if __name__ == "__main__":
    main()