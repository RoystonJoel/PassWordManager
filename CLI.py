import requests
import getpass
import sys
import datetime # Import the datetime module
import pyotp # Import pyotp for TOTP generation

BASE_URL = "http://localhost:8000"


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

    payload = {
        "username": username,
        "master_password": master_pw
    }

    try:
        response = requests.post(f"{BASE_URL}/register", json=payload)

        if response.status_code == 201:
            print(f"\n[+] User '{username}' created successfully! You can now log in.")
        else:
            # Extract the error message from the API if it failed (e.g., username taken)
            error_detail = response.json().get("detail", "Unknown error")
            print(f"\n[-] Registration failed: {error_detail}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")


def login_user():
    """
    Since the API uses Basic Auth on every request rather than session tokens,
    we 'log in' by making a test request to the /items endpoint.
    """
    print("\n--- User Login ---")
    username = input("Username: ").strip().lower()

    attempts = 3
    while attempts > 0:
        password = getpass.getpass(f"Master Password ({attempts} attempts left): ")
        auth_tuple = (username, password)

        try:
            # Test the credentials by trying to fetch the vault
            response = requests.get(f"{BASE_URL}/items", auth=auth_tuple)

            if response.status_code == 200:
                print(f"\n[+] Welcome back, {username}!")
                return auth_tuple
            elif response.status_code == 401:
                print("[-] Incorrect password or user not found.")
                attempts -= 1
            else:
                print(f"[-] Server error: {response.status_code}")
                return None
        except requests.exceptions.ConnectionError:
            print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
            print("    Please ensure the server is running.")
            return None

    print("\n[-] Access denied.")
    return None


def display_folders(auth_tuple: tuple):
    try:
        response = requests.get(f"{BASE_URL}/items", auth=auth_tuple)

        if response.status_code != 200:
            print("[-] Failed to fetch vault.")
            return None # Return None to indicate failure

        items = response.json()

        if not items:
            print("\n[-] Your vault is empty.")
            return None # Return None to indicate no items

        folders = {}
        for item in items:
            folder = item["folder"]
            if folder not in folders:
                folders[folder] = []
            folders[folder].append(item)

        print("\n--- Your Vault Contents ---")
        item_list = []
        count = 1
        for folder, folder_items in folders.items():
            print(f"\n📁 {folder}:")
            for item in folder_items:
                created_at_dt = datetime.datetime.fromisoformat(item['created_at'])
                updated_at_dt = datetime.datetime.fromisoformat(item['updated_at'])
                totp_status = "Configured" if item.get('totp_secret') else "Not Configured"
                print(f"   {count}. {item['title']} (Username: {item['username']}) [ID: {item['id']}]")
                print(f"      TOTP: {totp_status}")
                print(f"      Created: {created_at_dt.strftime('%Y-%m-%d %H:%M:%S')}, Last Updated: {updated_at_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                item_list.append(item)
                count += 1
        print("---------------------------")
        return item_list # Return the list of items for editing
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")
        return None


def add_item(auth_tuple: tuple):
    print("\n--- Add New Item ---")
    title = input("Title (e.g., Gmail): ")
    folder = input("Folder (e.g., Personal, Work): ")
    username = input("Username/Email: ")
    password = input("Password: ")
    totp_secret = input("TOTP Secret (leave blank if none): ").strip()

    payload = {
        "title": title,
        "folder": folder if folder else "Uncategorized",
        "username": username,
        "password": password
    }
    if totp_secret:
        payload["totp_secret"] = totp_secret

    try:
        response = requests.post(f"{BASE_URL}/items", json=payload, auth=auth_tuple)

        if response.status_code == 200:
            print(f"\n[+] '{title}' added to your vault.")
        else:
            print(f"\n[-] Failed to add item: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")


def edit_item(auth_tuple: tuple):
    print("\n--- Edit Item ---")
    items = display_folders(auth_tuple) # Display items and get the list

    if not items:
        return

    item_id_to_edit = input("Enter the ID of the item you want to edit: ").strip()

    # Find the item to ensure it exists and belongs to the user (implicitly handled by API)
    # For a better UX, we could pre-fill current values, but for now, we'll just update.
    found_item = next((item for item in items if item['id'] == item_id_to_edit), None)

    if not found_item:
        print("[-] Item not found with the given ID.")
        return

    print(f"\nEditing item: {found_item['title']} (ID: {found_item['id']})")
    print("Enter new values, or leave blank to keep current value.")
    print("For TOTP Secret, enter 'clear' to remove it, or leave blank to keep current.")

    new_title = input(f"New Title (current: {found_item['title']}): ").strip()
    new_folder = input(f"New Folder (current: {found_item['folder']}): ").strip()
    new_username = input(f"New Username (current: {found_item['username']}): ").strip()
    new_password = getpass.getpass("New Password (leave blank to keep current): ").strip()
    current_totp_status = "Configured" if found_item.get('totp_secret') else "Not Configured"
    new_totp_secret_input = input(f"New TOTP Secret (current: {current_totp_status}): ").strip()


    payload = {}
    if new_title:
        payload["title"] = new_title
    if new_folder:
        payload["folder"] = new_folder
    if new_username:
        payload["username"] = new_username
    if new_password:
        payload["password"] = new_password
    if new_totp_secret_input == 'clear':
        payload["totp_secret"] = None # Explicitly set to None to clear it
    elif new_totp_secret_input:
        payload["totp_secret"] = new_totp_secret_input


    if not payload:
        print("[!] No changes to apply.")
        return

    try:
        response = requests.patch(f"{BASE_URL}/items/{item_id_to_edit}", json=payload, auth=auth_tuple)

        if response.status_code == 200:
            print(f"\n[+] Item '{found_item['title']}' updated successfully!")
        elif response.status_code == 404:
            print("[-] Item not found or not owned by you.")
        else:
            print(f"\n[-] Failed to update item: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")


def generate_totp_code(auth_tuple: tuple):
    print("\n--- Generate TOTP Code ---")
    items = display_folders(auth_tuple)

    if not items:
        return

    item_id_for_totp = input("Enter the ID of the item for which to generate TOTP: ").strip()

    found_item = next((item for item in items if item['id'] == item_id_for_totp), None)

    if not found_item:
        print("[-] Item not found with the given ID.")
        return

    totp_secret = found_item.get('totp_secret')
    if not totp_secret:
        print(f"[-] Item '{found_item['title']}' does not have a TOTP secret configured.")
        return

    try:
        totp = pyotp.TOTP(totp_secret)
        print(f"\n[+] Current TOTP code for '{found_item['title']}': {totp.now()}")
        print("    (Code is valid for 30 seconds)")
    except Exception as e:
        print(f"[-] Error generating TOTP code: {e}")
        print("    Please ensure the TOTP secret is valid Base32 encoded.")


def search_vault(auth_tuple: tuple):
    print("\n--- Search Vault ---")
    query = input("Enter title search term: ")

    try:
        # Pass the query parameter to the URL
        response = requests.get(f"{BASE_URL}/search", params={"query": query}, auth=auth_tuple)

        if response.status_code != 200:
            print("[-] Failed to search vault.")
            return

        results = response.json()

        if not results:
            print("\n[-] No matches found.")
        else:
            print(f"\nFound {len(results)} match(es):")
            for item in results:
                print(f"\nTitle: {item['title']}")
                print(f"Folder: {item['folder']}")
                print(f"Username: {item['username']}")
                print(f"Password: {item['password']}")
                totp_status = "Configured" if item.get('totp_secret') else "Not Configured"
                print(f"TOTP: {totp_status}")
                # Format created_at and updated_at for user-friendly display
                created_at_dt = datetime.datetime.fromisoformat(item['created_at'])
                updated_at_dt = datetime.datetime.fromisoformat(item['updated_at'])
                print(f"Created at: {created_at_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Last Updated: {updated_at_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")


def vault_menu(auth_tuple: tuple):
    username = auth_tuple[0]
    while True:
        print(f"\n--- {username}'s Vault ---")
        print("1. View Vault")
        print("2. Search Vault")
        print("3. Add New Item")
        print("4. Edit Item")
        print("5. Generate TOTP Code") # New option
        print("6. Log Out") # Updated option number

        choice = input("\nSelect an option (1-6): ")

        if choice == '1':
            display_folders(auth_tuple)
        elif choice == '2':
            search_vault(auth_tuple)
        elif choice == '3':
            add_item(auth_tuple)
        elif choice == '4':
            edit_item(auth_tuple)
        elif choice == '5': # Handle new option
            generate_totp_code(auth_tuple)
        elif choice == '6': # Updated option number
            print("\nLogging out. Your credentials have been cleared from memory.")
            break
        else:
            print("\n[-] Invalid choice.")


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
                vault_menu(auth_tuple)
        elif choice == '2':
            register_user()
        elif choice == '3':
            print("\nGoodbye!")
            break
        else:
            print("\n[-] Invalid choice.")


if __name__ == "__main__":
    main()