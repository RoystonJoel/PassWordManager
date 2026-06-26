import requests
import getpass
import sys

BASE_URL = "http://127.0.0.1:8000"


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
            return

        items = response.json()

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
                print(f"   {idx}. {item['title']} (Username: {item['username']})")
        print("---------------------------")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")


def add_item(auth_tuple: tuple):
    print("\n--- Add New Item ---")
    title = input("Title (e.g., Gmail): ")
    folder = input("Folder (e.g., Personal, Work): ")
    username = input("Username/Email: ")
    password = input("Password: ")

    payload = {
        "title": title,
        "folder": folder if folder else "Uncategorized",
        "username": username,
        "password": password
    }

    try:
        response = requests.post(f"{BASE_URL}/items", json=payload, auth=auth_tuple)

        if response.status_code == 200:
            print(f"\n[+] '{title}' added to your vault.")
        else:
            print(f"\n[-] Failed to add item: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Error: Could not connect to the API server at {BASE_URL}.")
        print("    Please ensure the server is running.")


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
        print("4. Log Out")

        choice = input("\nSelect an option (1-4): ")

        if choice == '1':
            display_folders(auth_tuple)
        elif choice == '2':
            search_vault(auth_tuple)
        elif choice == '3':
            add_item(auth_tuple)
        elif choice == '4':
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