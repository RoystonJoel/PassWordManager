import password_manager as f

def main():
    f.setup_database()

    print("====================================")
    print(" Multi-User Secure Password Manager ")
    print("====================================")

    while True:
        print("\n--- Welcome ---")
        print("1. Log In")
        print("2. Create New User")
        print("3. Exit Program")

        choice = input("\nSelect an option (1-3): ")

        if choice == '1':
            user, cipher = f.login_user()
            if user and cipher:
                f.vault_menu(user, cipher)
        elif choice == '2':
            f.create_user()
        elif choice == '3':
            print("\nGoodbye!")
            break
        else:
            print("\n[-] Invalid choice.")


if __name__ == "__main__":
    main()