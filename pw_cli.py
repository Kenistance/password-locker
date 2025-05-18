import json
import os

PASSWORD_FILE = 'passwords.json'

def load_passwords():
    if not os.path.exists(PASSWORD_FILE):
        return {}
    with open(PASSWORD_FILE, 'r') as f:
        return json.load(f)

def save_passwords(passwords):
    with open(PASSWORD_FILE, 'w') as f:
        json.dump(passwords, f)

def show_menu():
    print("\n🔐 Welcome to Password Locker")
    print("What would you like to do?")
    print("1. Get a password")
    print("2. Add a password")
    print("3. List accounts")
    print("4. Exit")

def get_password(account, passwords):
    password = passwords.get(account)
    if password:
        print(f"\n🔑 The password for {account} is: {password}")
    else:
        print(f"❌ No password found for '{account}'")

def add_password(account, password, passwords):
    passwords[account] = password
    save_passwords(passwords)
    print(f"✅ Password for '{account}' added successfully.")

def list_accounts(passwords):
    if passwords:
        print("\n📂 Stored accounts:")
        for account in passwords:
            print(f"- {account}")
    else:
        print("No accounts saved yet.")

def main():
    passwords = load_passwords()
    while True:
        show_menu()
        choice = input("> ").strip()

        if choice == '1':
            account = input("Enter account name: ").strip()
            get_password(account, passwords)
        elif choice == '2':
            account = input("Enter account name: ").strip()
            pwd = input("Enter password: ").strip()
            add_password(account, pwd, passwords)
        elif choice == '3':
            list_accounts(passwords)
        elif choice == '4':
            print("👋 Goodbye!")
            break
        else:
            print("❗ Invalid option. Try again.")

if __name__ == '__main__':
    main()
