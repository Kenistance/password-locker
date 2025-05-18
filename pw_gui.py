import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import json
import os
import random
import string
import pyperclip  # For clipboard copy, install with: pip install pyperclip
from cryptography.fernet import Fernet
import hashlib

# --- CONSTANTS & FILES ---
DATA_FILE = "passwords.enc"
KEY_FILE = "key.key"

# --- Generate or load encryption key ---
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

key = load_key()
cipher = Fernet(key)

# --- Load passwords from encrypted file ---
def load_passwords():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())
    except:
        return {}

# --- Save passwords to encrypted file ---
def save_passwords():
    data = json.dumps(passwords).encode()
    encrypted = cipher.encrypt(data)
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)

# --- Master password management ---
MASTER_HASH_FILE = "master.hash"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def set_master_password():
    # Ask user to set master password (first time only)
    while True:
        pwd1 = simpledialog.askstring("Set Master Password", "Create a master password:", show="*")
        if not pwd1:
            messagebox.showerror("Error", "Master password is required!")
            continue
        pwd2 = simpledialog.askstring("Confirm Master Password", "Confirm your master password:", show="*")
        if pwd1 != pwd2:
            messagebox.showerror("Error", "Passwords do not match!")
        else:
            with open(MASTER_HASH_FILE, "w") as f:
                f.write(hash_password(pwd1))
            return pwd1

def verify_master_password():
    if not os.path.exists(MASTER_HASH_FILE):
        return set_master_password()
    with open(MASTER_HASH_FILE, "r") as f:
        stored_hash = f.read()
    for _ in range(3):
        pwd = simpledialog.askstring("Master Password", "Enter master password:", show="*")
        if pwd is None:
            return None
        if hash_password(pwd) == stored_hash:
            return pwd
        else:
            messagebox.showerror("Error", "Incorrect password. Try again.")
    return None

# --- Password Generator ---
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# --- Password Strength Meter ---
def password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    score = sum([has_upper, has_lower, has_digit, has_symbol])
    if length >= 12 and score >= 3:
        return "Strong"
    elif length >= 8 and score >= 2:
        return "Moderate"
    else:
        return "Weak"

# --- Main app ---

passwords = load_passwords()

# Login
root = tk.Tk()
root.withdraw()  # Hide main window during login

master = verify_master_password()
if master is None:
    messagebox.showinfo("Exit", "Failed to authenticate. Exiting.")
    exit()

root.deiconify()  # Show main window after login

root.title("Password Locker")
root.geometry("600x400")
root.resizable(False, False)

# --- GUI Widgets ---

# Frame for inputs
frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Account:", font=("Arial", 12)).grid(row=0, column=0, sticky="w", padx=5)
account_entry = tk.Entry(frame, width=40)
account_entry.grid(row=0, column=1, padx=5)

tk.Label(frame, text="Password:", font=("Arial", 12)).grid(row=1, column=0, sticky="w", padx=5)
password_entry = tk.Entry(frame, width=40, show="*")
password_entry.grid(row=1, column=1, padx=5)

strength_label = tk.Label(frame, text="Password strength: ", font=("Arial", 10))
strength_label.grid(row=2, column=1, sticky="w", padx=5)

def update_strength(event=None):
    pwd = password_entry.get()
    strength = password_strength(pwd)
    strength_label.config(text=f"Password strength: {strength}")

password_entry.bind("<KeyRelease>", update_strength)

# Buttons frame
btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

def save_password():
    account = account_entry.get().strip()
    password = password_entry.get().strip()
    if not account or not password:
        messagebox.showwarning("Input Error", "Please fill in both fields.")
        return
    passwords[account] = password
    save_passwords()
    messagebox.showinfo("Success", f"Password saved for '{account}'!")
    account_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    update_list()

def show_password():
    selected = tree.focus()
    if not selected:
        messagebox.showwarning("Select Account", "Please select an account from the list.")
        return
    account = tree.item(selected)['text']
    password = passwords.get(account)
    if password:
        # Copy password to clipboard instead of showing (safer)
        pyperclip.copy(password)
        messagebox.showinfo(f"Copied Password for '{account}'", "Password copied to clipboard.")
    else:
        messagebox.showerror("Not Found", "Password not found.")

def delete_password():
    selected = tree.focus()
    if not selected:
        messagebox.showwarning("Select Account", "Please select an account to delete.")
        return
    account = tree.item(selected)['text']
    if messagebox.askyesno("Confirm Delete", f"Delete password for '{account}'?"):
        passwords.pop(account, None)
        save_passwords()
        update_list()

def edit_password():
    selected = tree.focus()
    if not selected:
        messagebox.showwarning("Select Account", "Please select an account to edit.")
        return
    account = tree.item(selected)['text']
    new_password = simpledialog.askstring("Edit Password", f"Enter new password for '{account}':", show="*")
    if new_password:
        passwords[account] = new_password
        save_passwords()
        update_list()

def generate_and_fill():
    gen_pwd = generate_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, gen_pwd)
    update_strength()

tk.Button(btn_frame, text="Save", width=12, command=save_password).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Show/Copy", width=12, command=show_password).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Edit", width=12, command=edit_password).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Delete", width=12, command=delete_password).grid(row=0, column=3, padx=5)
tk.Button(btn_frame, text="Generate", width=12, command=generate_and_fill).grid(row=0, column=4, padx=5)
tk.Button(btn_frame, text="Exit", width=12, command=root.quit).grid(row=0, column=5, padx=5)

# --- Treeview for listing accounts ---
tree = ttk.Treeview(root, columns=("Password"), show="tree")
tree.pack(pady=10, fill="x", expand=True)

def update_list():
    tree.delete(*tree.get_children())
    for acc in passwords:
        tree.insert("", "end", text=acc)

update_list()

# --- Start GUI loop ---
root.mainloop()
