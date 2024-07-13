import os
import json
import shutil
import time
import tkinter as tk
from tkinter import filedialog, simpledialog, ttk, messagebox
from threading import Thread
import queue
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
import random

# Function to securely prompt for user password (no echoing)
def get_user_password(prompt="Enter your password: "):
    password = simpledialog.askstring("Password", prompt, show='*', parent=root)
    if password:
        return password.encode()
    return None

# Function to confirm the password
def confirm_password(password):
    confirm = simpledialog.askstring("Confirm Password", "Confirm your password:", show='*', parent=root)
    if confirm and password.decode() == confirm:
        return True
    return False

# Function to generate a random file encryption key
def generate_random_key():
    return get_random_bytes(32)  # 32 bytes for AES-256

# Function to derive a secure key from user password and salt
def derive_key(password, salt):
    return PBKDF2(password, salt, 32, count=390000)

# Function to encrypt a file using AES-CFB mode
def encrypt_file(filepath, key):
    try:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        with open(filepath, 'rb') as f_in:
            content = f_in.read()
        ciphertext = iv + cipher.encrypt(content)
        return ciphertext
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return None

# Function to decrypt a file using AES-CFB mode
def decrypt_file(filepath, key):
    try:
        with open(filepath, 'rb') as f_in:
            ciphertext = f_in.read()
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return None

# Function to encrypt a file/directory and store key securely
def encrypt(filepath, password):
    file_key = generate_random_key()
    salt = get_random_bytes(16)
    key_encryption_key = derive_key(password, salt)
    
    if os.path.isfile(filepath):
        ciphertext = encrypt_file(filepath, file_key)
        if ciphertext is None:
            return False
        enc_filepath = filepath + '.enc'
        with open(enc_filepath, 'wb') as f_out:
            f_out.write(ciphertext)
        os.remove(filepath)

        iv = get_random_bytes(AES.block_size)
        key_encryption_cipher = AES.new(key_encryption_key, AES.MODE_CFB, iv)
        encrypted_file_key = iv + key_encryption_cipher.encrypt(file_key)
        
        # Generate HMAC for the file key for integrity check
        hmac = HMAC.new(key_encryption_key, encrypted_file_key, digestmod=SHA256).hexdigest()

        key_info = {
            'salt': salt.hex(),
            'encrypted_file_key': encrypted_file_key.hex(),
            'hmac': hmac
        }

        with open(filepath + '.enc.key', 'w') as f_out:
            json.dump(key_info, f_out)

    else:
        new_dir = filepath + '.enc'
        os.makedirs(new_dir, exist_ok=True)
        for root, dirs, files in os.walk(filepath):
            for filename in files:
                file_path = os.path.join(root, filename)
                ciphertext = encrypt_file(file_path, file_key)
                if ciphertext is None:
                    continue
                rel_path = os.path.relpath(file_path, filepath)
                enc_file_path = os.path.join(new_dir, rel_path + '.enc')
                enc_file_dir = os.path.dirname(enc_file_path)
                os.makedirs(enc_file_dir, exist_ok=True)
                with open(enc_file_path, 'wb') as f_out:
                    f_out.write(ciphertext)
                os.remove(file_path)

        time.sleep(4)
        try:
            shutil.rmtree(filepath)
        except OSError as e:
            print(f"Error removing directory: {e}")

        iv = get_random_bytes(AES.block_size)
        key_encryption_cipher = AES.new(key_encryption_key, AES.MODE_CFB, iv)
        encrypted_file_key = iv + key_encryption_cipher.encrypt(file_key)
        
        # Generate HMAC for the file key for integrity check
        hmac = HMAC.new(key_encryption_key, encrypted_file_key, digestmod=SHA256).hexdigest()

        key_info = {
            'salt': salt.hex(),
            'encrypted_file_key': encrypted_file_key.hex(),
            'hmac': hmac
        }

        with open(filepath + '.enc.key', 'w') as f_out:
            json.dump(key_info, f_out)

    return True

# Function to decrypt a file/directory (requires user authentication)
def decrypt(filepath, password):
    if filepath.endswith('.enc'):
        key_file_path = filepath[:-4] + '.enc.key'
    elif os.path.exists(filepath + '.enc.key'):
        key_file_path = filepath + '.enc.key'
    else:
        print("Invalid file. Only files with '.enc' extensions or directories with '.enc' suffix can be processed.")
        return False

    if not os.path.exists(key_file_path):
        print("Key file not found for decryption.")
        return False

    with open(key_file_path, 'r') as f_in:
        key_info = json.load(f_in)

    salt = bytes.fromhex(key_info['salt'])
    encrypted_file_key = bytes.fromhex(key_info['encrypted_file_key'])
    stored_hmac = key_info['hmac']

    iv = encrypted_file_key[:AES.block_size]
    encrypted_file_key = encrypted_file_key[AES.block_size:]

    key_encryption_key = derive_key(password, salt)
    key_encryption_cipher = AES.new(key_encryption_key, AES.MODE_CFB, iv)

    try:
        file_key = key_encryption_cipher.decrypt(encrypted_file_key)
        
        # Verify HMAC
        computed_hmac = HMAC.new(key_encryption_key, iv + encrypted_file_key, digestmod=SHA256).hexdigest()
        if computed_hmac != stored_hmac:
            print("Incorrect password or data integrity check failed.")
            return False

    except ValueError:
        print("Incorrect password.")
        return False

    if filepath.endswith('.enc') and os.path.isfile(filepath):
        plaintext = decrypt_file(filepath, file_key)
        if plaintext is None:
            return False
        with open(filepath[:-4], 'wb') as f_out:
            f_out.write(plaintext)
        os.remove(filepath)
    else:
        new_dir = filepath.replace('.enc', '')
        os.makedirs(new_dir, exist_ok=True)
        for root, dirs, files in os.walk(filepath):
            for filename in files:
                file_path = os.path.join(root, filename)
                plaintext = decrypt_file(file_path, file_key)
                if plaintext is None:
                    continue
                rel_path = os.path.relpath(file_path, filepath)
                dec_file_path = os.path.join(new_dir, rel_path[:-4])
                dec_file_dir = os.path.dirname(dec_file_path)
                os.makedirs(dec_file_dir, exist_ok=True)
                with open(dec_file_path, 'wb') as f_out:
                    f_out.write(plaintext)
                os.remove(file_path)
        shutil.rmtree(filepath)

    os.remove(key_file_path)
    return True

def run_encryption(filepath, password, result_queue):
    success = encrypt(filepath, password)
    result_queue.put(success)

def run_decryption(filepath, password, result_queue):
    success = decrypt(filepath, password)
    result_queue.put(success)

def encrypt_thread(filepath, password):
    result_queue = queue.Queue()
    Thread(target=run_encryption, args=(filepath, password, result_queue)).start()
    show_loading("Encrypting...", result_queue)

def decrypt_thread(filepath, password):
    result_queue = queue.Queue()
    Thread(target=run_decryption, args=(filepath, password, result_queue)).start()
    show_loading("Decrypting...", result_queue)

def browse_file():
    filename = filedialog.askopenfilename(parent=root)
    if filename:
        entry_filepath.delete(0, tk.END)
        entry_filepath.insert(0, filename)

def browse_folder():
    foldername = filedialog.askdirectory(parent=root)
    if foldername:
        entry_filepath.delete(0, tk.END)
        entry_filepath.insert(0, foldername)

def reset_entry():
    entry_filepath.delete(0, tk.END)

def on_encrypt():
    filepath = entry_filepath.get()
    if not filepath:
        show_message("Error", "Please select a file or folder to encrypt.")
        return

    password = get_user_password("Enter password for encryption:")
    if password:
        if confirm_password(password):
            encrypt_thread(filepath, password)
        else:
            show_message("Error", "Passwords do not match.")
    else:
        show_message("Error", "Password cannot be empty.")

def on_decrypt():
    filepath = entry_filepath.get()
    if not filepath:
        show_message("Error", "Please select a file or folder to decrypt.")
        return

    password = get_user_password("Enter password for decryption:")
    if password:
        decrypt_thread(filepath, password)
    else:
        show_message("Error", "Password cannot be empty.")

def show_message(title, message):
    messagebox.showinfo(title, message)

def show_loading(message, result_queue):
    loading_label.config(text=message)
    progress_bar.start()
    action_frame.pack_forget()
    loading_frame.pack(pady=20)
    root.update()
    root.after(100, check_result_queue, result_queue)

def check_result_queue(result_queue):
    try:
        result = result_queue.get_nowait()
        progress_bar.stop()
        loading_frame.pack_forget()
        action_frame.pack(pady=20)
        if result:
            show_operation_status("Operation completed successfully.")
        else:
            show_operation_status("Operation failed.")
        reset_entry()
    except queue.Empty:
        root.after(100, check_result_queue, result_queue)

def show_operation_status(message):
    status_label.config(text=message)
    success_label.config(text=message)

def draw_matrix():
    canvas.delete("all")
    for _ in range(200):
        x = random.randint(0, 400)
        y = random.randint(0, 400)
        char = random.choice(["0", "1"])
        color = "#0F0"
        canvas.create_text(x, y, text=char, fill=color, font=("Consolas", 10))
    root.after(50, draw_matrix)

# Graphical User Interface
root = tk.Tk()
root.title("HPJ_CRYP")
root.geometry("400x400")
root.configure(bg="black")

style = ttk.Style()
style.configure("TButton", padding=6, relief="flat")
style.map("Encrypt.TButton", background=[('active', 'red')])
style.map("Decrypt.TButton", background=[('active', 'green')])
style.configure("TEntry", padding=6, relief="flat")
style.configure("TLabel", padding=6, relief="flat", background="black", foreground="white")
style.configure("TFrame", background="black")

main_frame = ttk.Frame(root, style="TFrame")
main_frame.pack(pady=20)

canvas = tk.Canvas(root, width=400, height=400, bg="black", highlightthickness=0)
canvas.pack(fill="both", expand=True)

entry_filepath = ttk.Entry(main_frame, width=40, style="TEntry")
entry_filepath.pack(padx=10, pady=10)

browse_frame = ttk.Frame(main_frame, style="TFrame")
browse_frame.pack(pady=5)

btn_browse_file = ttk.Button(browse_frame, text="Browse File", command=browse_file, style="TButton")
btn_browse_file.pack(side=tk.LEFT, padx=5)

btn_browse_folder = ttk.Button(browse_frame, text="Browse Folder", command=browse_folder, style="TButton")
btn_browse_folder.pack(side=tk.LEFT, padx=5)

action_frame = ttk.Frame(main_frame, style="TFrame")
action_frame.pack(pady=20)

btn_encrypt = ttk.Button(action_frame, text="Encrypt", command=on_encrypt, style="Encrypt.TButton")
btn_encrypt.grid(row=0, column=0, padx=10)

btn_decrypt = ttk.Button(action_frame, text="Decrypt", command=on_decrypt, style="Decrypt.TButton")
btn_decrypt.grid(row=0, column=1, padx=10)

loading_frame = ttk.Frame(main_frame, style="TFrame")

loading_label = ttk.Label(loading_frame, text="", style="TLabel")
loading_label.pack(pady=10)

progress_bar = ttk.Progressbar(loading_frame, mode="indeterminate")
progress_bar.pack(pady=10)

status_label = ttk.Label(root, text="", style="TLabel")
status_label.pack(pady=10)

success_label = ttk.Label(action_frame, text="", style="TLabel")
success_label.grid(row=1, column=0, columnspan=2, pady=10)

draw_matrix()
root.mainloop()


