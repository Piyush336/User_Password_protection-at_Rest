#Graphical User Interface***
#To Run the Encryption on the GUI
def run_encryption(filepath, password, result_queue):
    success = encrypt(filepath, password)
    result_queue.put(success)
##To Run the Decryption on the GUI
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
