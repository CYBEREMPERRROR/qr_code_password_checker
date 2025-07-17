import tkinter as tk from tkinter import messagebox, simpledialog, PhotoImage from tkinter import ttk import json, os, base64, time from cryptography.fernet import Fernet from PIL import Image, ImageTk import threading import pygame

Initialize Pygame mixer for sound

pygame.mixer.init()

def play_sound(file): try: pygame.mixer.Sound(file).play() except Exception as e: print(f"Error playing sound: {e}")

=== Vault Logic ===

VAULT_FILE = 'vault.json' KEY_FILE = 'secret.key' QR_UNLOCK_FILE = 'unlock_key.png'

class PasswordVault: def init(self): self.key = None self.vault = {} self.last_activity = time.time()

def load_key(self):
    with open(KEY_FILE, 'rb') as f:
        self.key = f.read()
    return self.key

def load_vault(self):
    if not os.path.exists(VAULT_FILE):
        self.vault = {}
    else:
        with open(VAULT_FILE, 'rb') as f:
            data = Fernet(self.key).decrypt(f.read()).decode()
            self.vault = json.loads(data)

def save_vault(self):
    data = json.dumps(self.vault).encode()
    with open(VAULT_FILE, 'wb') as f:
        f.write(Fernet(self.key).encrypt(data))

def add_entry(self, platform, username, password):
    self.vault[platform] = {'username': username, 'password': password}
    self.save_vault()

def delete_entry(self, platform):
    if platform in self.vault:
        del self.vault[platform]
        self.save_vault()

=== GUI ===

class VaultApp: def init(self, root): self.root = root self.vault = PasswordVault() self.authenticated = False self.vault_screen = None self.inactivity_timer = None

self.build_intro()

def reset_timer(self):
    self.vault.last_activity = time.time()

def check_auto_lock(self):
    while True:
        if self.authenticated and (time.time() - self.vault.last_activity > 60):
            self.lock_vault()
        time.sleep(5)

def lock_vault(self):
    self.authenticated = False
    messagebox.showinfo("Vault Locked", "Vault auto-locked due to inactivity.")
    self.show_unlock()

def build_intro(self):
    self.intro_frame = tk.Frame(self.root, bg="black")
    self.intro_frame.pack(fill='both', expand=True)

    canvas = tk.Canvas(self.intro_frame, bg="black", highlightthickness=0)
    canvas.pack(fill='both', expand=True)

    self.binary_text = []
    for i in range(0, 800, 15):
        text = canvas.create_text(i, 0, text='0', fill='green', font=('Consolas', 12))
        self.binary_text.append((text, i))

    def animate():
        while True:
            for txt, x in self.binary_text:
                y = canvas.coords(txt)[1]
                if y > 600:
                    canvas.coords(txt, x, 0)
                else:
                    canvas.move(txt, 0, 10)
            time.sleep(0.1)
    threading.Thread(target=animate, daemon=True).start()

    # Developer Info
    info = tk.Label(self.intro_frame, text="BY\nYAHUZA YUNUS MUSA\nCOMPUTER SCIENCE\nUA-CSC102 - SURVEY OF PROGRAMMING LANGUAGES",
                    font=("Consolas", 12), fg="lime", bg="black")
    info.place(relx=0.5, rely=0.3, anchor='center')

    # Profile Picture
    if os.path.exists("ethical_hacker.jpg"):
        img = Image.open("ethical_hacker.jpg").resize((100, 100))
        self.pic = ImageTk.PhotoImage(img)
        tk.Label(self.intro_frame, image=self.pic, bg="black").place(relx=0.5, rely=0.55, anchor='center')

    # Continue Button
    style = ttk.Style()
    style.configure("Futuristic.TButton", font=("Consolas", 11, "bold"), foreground="black", background="lime")
    btn = ttk.Button(self.intro_frame, text="[ CONTINUE ]", style="Futuristic.TButton", command=self.startup, cursor='hand2')
    btn.place(relx=0.5, rely=0.8, anchor='center')

    play_sound("startup.wav")

def startup(self):
    self.intro_frame.destroy()
    self.show_unlock()
    threading.Thread(target=self.check_auto_lock, daemon=True).start()

def show_unlock(self):
    self.unlock_frame = tk.Frame(self.root, bg="black")
    self.unlock_frame.pack(fill='both', expand=True)
    tk.Label(self.unlock_frame, text="Enter QR Key String", font=("Consolas", 12), fg="lime", bg="black").pack(pady=10)
    key_entry = tk.Entry(self.unlock_frame, font=("Consolas", 12), show='*')
    key_entry.pack()

    def unlock():
        key = key_entry.get()
        try:
            decoded = base64.b64decode(key.encode())
            with open(KEY_FILE, 'wb') as f:
                f.write(decoded)
            self.vault.load_key()
            self.vault.load_vault()
            self.authenticated = True
            play_sound("unlock.wav")
            self.unlock_frame.destroy()
            self.build_vault()
        except:
            messagebox.showerror("Error", "Invalid Key")

    tk.Button(self.unlock_frame, text="Unlock", command=unlock, bg="lime", fg="black").pack(pady=10)

def build_vault(self):
    self.vault_screen = tk.Frame(self.root, bg="#0f0f0f")
    self.vault_screen.pack(fill='both', expand=True)

    tk.Label(self.vault_screen, text="🔐 Password Vault", font=("Consolas", 14), bg="#0f0f0f", fg="lime").pack(pady=10)

    search_var = tk.StringVar()
    search_entry = tk.Entry(self.vault_screen, textvariable=search_var)
    search_entry.pack()

    password_list = tk.Listbox(self.vault_screen, width=50, height=10, font=("Consolas", 10))
    password_list.pack(pady=10)

    show_passwords = tk.BooleanVar(value=False)

    def update_list():
        password_list.delete(0, tk.END)
        for platform, creds in self.vault.vault.items():
            if search_var.get().lower() in platform.lower():
                line = f"{platform} - {creds['username']} - " + (creds['password'] if show_passwords.get() else '********')
                password_list.insert(tk.END, line)

    def toggle_password():
        show_passwords.set(not show_passwords.get())
        update_list()

    search_var.trace("w", lambda *args: update_list())

    tk.Checkbutton(self.vault_screen, text="👁️ Show Passwords", variable=show_passwords, command=toggle_password, bg="#0f0f0f", fg="white").pack()

    def add_entry():
        self.reset_timer()
        platform = simpledialog.askstring("Platform", "Enter platform name:")
        username = simpledialog.askstring("Username", "Enter username:")
        password = simpledialog.askstring("Password", "Enter password:")
        if platform and username and password:
            self.vault.add_entry(platform, username, password)
            update_list()

    def delete_entry():
        self.reset_timer()
        selection = password_list.curselection()
        if not selection:
            return
        platform = password_list.get(selection[0]).split(' - ')[0]
        self.vault.delete_entry(platform)
        update_list()

    tk.Button(self.vault_screen, text="➕ Add", command=add_entry, bg="#0fa", fg="black").pack(side='left', padx=10, pady=5)
    tk.Button(self.vault_screen, text="🗑️ Delete", command=delete_entry, bg="#f44", fg="white").pack(side='left', padx=10, pady=5)
    update_list()

if name == 'main': root = tk.Tk() root.title("QR Password Vault") root.geometry("500x500") app = VaultApp(root) root.mainloop()

