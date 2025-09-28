"""
Frozen Dead Strawberry System (FDS) - GUI edition (Clean Version)
No quotes, no ASCII art — just tools, encryption, file organizer, and hack simulator.
Dependencies: cryptography

Usage:
    pip install cryptography
    python strawberry_clean.py
"""

import os
import sys
import time
import random
import string
import platform
import threading
from pathlib import Path
from tkinter import (
    Tk, Frame, Button, Label, Text, Entry, Menu, END,
    filedialog, messagebox, StringVar, ttk, LEFT, BOTH, X
)
from cryptography.fernet import Fernet

APP_TITLE = "Frozen Dead Strawberry System (FDS)"
KEY_FILE = "fds_gui.key"

# ---------------- Key management ----------------
def load_or_create_key(path=KEY_FILE):
    if not os.path.exists(path):
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(key)
        return key
    with open(path, "rb") as f:
        return f.read()

FERNET_KEY = load_or_create_key()
F = Fernet(FERNET_KEY)

# ---------------- Utilities ----------------
def safe_rename(src, dst):
    i = 1
    base, ext = os.path.splitext(dst)
    new = dst
    while os.path.exists(new):
        new = f"{base} ({i}){ext}"
        i += 1
    os.rename(src, new)

# ---------------- GUI App ----------------
class FDSApp:
    def __init__(self, master):
        self.master = master
        master.title(APP_TITLE)
        master.geometry("900x600")
        master.minsize(760, 480)

        # Menu
        self.build_menu()

        # Tabs
        self.nb = ttk.Notebook(master)
        self.nb.pack(fill=BOTH, expand=True, padx=8, pady=8)

        self.tab_dashboard = Frame(self.nb)
        self.tab_tools = Frame(self.nb)
        self.tab_crypto = Frame(self.nb)
        self.tab_files = Frame(self.nb)
        self.tab_sim = Frame(self.nb)

        self.nb.add(self.tab_dashboard, text="Dashboard")
        self.nb.add(self.tab_tools, text="Utilities")
        self.nb.add(self.tab_crypto, text="Encryption")
        self.nb.add(self.tab_files, text="File Organizer")
        self.nb.add(self.tab_sim, text="Hack Simulator")

        self.build_dashboard()
        self.build_tools()
        self.build_crypto()
        self.build_files()
        self.build_simulator()

    def build_menu(self):
        menubar = Menu(self.master)
        filemenu = Menu(menubar, tearoff=0)
        filemenu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.master.config(menu=menubar)

    def show_about(self):
        messagebox.showinfo("About FDS", f"{APP_TITLE}\nSafe utilities + simulated hacks\nNo malicious capabilities included.")

    # ---------------- Dashboard ----------------
    def build_dashboard(self):
        f = Frame(self.tab_dashboard)
        f.pack(fill=BOTH, expand=True, padx=10, pady=10)

        Label(f, text="FDS Dashboard", font=("Helvetica", 16, "bold")).pack(anchor="w", pady=(0, 10))

        Button(f, text="Open Utilities", command=lambda: self.nb.select(self.tab_tools)).pack(pady=6)
        Button(f, text="Open Encryption", command=lambda: self.nb.select(self.tab_crypto)).pack(pady=6)
        Button(f, text="Open File Organizer", command=lambda: self.nb.select(self.tab_files)).pack(pady=6)
        Button(f, text="Open Hack Simulator", command=lambda: self.nb.select(self.tab_sim)).pack(pady=6)

    # ---------------- Utilities ----------------
    def build_tools(self):
        frame = Frame(self.tab_tools)
        frame.pack(fill=BOTH, expand=True, padx=12, pady=12)

        # Password generator
        pw_frame = Frame(frame, relief="groove", bd=2, padx=8, pady=8)
        pw_frame.pack(fill=X, pady=6)
        Label(pw_frame, text="Password Generator", font=("Helvetica", 12, "bold")).pack(anchor="w")
        opts = Frame(pw_frame)
        opts.pack(fill=X, pady=4)
        Label(opts, text="Length: ").pack(side=LEFT)
        self.pw_len = StringVar(value="16")
        Entry(opts, width=5, textvariable=self.pw_len).pack(side=LEFT)
        Button(opts, text="Generate", command=self.generate_password).pack(side=LEFT, padx=6)
        self.pw_result = Entry(pw_frame, width=60)
        self.pw_result.pack(fill=X, pady=4)

        # Password strength
        strength_frame = Frame(frame, relief="groove", bd=2, padx=8, pady=8)
        strength_frame.pack(fill=X, pady=6)
        Label(strength_frame, text="Password Strength (est.)", font=("Helvetica", 12, "bold")).pack(anchor="w")
        self.str_pwd = Entry(strength_frame, width=60)
        self.str_pwd.pack(fill=X, pady=4)
        self.str_label = Label(strength_frame, text="Strength: N/A")
        self.str_label.pack(anchor="w")
        Button(strength_frame, text="Estimate Strength", command=self.estimate_strength).pack(pady=4)

        # System info
        sys_frame = Frame(frame, relief="groove", bd=2, padx=8, pady=8)
        sys_frame.pack(fill=BOTH, pady=6, expand=True)
        Label(sys_frame, text="System Info", font=("Helvetica", 12, "bold")).pack(anchor="w")
        self.sys_text = Text(sys_frame, height=8)
        self.sys_text.pack(fill=BOTH, expand=True)
        Button(sys_frame, text="Refresh Info", command=self.refresh_sysinfo).pack(pady=4)
        self.refresh_sysinfo()

    def generate_password(self):
        try:
            length = max(4, int(self.pw_len.get()))
        except:
            length = 16
        alphabet = string.ascii_letters + string.digits + string.punctuation
        pw = ''.join(random.SystemRandom().choice(alphabet) for _ in range(length))
        self.pw_result.delete(0, END)
        self.pw_result.insert(0, pw)
        self.str_pwd.delete(0, END)
        self.str_pwd.insert(0, pw)

    def estimate_strength(self):
        pw = self.str_pwd.get()
        score = 0
        if len(pw) >= 8:
            score += 1
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
            score += 1
        if any(c.isdigit() for c in pw):
            score += 1
        if any(c in string.punctuation for c in pw):
            score += 1
        if len(pw) >= 16:
            score += 1
        labels = {0: "Very Weak", 1: "Weak", 2: "Okay", 3: "Strong", 4: "Very Strong", 5: "Excellent"}
        self.str_label.config(text=f"Strength: {labels.get(score, 'Unknown')} (score {score}/5)")

    def refresh_sysinfo(self):
        info = {
            "Platform": platform.platform(),
            "System": platform.system(),
            "Processor": platform.processor(),
            "Python": sys.version.split()[0],
            "Machine": platform.machine(),
            "Node": platform.node()
        }
        self.sys_text.delete("1.0", END)
        for k, v in info.items():
            self.sys_text.insert(END, f"{k}: {v}\n")

    # ---------------- Encryption ----------------
    def build_crypto(self):
        frame = Frame(self.tab_crypto)
        frame.pack(fill=BOTH, expand=True, padx=12, pady=12)

        Label(frame, text="Encryption (Fernet symmetric)", font=("Helvetica", 12, "bold")).pack(anchor="w")
        enc_frame = Frame(frame)
        enc_frame.pack(fill=X, pady=6)
        Label(enc_frame, text="Plaintext:").pack(anchor="w")
        self.plain_entry = Text(enc_frame, height=5)
        self.plain_entry.pack(fill=X)
        Button(enc_frame, text="Encrypt -> show token", command=self.do_encrypt).pack(pady=4)

        Label(enc_frame, text="Token (base64):").pack(anchor="w")
        self.token_entry = Text(enc_frame, height=5)
        self.token_entry.pack(fill=X)
        Button(enc_frame, text="Decrypt token", command=self.do_decrypt).pack(pady=4)
        Button(enc_frame, text="Save key to file...", command=self.save_key_dialog).pack(pady=2)

    def do_encrypt(self):
        raw = self.plain_entry.get("1.0", END).encode().strip()
        if not raw:
            messagebox.showwarning("Encrypt", "No plaintext provided.")
            return
        token = F.encrypt(raw)
        self.token_entry.delete("1.0", END)
        self.token_entry.insert(END, token.decode())
        messagebox.showinfo("Encrypt", "Encrypted. Keep your key safe.")

    def do_decrypt(self):
        token = self.token_entry.get("1.0", END).strip().encode()
        if not token:
            messagebox.showwarning("Decrypt", "No token provided.")
            return
        try:
            decoded = F.decrypt(token).decode()
            self.plain_entry.delete("1.0", END)
            self.plain_entry.insert(END, decoded)
            messagebox.showinfo("Decrypt", "Decryption successful.")
        except Exception as e:
            messagebox.showerror("Decrypt", f"Failed: {e}")

    def save_key_dialog(self):
        path = filedialog.asksaveasfilename(
            title="Save FDS Key", defaultextension=".key", filetypes=[("Key file","*.key")]
        )
        if path:
            with open(path, "wb") as f:
                f.write(FERNET_KEY)
            messagebox.showinfo("Save key", f"Key saved to: {path}")

    # ---------------- File Organizer ----------------
    def build_files(self):
        frame = Frame(self.tab_files)
        frame.pack(fill=BOTH, expand=True, padx=12, pady=12)

        Label(frame, text="File Organizer", font=("Helvetica", 12, "bold")).pack(anchor="w")
        controls = Frame(frame)
        controls.pack(fill=X, pady=4)
        self.folder_var = StringVar()
        Entry(controls, textvariable=self.folder_var).pack(side=LEFT, fill=X, expand=True, padx=4)
        Button(controls, text="Browse", command=self.browse_folder).pack(side=LEFT, padx=4)
        Button(controls, text="Organize", command=self.organize_folder).pack(side=LEFT, padx=4)

        Label(frame, text="Log:").pack(anchor="w", pady=(8,0))
        self.file_log = Text(frame, height=12)
        self.file_log.pack(fill=BOTH, expand=True)

    def browse_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.folder_var.set(p)

    def organize_folder(self):
        folder = self.folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Organizer", "Please select a valid folder.")
            return
        self.file_log.insert(END, f"Organizing: {folder}\n")
        try:
            moved = 0
            for entry in os.scandir(folder):
                if entry.is_file():
                    ext = Path(entry.name).suffix.lower().strip(".")
                    if not ext:
                        ext = "no_ext"
                    target_dir = os.path.join(folder, ext)
                    os.makedirs(target_dir, exist_ok=True)
                    dst = os.path.join(target_dir, entry.name)
                    safe_rename(entry.path, dst)
                    self.file_log.insert(END, f"Moved {entry.name} -> {ext}/\n")
                    moved += 1
            self.file_log.insert(END, f"Done. {moved} files moved.\n\n")
        except Exception as e:
            self.file_log.insert(END, f"Error: {e}\n")

    # ---------------- Hack Simulator ----------------
    def build_simulator(self):
        frame = Frame(self.tab_sim)
        frame.pack(fill=BOTH, expand=True, padx=12, pady=12)
        Label(frame, text="Hack Simulator — purely cosmetic", font=("Helvetica", 12, "bold")).pack(anchor="w")
        sim_controls = Frame(frame)
        sim_controls.pack(fill=X, pady=6)
        Button(sim_controls, text="Start Show", command=self.start_simulation).pack(side=LEFT, padx=4)
        Button(sim_controls, text="Stop", command=self.stop_simulation).pack(side=LEFT, padx=4)
        Button(sim_controls, text="Clear", command=self.clear_sim_console).pack(side=LEFT, padx=4)

        self.sim_console = Text(frame, height=20)
        self.sim_console.pack(fill=BOTH, expand=True)
        self.sim_console.insert(END, "# FDS Hack Simulator (safe)\n")
        self._sim_running = False
        self._sim_thread = None

    def clear_sim_console(self):
        self.sim_console.delete("1.0", END)

    def start_simulation(self):
        if self._sim_running:
            return
        self._sim_running = True
        self._sim_thread = threading.Thread(target=self._simulate_run, daemon=True)
        self._sim_thread.start()

    def stop_simulation(self):
        self._sim_running = False

    def _simulate_run(self):
        script = [
            ("Scanning local environment...", 1.0),
            ("Found: frozen_strawberry_drive (mounted)", 0.8),
            ("Enumerating processes...", 1.1),
            ("Process 1024: strawberry_sync [suspicious]", 0.7),
            ("Cracking fake-hash: *******", 1.4),
            ("Bypassing imaginary firewall...", 1.2),
            ("Decrypting sample token...", 1.0),
            ("Access granted: the strawberry secret is jam.", 0.9),
            ("Wiping nothing (simulation).", 0.6),
            ("Simulation complete. Remember: this is fake.", 0.5)
        ]
        for line, delay in script:
            if not self._sim_running:
                break
            self._type_line(line + "\n", delay)
        self._sim_running = False

    def _type_line(self, line, base_delay=0.8):
        for ch in line:
            if not self._sim_running:
                return
            self.sim_console.insert(END, ch)
            self.sim_console.see(END)
            time.sleep(base_delay * 0.02)
        time.sleep(base_delay * 0.35)

# ---------------- Main ----------------
def main():
    root = Tk()
    app = FDSApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
