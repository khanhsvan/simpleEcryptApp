import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .constants import APP_TITLE, ENCRYPTION_OPTIONS, METHOD_DESCRIPTIONS
from .services import decrypt_with_method, encrypt_with_method


class EncryptionApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("860x620")
        self.root.minsize(780, 580)

        self.base_dir = Path(__file__).resolve().parent.parent
        self.mode_var = tk.StringVar(value="Encrypt")
        self.method_var = tk.StringVar(value="ChaCha20-Poly1305")
        self.source_path = tk.StringVar()
        self.destination_path = tk.StringVar()
        self.status_var = tk.StringVar(value="Welcome. Choose a file, pick a method, and press Start.")
        self.method_hint_var = tk.StringVar(value=METHOD_DESCRIPTIONS["ChaCha20-Poly1305"])

        self.configure_style()
        self.build_ui()
        self.update_mode_copy()

    def configure_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Hero.TFrame", background="#f4f8fb")
        style.configure("HeroTitle.TLabel", font=("Segoe UI", 18, "bold"), background="#f4f8fb")
        style.configure("HeroText.TLabel", background="#f4f8fb")
        style.configure("Section.TLabelframe.Label", font=("Segoe UI", 11, "bold"))
        style.configure("Primary.TButton", padding=(12, 10))

    def build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        hero = ttk.Frame(self.root, padding=(20, 20, 20, 14), style="Hero.TFrame")
        hero.grid(row=0, column=0, sticky="ew")
        hero.columnconfigure(0, weight=1)

        ttk.Label(hero, text=APP_TITLE, style="HeroTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            hero,
            text="A simpler customer flow for protecting files with guided choices, clearer feedback, and a faster recommended option.",
            style="HeroText.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        top_controls = ttk.Frame(self.root, padding=(20, 16, 20, 0))
        top_controls.grid(row=1, column=0, sticky="ew")
        top_controls.columnconfigure(0, weight=1)
        top_controls.columnconfigure(1, weight=1)

        mode_frame = ttk.LabelFrame(top_controls, text="Step 1: Choose Action", style="Section.TLabelframe", padding=14)
        mode_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        ttk.Radiobutton(mode_frame, text="Encrypt a file", value="Encrypt", variable=self.mode_var, command=self.update_mode_copy).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Radiobutton(mode_frame, text="Decrypt a file", value="Decrypt", variable=self.mode_var, command=self.update_mode_copy).grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )

        method_frame = ttk.LabelFrame(top_controls, text="Step 2: Pick Protection Type", style="Section.TLabelframe", padding=14)
        method_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        method_frame.columnconfigure(0, weight=1)
        method_menu = ttk.OptionMenu(
            method_frame,
            self.method_var,
            self.method_var.get(),
            *ENCRYPTION_OPTIONS,
            command=self.on_method_change,
        )
        method_menu.grid(row=0, column=0, sticky="ew")
        ttk.Label(method_frame, textvariable=self.method_hint_var, wraplength=320).grid(row=1, column=0, sticky="w", pady=(10, 0))

        main = ttk.Frame(self.root, padding=20)
        main.grid(row=2, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)

        files_frame = ttk.LabelFrame(main, text="Step 3: Choose Files", style="Section.TLabelframe", padding=14)
        files_frame.grid(row=0, column=0, sticky="ew")
        files_frame.columnconfigure(1, weight=1)

        self.source_label = ttk.Label(files_frame, text="Source file")
        self.source_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        ttk.Entry(files_frame, textvariable=self.source_path).grid(row=0, column=1, sticky="ew", padx=10)
        ttk.Button(files_frame, text="Browse...", command=self.select_source_file).grid(row=0, column=2, sticky="e")

        self.destination_label = ttk.Label(files_frame, text="Destination file")
        self.destination_label.grid(row=1, column=0, sticky="w")
        ttk.Entry(files_frame, textvariable=self.destination_path).grid(row=1, column=1, sticky="ew", padx=10)
        ttk.Button(files_frame, text="Save as...", command=self.select_destination_file).grid(row=1, column=2, sticky="e")

        action_frame = ttk.LabelFrame(main, text="Step 4: Run", style="Section.TLabelframe", padding=14)
        action_frame.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        action_frame.columnconfigure(0, weight=1)

        self.primary_button = ttk.Button(action_frame, text="Start Encryption", style="Primary.TButton", command=self.process_file)
        self.primary_button.grid(row=0, column=0, sticky="ew")
        ttk.Label(action_frame, textvariable=self.status_var, foreground="#1f4e79", wraplength=760).grid(
            row=1, column=0, sticky="w", pady=(12, 0)
        )

        log_frame = ttk.LabelFrame(main, text="Recent Activity", style="Section.TLabelframe", padding=14)
        log_frame.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_box = tk.Text(log_frame, height=12, wrap="word", state="disabled", font=("Consolas", 10))
        self.log_box.grid(row=0, column=0, sticky="nsew")

    def on_method_change(self, method: str) -> None:
        self.method_var.set(method)
        self.method_hint_var.set(METHOD_DESCRIPTIONS[method])

    def update_mode_copy(self) -> None:
        is_encrypt = self.mode_var.get() == "Encrypt"
        self.primary_button.configure(text="Start Encryption" if is_encrypt else "Start Decryption")
        self.source_label.configure(text="File to protect" if is_encrypt else "Encrypted file")
        self.destination_label.configure(text="Save protected file as" if is_encrypt else "Save unlocked file as")

    def log(self, message: str) -> None:
        self.status_var.set(message)
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def select_source_file(self) -> None:
        path = filedialog.askopenfilename(title="Select source file")
        if path:
            self.source_path.set(path)
            self.log(f"Selected source file: {Path(path).name}")

    def select_destination_file(self) -> None:
        path = filedialog.asksaveasfilename(title="Choose destination file")
        if path:
            self.destination_path.set(path)
            self.log(f"Selected destination file: {Path(path).name}")

    def ensure_paths(self) -> tuple[str, str]:
        source = self.source_path.get().strip()
        destination = self.destination_path.get().strip()

        if not source or not destination:
            raise ValueError("Please choose both a source file and a destination file.")
        if not os.path.exists(source):
            raise ValueError("The selected source file does not exist.")
        if source == destination:
            raise ValueError("Source and destination must be different files.")
        return source, destination

    def ask_required_string(self, title: str, prompt: str) -> str:
        value = simpledialog.askstring(title, prompt, parent=self.root)
        if value is None or not value.strip():
            raise ValueError(f"{title} is required to continue.")
        return value.strip()

    def ask_secret(self, mode: str, method: str) -> str:
        if method == "AES":
            prompt = "Enter the AES key used for this file:" if mode == "Decrypt" else "Enter an AES key (16, 24, or 32 characters):"
            return self.ask_required_string("AES Key", prompt)

        if method == "ChaCha20-Poly1305":
            prompt = (
                "Enter the passphrase used for this file:"
                if mode == "Decrypt"
                else "Enter a passphrase for the fast ChaCha20-Poly1305 method:"
            )
            return self.ask_required_string("Passphrase", prompt)

        if method == "RSA":
            if mode == "Encrypt":
                return ""
            path = filedialog.askopenfilename(
                title="Select private RSA key",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            )
            if not path:
                raise ValueError("A private RSA key is required for RSA decryption.")
            return path

        if method == "Caesar":
            return self.ask_required_string("Caesar Key", "Enter the Caesar shift value:")

        return self.ask_required_string("Playfair Key", "Enter the Playfair keyword:")

    def process_file(self) -> None:
        try:
            source, destination = self.ensure_paths()
            mode = self.mode_var.get()
            method = self.method_var.get()
            secret = self.ask_secret(mode, method)

            if mode == "Encrypt":
                message = encrypt_with_method(method, source, destination, secret, self.base_dir)
            else:
                message = decrypt_with_method(method, source, destination, secret)

            self.log(message)
            messagebox.showinfo(APP_TITLE, message, parent=self.root)
        except Exception as error:
            self.log(f"Error: {error}")
            messagebox.showerror(APP_TITLE, str(error), parent=self.root)


def create_app() -> tk.Tk:
    root = tk.Tk()
    app = EncryptionApp(root)
    app.log("Application ready.")
    return root
