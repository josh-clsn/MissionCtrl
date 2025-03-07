import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from autonomi_client import Client, Network, Wallet, PaymentOption, DataMapChunk, PublicArchive, Metadata
import asyncio
import os
import threading
import logging
import io
import json
from PIL import Image, ImageTk
from web3 import Web3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import platform
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MissionCtrl")

ANT_TOKEN_ADDRESS = "0xa78d8321B20c4Ef90eCd72f2588AA985A4BDb684"
ANT_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    }
]

def add_context_menu(widget):
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    widget.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))

class TestApp:
    def __init__(self):
        if platform.system() == "Linux":
            self.default_dir = Path(os.path.expanduser("~/.local/share/missionctrl"))
        elif platform.system() == "Windows":
            self.default_dir = Path(os.path.expanduser("~/Documents/missionctrl"))
        elif platform.system() == "Darwin":  # macOS
            self.default_dir = Path(os.path.expanduser("~/Documents/missionctrl"))
        else:
            self.default_dir = Path(os.path.expanduser("~/Documents/missionctrl"))
        self.default_dir.mkdir(parents=True, exist_ok=True)

        os.environ.setdefault("EVM_NETWORK", "arbitrum-one")
        
        self.root = tk.Tk()
        self.root.withdraw()
        if not messagebox.askokcancel(
            "Warning",
            "WARNING: Only send or import small amounts of funds. "
            "The app developer makes no guarantees that your funds will not be lost. Do you agree?"
        ):
            self.root.destroy()
            sys.exit()
        self.root.deiconify()
        
        self.root.title("Mission Ctrl")
        self.root.geometry("630x550")
        self.root.configure(bg="#f0f2f5")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.loop = asyncio.new_event_loop()
        self.client = None
        self.wallet = None
        self.uploaded_files = []
        self.local_archives = []
        self.w3 = Web3(Web3.HTTPProvider('https://arb1.arbitrum.io/rpc'))
        self.wallet_file = str(self.default_dir / "wallet.enc")
        self.data_file = str(self.default_dir / "mission_control_data.json")
        
        self.is_public_var = tk.BooleanVar(value=False)
        self.is_private_var = tk.BooleanVar(value=False)
        self.upload_queue = []
        self.is_processing = False
        self.status_dots = ["", ".", "..", "..."]
        self.current_dot_idx = 0
        self.status_update_task = None
        self._current_operation = None

        self.load_persistent_data()
        self.setup_gui()
        
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        asyncio.run_coroutine_threadsafe(self.initialize_client(), self.loop)
        self.update_balances()

    def start_status_animation(self):
        if self.status_update_task is None:
            def update_status():
                if self.is_processing:
                    if self._current_operation == 'upload':
                        msg = "Uploading files"
                    elif self._current_operation == 'archive':
                        msg = "Creating archive"
                    elif self._current_operation == 'download':
                        msg = "Downloading data"
                    else:
                        msg = "Processing"
                    self.status_label.config(text=f"{msg}{self.status_dots[self.current_dot_idx]}")
                    self.current_dot_idx = (self.current_dot_idx + 1) % len(self.status_dots)
                    self.root.after(500, update_status)
                else:
                    self.status_update_task = None
                    self.status_label.config(text="Ready")
            self.status_update_task = self.root.after(0, update_status)

    def stop_status_animation(self):
        if self.status_update_task is not None:
            self.root.after_cancel(self.status_update_task)
            self.status_update_task = None
        self.status_label.config(text="Ready")

    def load_persistent_data(self):
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                self.uploaded_files = [(item["filename"], item["chunk_addr"]) for item in data.get("uploaded_files", [])]
                self.local_archives = [(item["addr"], item["nickname"], item["is_private"]) for item in data.get("local_archives", [])]
                logger.info("Loaded persistent data from %s", self.data_file)
        except Exception as e:
            logger.error("Failed to load persistent data: %s", e)
            self.uploaded_files = []
            self.local_archives = []

    def save_persistent_data(self):
        try:
            data = {
                "uploaded_files": [{"filename": f, "chunk_addr": a} for f, a in self.uploaded_files],
                "local_archives": [{"addr": a, "nickname": n, "is_private": p} for a, n, p in self.local_archives]
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info("Saved persistent data to %s", self.data_file)
        except Exception as e:
            logger.error("Failed to save persistent data: %s", e)

    def on_closing(self):
        logger.info("Closing window...")
        self.save_persistent_data()
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.root.destroy()

    def setup_gui(self):
        style = ttk.Style()
        style.configure("TButton", padding=6, font=("Arial", 10))
        style.map("TButton", background=[("active", "#d3d3d3")])
        style.configure("TLabel", background="#f0f2f5", font=("Arial", 10))
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("Accent.TButton", background="#b0c4de", foreground="black")
        style.map("Accent.TButton", background=[("active", "#a9b7d1")])
        style.configure("Status.TFrame", background="#e9ecef")

        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        wallet_tab = ttk.Frame(notebook)
        notebook.add(wallet_tab, text="Wallet")
        
        self.connection_label = ttk.Label(wallet_tab, text="Network: Connecting...", foreground="#666666")
        self.connection_label.pack(pady=(0, 15))

        wallet_card = ttk.Frame(wallet_tab, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
        wallet_card.pack(fill=tk.X, pady=(0, 15))
        self.wallet_address_label = ttk.Label(wallet_card, text="Wallet: Not Connected", wraplength=400, foreground="#333333")
        self.wallet_address_label.pack(anchor="w")
        wallet_actions = ttk.Frame(wallet_card)
        wallet_actions.pack(fill=tk.X, pady=(10, 0))
        options_btn = ttk.Button(wallet_actions, text="Wallet Options", command=self.show_wallet_options)
        options_btn.pack(side=tk.RIGHT)
        help_btn = ttk.Button(wallet_actions, text="Help", command=self.show_help)
        help_btn.pack(side=tk.RIGHT, padx=5)

        balance_card = ttk.Frame(wallet_tab, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
        balance_card.pack(fill=tk.X, pady=(0, 15))
        balances = ttk.Frame(balance_card)
        balances.pack(fill=tk.X)
        self.ant_balance_label = ttk.Label(balances, text="ANT Balance: Not Connected", foreground="#333333")
        self.ant_balance_label.pack(side=tk.LEFT)
        self.eth_balance_label = ttk.Label(balances, text="ETH Balance: Not Connected", foreground="#333333")
        self.eth_balance_label.pack(side=tk.RIGHT)
        refresh_btn = ttk.Button(balance_card, text="Refresh", command=self.update_balances)
        refresh_btn.pack(pady=(10, 0))

        upload_tab = ttk.Frame(notebook)
        notebook.add(upload_tab, text="Upload")
        
        actions_frame = ttk.Frame(upload_tab, padding="10")
        actions_frame.pack(fill=tk.X, pady=(0, 15))
        def toggle_public():
            if self.is_public_var.get():
                self.is_private_var.set(False)
        def toggle_private():
            if self.is_private_var.get():
                self.is_public_var.set(False)
        public_checkbox = ttk.Checkbutton(actions_frame, text="Public", variable=self.is_public_var, command=toggle_public)
        public_checkbox.pack(anchor="w")
        private_checkbox = ttk.Checkbutton(actions_frame, text="Private (encrypted)", variable=self.is_private_var, command=toggle_private)
        private_checkbox.pack(anchor="w")
        upload_btn = ttk.Button(actions_frame, text="Upload", command=self.upload_file, style="Accent.TButton")
        upload_btn.pack(fill=tk.X, pady=(10, 0))

        queue_frame = ttk.Frame(actions_frame)
        queue_frame.pack(fill=tk.X, pady=(5, 0))
        add_queue_btn = ttk.Button(queue_frame, text="Add to Upload Queue", command=self.add_to_upload_queue, style="Accent.TButton")
        add_queue_btn.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        start_queue_btn = ttk.Button(queue_frame, text="Start Upload Queue", command=self.start_upload_queue, style="Accent.TButton")
        start_queue_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.queue_label = ttk.Label(actions_frame, text="Queue: 0 files")
        self.queue_label.pack(anchor="w", pady=(5, 0))
        
        queue_list_frame = ttk.Frame(actions_frame)
        queue_list_frame.pack(fill=tk.BOTH, expand=True)
        self.queue_listbox = tk.Listbox(queue_list_frame, height=5)
        self.queue_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(queue_list_frame, orient="vertical", command=self.queue_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.queue_listbox.config(yscrollcommand=scrollbar.set)
        
        remove_btn = ttk.Button(actions_frame, text="Remove Selected", command=self.remove_from_queue)
        remove_btn.pack(pady=(5, 0))

        retrieve_tab = ttk.Frame(notebook)
        notebook.add(retrieve_tab, text="Download")
        
        retrieve_frame = ttk.Frame(retrieve_tab, padding="10")
        retrieve_frame.pack(fill=tk.X)
        ttk.Label(retrieve_frame, text="Download Data", font=("Arial", 11, "bold")).pack(anchor="w")
        retrieve_inner = ttk.Frame(retrieve_frame, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
        retrieve_inner.pack(fill=tk.X, pady=(5, 0))
        self.retrieve_entry = ttk.Entry(retrieve_inner)
        self.retrieve_entry.pack(fill=tk.X, pady=(0, 10))
        self.retrieve_entry.insert(0, "Enter a data address (e.g., 0x123...)")
        self.retrieve_entry.config(foreground="grey")
        def on_entry_focus_in(event):
            if self.retrieve_entry.get() == "Enter a data address (e.g., 0x123...)":
                self.retrieve_entry.delete(0, tk.END)
                self.retrieve_entry.config(foreground="black")
        def on_entry_focus_out(event):
            if not self.retrieve_entry.get().strip():  # Only reset if empty
                self.retrieve_entry.insert(0, "Enter a data address (e.g., 0x123...)")
                self.retrieve_entry.config(foreground="grey")
        self.retrieve_entry.bind("<FocusIn>", on_entry_focus_in)
        self.retrieve_entry.bind("<FocusOut>", on_entry_focus_out)
        self.retrieve_entry.bind("<Return>", lambda event: self.retrieve_data())
        add_context_menu(self.retrieve_entry)
        get_btn = ttk.Button(retrieve_inner, text="Get", command=self.retrieve_data, style="Accent.TButton")
        get_btn.pack(fill=tk.X)

        manage_tab = ttk.Frame(notebook)
        notebook.add(manage_tab, text="Manage Files")
        
        manage_frame = ttk.Frame(manage_tab, padding="10")
        manage_frame.pack(fill=tk.BOTH, expand=True)
        manage_btn = ttk.Button(manage_frame, text="Manage Public Data", command=self.manage_public_files, style="Accent.TButton")
        manage_btn.pack(fill=tk.X, pady=5)
        store_private_btn = ttk.Button(manage_frame, text="Manage Private Data", command=self.manage_private_files, style="Accent.TButton")
        store_private_btn.pack(fill=tk.X, pady=5)

        status_bar = ttk.Frame(main_frame, relief="sunken", borderwidth=1, style="Status.TFrame")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_label = ttk.Label(status_bar, text="Ready", foreground="#666666")
        self.status_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(status_bar, text="v1.0.0", foreground="#666666").pack(side=tk.RIGHT, padx=5)

        self.root.resizable(False, False)

    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Mission Ctrl Help")
        help_window.geometry("500x400")
        help_window.resizable(False, False)

        text = tk.Text(help_window, wrap=tk.WORD, height=20, width=60)
        text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
        scrollbar = tk.Scrollbar(help_window, command=text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.config(yscrollcommand=scrollbar.set)
        text.insert(tk.END, "Welcome to Mission Ctrl!\n\n")
        text.insert(tk.END, "Getting Started:\n")
        text.insert(tk.END, "- Wallet: You need a wallet to pay for uploads and manage funds. Go to the Wallet tab to create or import one.\n")
        text.insert(tk.END, "- Upload: Select 'Public' (anyone can see) or 'Private' (encrypted) and choose files to upload.\n")
        text.insert(tk.END, "- Download: Enter a data address from an upload to retrieve your files.\n")
        text.insert(tk.END, "- Manage Files: Organize your uploaded files into archives or remove them.\n\n")
        text.insert(tk.END, "Tips:\n")
        text.insert(tk.END, "- Save your wallet’s private key securely! You’ll lose access to funds without it.\n")
        text.insert(tk.END, "- Check your ANT balance before uploading (you need ANT to pay).\n")
        text.insert(tk.END, "- Addresses look like long strings (e.g., 0x123...). Copy them carefully.\n")
        text.bind("<Key>", lambda e: "break")
        add_context_menu(text)

        tk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=5)

    def upload_file(self):
        self.status_label.config(text="Checking upload options...")
        public_selected = self.is_public_var.get()
        private_selected = self.is_private_var.get()

        if not public_selected and not private_selected:
            messagebox.showwarning(
                "Selection Required",
                "Please select either Public or Private upload type.\n"
                "Public data is NOT encrypted.\nPrivate data IS encrypted."
            )
            self.status_label.config(text="Ready")
            return

        file_path = filedialog.askopenfilename(
            title="Select a File to Upload",
            filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")]
        )
        if not file_path:
            self.status_label.config(text="Ready")
            return

        self.is_processing = True
        self._current_operation = 'upload'
        self.start_status_animation()
        self.status_label.config(text=f"Uploading file: {os.path.basename(file_path)}")
        if public_selected:
            asyncio.run_coroutine_threadsafe(self._upload_public(file_path), self.loop)
        elif private_selected:
            asyncio.run_coroutine_threadsafe(self._upload_private(file_path), self.loop)

    def add_to_upload_queue(self):
        self.status_label.config(text="Adding files to queue...")
        public_selected = self.is_public_var.get()
        private_selected = self.is_private_var.get()

        if not public_selected and not private_selected:
            messagebox.showwarning(
                "Selection Required",
                "Please select either Public or Private upload type.\n"
                "Public data is NOT encrypted.\nPrivate data IS encrypted."
            )
            self.status_label.config(text="Ready")
            return

        file_paths = filedialog.askopenfilenames(
            title="Select Files to Upload",
            filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")]
        )
        if not file_paths:
            self.status_label.config(text="Ready")
            return

        upload_type = "public" if public_selected else "private"
        for file_path in file_paths:
            self.upload_queue.append((upload_type, file_path))
            self.queue_listbox.insert(tk.END, f"{upload_type.capitalize()}: {os.path.basename(file_path)}")
        
        self.queue_label.config(text=f"Queue: {len(self.upload_queue)} files")
        self.status_label.config(text=f"Added {len(file_paths)} files to queue")

    def remove_from_queue(self):
        selection = self.queue_listbox.curselection()
        if not selection:
            messagebox.showwarning("Selection Error", "Please select a file to remove from the queue.")
            return
        
        index = selection[0]
        self.upload_queue.pop(index)
        self.queue_listbox.delete(index)
        self.queue_label.config(text=f"Queue: {len(self.upload_queue)} files")
        self.status_label.config(text="File removed from queue")

    def start_upload_queue(self):
        if not self.upload_queue:
            messagebox.showinfo("Queue Empty", "No files in the upload queue.")
            return
        if not self.is_processing:
            if messagebox.askyesno("Confirm Upload", f"Start uploading {len(self.upload_queue)} files now? This will use ANT from your wallet."):
                self.is_processing = True
                self._current_operation = 'upload'
                self.start_status_animation()
                asyncio.run_coroutine_threadsafe(self.process_upload_queue(), self.loop)

    async def process_upload_queue(self):
        total_files = len(self.upload_queue)
        while self.upload_queue and self.is_processing:
            upload_type, file_path = self.upload_queue[0]  # Peek at the first item
            self.root.after(0, lambda: self.status_label.config(text=f"Uploading file 1 of {total_files}: {os.path.basename(file_path)}"))
            if upload_type == "public":
                await self._upload_public(file_path, from_queue=True)
            else:
                await self._upload_private(file_path, from_queue=True)
            if self.upload_queue:  # Check if queue still has items after upload
                self.upload_queue.pop(0)
                self.queue_listbox.delete(0)
                self.root.after(0, lambda: self.queue_label.config(text=f"Queue: {len(self.upload_queue)} files"))
                self.root.after(0, lambda: self.status_label.config(text=f"Completed file {total_files - len(self.upload_queue)} of {total_files}"))
        
        self.is_processing = False
        self.stop_status_animation()
        self.root.after(0, lambda: self.status_label.config(text="Queue processing completed"))

    def manage_public_files(self):
        manage_window = tk.Toplevel(self.root)
        manage_window.title("Manage Public Files - Mission Ctrl")
        manage_window.geometry("600x700")
        manage_window.resizable(True, True)

        search_frame = ttk.Frame(manage_window)
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        search_entry = ttk.Entry(search_frame)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        add_context_menu(search_entry)

        def filter_files():
            query = search_entry.get().lower()
            refresh_content(query)

        search_entry.bind("<KeyRelease>", lambda e: filter_files())

        files_frame = ttk.LabelFrame(manage_window, text="Uploaded Files", padding=5)
        files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        files_canvas = tk.Canvas(files_frame)
        files_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
        files_inner_frame = ttk.Frame(files_canvas)
        files_canvas.configure(yscrollcommand=files_scrollbar.set)

        files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")

        check_vars = []

        archives_frame = ttk.LabelFrame(manage_window, text="Archives", padding=5)
        archives_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        archives_canvas = tk.Canvas(archives_frame)
        archives_scrollbar = ttk.Scrollbar(archives_frame, orient="vertical", command=archives_canvas.yview)
        archives_inner_frame = ttk.Frame(archives_canvas)
        archives_canvas.configure(yscrollcommand=archives_scrollbar.set)

        archives_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        archives_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        archives_canvas.create_window((0, 0), window=archives_inner_frame, anchor="nw")

        archive_vars = []

        def refresh_content(query=""):
            for widget in files_inner_frame.winfo_children():
                widget.destroy()
            for widget in archives_inner_frame.winfo_children():
                widget.destroy()

            check_vars.clear()
            archive_vars.clear()
            for filename, chunk_addr in self.uploaded_files:
                if query in filename.lower() or query in chunk_addr.lower():
                    var = tk.BooleanVar(value=False)
                    check_vars.append((var, filename, chunk_addr))
                    frame = ttk.Frame(files_inner_frame)
                    frame.pack(anchor="w", padx=5, pady=2)
                    chk = ttk.Checkbutton(frame, text=f"{filename} - ", variable=var)
                    chk.pack(side=tk.LEFT)
                    addr_entry = ttk.Entry(frame, width=80)
                    addr_entry.insert(0, chunk_addr)
                    addr_entry.config(state="readonly")
                    addr_entry.pack(side=tk.LEFT)
                    add_context_menu(addr_entry)

            public_archives = [(addr, name) for addr, name, is_private in self.local_archives if not is_private]
            for addr, nickname in public_archives:
                if query in nickname.lower() or query in addr.lower():
                    var = tk.BooleanVar(value=False)
                    archive_vars.append((var, addr, nickname))
                    frame = ttk.Frame(archives_inner_frame)
                    frame.pack(anchor="w", padx=5, pady=2)
                    chk = ttk.Checkbutton(frame, text=f"{nickname} - ", variable=var)
                    chk.pack(side=tk.LEFT)
                    addr_entry = ttk.Entry(frame, width=80)
                    addr_entry.insert(0, addr)
                    addr_entry.config(state="readonly")
                    addr_entry.pack(side=tk.LEFT)
                    add_context_menu(addr_entry)

            files_inner_frame.update_idletasks()
            files_canvas.configure(scrollregion=files_canvas.bbox("all"))
            archives_inner_frame.update_idletasks()
            archives_canvas.configure(scrollregion=archives_canvas.bbox("all"))

        refresh_content()

        buttons_frame = ttk.Frame(manage_window)
        buttons_frame.pack(fill=tk.X, pady=10)

        def add_to_archive(public_archives):
            selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
            if not selected:
                messagebox.showwarning("Selection Error", "Please select at least one file to archive.")
                return

            archive_window = tk.Toplevel(manage_window)
            archive_window.title("Add to Archive - Mission Ctrl")
            archive_window.geometry("400x250")

            ttk.Label(archive_window, text="Nickname for New Archive:").pack(pady=5)
            nickname_entry = ttk.Entry(archive_window)
            nickname_entry.pack(pady=5)
            nickname_entry.insert(0, "My Archive")

            ttk.Label(archive_window, text="Select Archive:").pack(pady=5)
            archive_combo = ttk.Combobox(archive_window, values=[f"{n} - {a}" for a, n in public_archives])
            archive_combo.pack(pady=5)
            archive_combo.set("Create New Archive")

            remove_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(archive_window, text="Remove selected files from Uploaded Files list", variable=remove_var).pack(pady=5)

            async def do_archive():
                nickname = nickname_entry.get().strip()
                if not nickname:
                    self.root.after(0, lambda: messagebox.showwarning("Input Error", "Please enter a nickname for the archive."))
                    return

                archive_choice = archive_combo.get()
                should_remove = remove_var.get()
                
                archive_window.destroy()
                self.root.after(0, lambda: messagebox.showinfo("Archiving Started", "The archiving process has begun. Go touch grass, it can take a while..."))

                selected_files = [(fn, addr, Metadata(size=0)) for fn, addr in selected]
                self.is_processing = True
                self._current_operation = 'archive'
                self.start_status_animation()
                try:
                    logger.info("Starting archive creation with nickname: %s", nickname)
                    if archive_choice == "Create New Archive":
                        archive = PublicArchive()
                        for filename, chunk_addr, metadata in selected_files:
                            archive.add_file(filename, chunk_addr, metadata)
                        logger.info("Calling archive_put_public for new archive")
                        cost, archive_addr = await asyncio.wait_for(
                            self.client.archive_put_public(archive, self.wallet),
                            timeout=1200
                        )
                        self.local_archives.append((archive_addr, nickname, False))
                        logger.info("New archive created at %s", archive_addr)
                    else:
                        archive_addr = archive_choice.split(" - ")[1]
                        logger.info("Fetching existing archive at %s", archive_addr)
                        archive = await self.client.archive_get_public(archive_addr)
                        for filename, chunk_addr, metadata in selected_files:
                            archive.add_file(filename, chunk_addr, metadata)
                        logger.info("Calling archive_put_public for updated archive")
                        cost, new_archive_addr = await asyncio.wait_for(
                            self.client.archive_put_public(archive, self.wallet),
                            timeout=1200
                        )
                        for i, (addr, _, is_private) in enumerate(self.local_archives):
                            if addr == archive_addr and not is_private:
                                self.local_archives[i] = (new_archive_addr, nickname, False)
                                break
                        archive_addr = new_archive_addr
                        logger.info("Updated archive at %s", archive_addr)

                    if should_remove:
                        for filename, chunk_addr in selected:
                            self.uploaded_files.remove((filename, chunk_addr))

                    self.save_persistent_data()
                    with open(self.data_file, 'r') as f:
                        saved_data = json.load(f)
                    saved_archives = [(item["addr"], item["nickname"], item["is_private"]) 
                                    for item in saved_data.get("local_archives", [])]
                    if (archive_addr, nickname, False) not in saved_archives:
                        logger.error("Failed to save archive %s with nickname %s to JSON", archive_addr, nickname)
                        raise Exception("Archive not saved correctly to JSON")

                    self.root.after(0, lambda: refresh_content())
                    self.root.after(0, lambda: messagebox.showinfo("Success", f"Archive '{nickname}' created successfully at {archive_addr}"))
                except asyncio.TimeoutError:
                    logger.error("Archive operation timed out after 1200 seconds")
                    self.root.after(0, lambda: messagebox.showerror("Error", "Archive operation timed out. Check your network connection."))
                except Exception as error:
                    logger.error("Archiving error: %s", error)
                    error_msg = str(error)
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Archiving failed: {error_msg}\nCheck your ANT balance and network."))
                finally:
                    self.is_processing = False
                    self.stop_status_animation()

            ttk.Button(archive_window, text="Archive", command=lambda: asyncio.run_coroutine_threadsafe(do_archive(), self.loop)).pack(pady=10)

        def append_to_archive(public_archives):
            selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
            if not selected:
                messagebox.showwarning("Selection Error", "Please select at least one file to append.")
                return
            if not public_archives:
                messagebox.showwarning("No Archives", "No existing archives to append to. Use 'Add to Archive' to create one.")
                return

            append_window = tk.Toplevel(manage_window)
            append_window.title("Append to Archive - Mission Ctrl")
            append_window.geometry("400x200")

            ttk.Label(append_window, text="Select Archive to Append To:").pack(pady=5)
            archive_combo = ttk.Combobox(append_window, values=[f"{n} - {a}" for a, n in public_archives])
            archive_combo.pack(pady=5)
            if public_archives:
                archive_combo.set(f"{public_archives[0][1]} - {public_archives[0][0]}")

            remove_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(append_window, text="Remove selected files from Uploaded Files list", variable=remove_var).pack(pady=5)

            async def do_append():
                archive_choice = archive_combo.get()
                should_remove = remove_var.get()
                
                if not archive_choice:
                    self.root.after(0, lambda: messagebox.showwarning("Input Error", "Please select an archive to append to."))
                    return

                append_window.destroy()
                self.root.after(0, lambda: messagebox.showinfo("Appending Started", "The appending process has begun. Please wait..."))

                archive_addr = archive_choice.split(" - ")[1]
                selected_files = [(fn, addr, Metadata(size=0)) for fn, addr in selected]
                self.is_processing = True
                self._current_operation = 'archive'
                self.start_status_animation()
                try:
                    logger.info("Appending to archive at %s", archive_addr)
                    archive = await self.client.archive_get_public(archive_addr)
                    # Store original nickname before modification
                    original_nickname = next((n for a, n, p in self.local_archives if a == archive_addr and not p), None)
                    for filename, chunk_addr, metadata in selected_files:
                        archive.add_file(filename, chunk_addr, metadata)
                    logger.info("Calling archive_put_public for updated archive")
                    cost, new_archive_addr = await asyncio.wait_for(
                        self.client.archive_put_public(archive, self.wallet),
                        timeout=1200
                    )
                    
                    for i, (addr, nickname, is_private) in enumerate(self.local_archives):
                        if addr == archive_addr and not is_private:
                            self.local_archives[i] = (new_archive_addr, original_nickname, False)
                            break

                    if should_remove:
                        for filename, chunk_addr in selected:
                            self.uploaded_files.remove((filename, chunk_addr))

                    self.save_persistent_data()
                    with open(self.data_file, 'r') as f:
                        saved_data = json.load(f)
                    saved_archives = [(item["addr"], item["nickname"], item["is_private"]) 
                                    for item in saved_data.get("local_archives", [])]
                    if (new_archive_addr, original_nickname, False) not in saved_archives:
                        logger.error("Failed to save updated archive %s with nickname %s to JSON", new_archive_addr, original_nickname)
                        raise Exception("Updated archive not saved correctly to JSON")

                    logger.info("Archive updated at %s", new_archive_addr)
                    self.root.after(0, lambda: refresh_content())
                    self.root.after(0, lambda: messagebox.showinfo("Success", f"Files appended to archive at {new_archive_addr}"))
                except asyncio.TimeoutError:
                    logger.error("Append operation timed out after 1200 seconds")
                    self.root.after(0, lambda: messagebox.showerror("Error", "Append operation timed out. Check your network connection."))
                except Exception as error:
                    logger.error("Appending error: %s", error)
                    error_msg = str(error)
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Appending failed: {error_msg}\nCheck your ANT balance and network."))
                finally:
                    self.is_processing = False
                    self.stop_status_animation()

            ttk.Button(append_window, text="Append", command=lambda: asyncio.run_coroutine_threadsafe(do_append(), self.loop)).pack(pady=10)

        def remove_selected():
            selected_files = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
            selected_archives = [(addr, nickname) for var, addr, nickname in archive_vars if var.get()]
            if not selected_files and not selected_archives:
                messagebox.showwarning("Selection Error", "Please select at least one item to remove.")
                return
            if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_files)} files and {len(selected_archives)} archives from the list? This won’t delete the data from the network."):
                for filename, chunk_addr in selected_files:
                    self.uploaded_files.remove((filename, chunk_addr))
                for addr, nickname in selected_archives:
                    for i, (a, n, is_private) in enumerate(self.local_archives):
                        if a == addr and n == nickname and not is_private:
                            self.local_archives.pop(i)
                            break
                self.save_persistent_data()
                refresh_content()

        public_archives = [(addr, name) for addr, name, is_private in self.local_archives if not is_private]
        ttk.Button(buttons_frame, text="Add to Archive", command=lambda: add_to_archive(public_archives)).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Append to Archive", command=lambda: append_to_archive(public_archives)).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Remove from List", command=remove_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Close", command=manage_window.destroy).pack(side=tk.LEFT, padx=5)

    def manage_private_files(self):
        manage_window = tk.Toplevel(self.root)
        manage_window.title("Store Private Data Files - Mission Ctrl")
        manage_window.geometry("600x700")
        manage_window.resizable(True, True)

        search_frame = ttk.Frame(manage_window)
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        search_entry = ttk.Entry(search_frame)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        add_context_menu(search_entry)

        def filter_files():
            query = search_entry.get().lower()
            refresh_content(query)

        search_entry.bind("<KeyRelease>", lambda e: filter_files())

        def refresh_content(query=""):
            for widget in files_inner_frame.winfo_children():
                widget.destroy()

            check_vars.clear()
            private_files = [(addr, name) for addr, name, is_private in self.local_archives if is_private]
            for addr, nickname in private_files:
                if query in nickname.lower() or query in addr.lower():
                    var = tk.BooleanVar(value=False)
                    check_vars.append((var, addr, nickname))
                    frame = ttk.Frame(files_inner_frame)
                    frame.pack(anchor="w", padx=5, pady=2)
                    chk = ttk.Checkbutton(frame, text=f"{nickname} - ", variable=var)
                    chk.pack(side=tk.LEFT)
                    addr_entry = ttk.Entry(frame, width=80)
                    addr_entry.insert(0, addr)
                    addr_entry.config(state="readonly")
                    addr_entry.pack(side=tk.LEFT)
                    add_context_menu(addr_entry)

            files_inner_frame.update_idletasks()
            files_canvas.configure(scrollregion=files_canvas.bbox("all"))

            manage_window.after(30000, lambda: refresh_content(query))

        files_frame = ttk.LabelFrame(manage_window, text="Private Data Files", padding=5)
        files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        files_canvas = tk.Canvas(files_frame)
        files_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
        files_inner_frame = ttk.Frame(files_canvas)
        files_canvas.configure(yscrollcommand=files_scrollbar.set)

        files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")

        check_vars = []

        refresh_content()

        buttons_frame = ttk.Frame(manage_window)
        buttons_frame.pack(fill=tk.X, pady=10)

        def remove_selected():
            selected_files = [(addr, nickname) for var, addr, nickname in check_vars if var.get()]
            if not selected_files:
                messagebox.showwarning("Selection Error", "Please select at least one file to remove.")
                return
            if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_files)} private files from the list? This won’t delete the data from the network."):
                for addr, nickname in selected_files:
                    for i, (a, n, is_private) in enumerate(self.local_archives):
                        if a == addr and n == nickname and is_private:
                            self.local_archives.pop(i)
                            break
                manage_window.destroy()

        ttk.Button(buttons_frame, text="Remove from List", command=remove_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Close", command=manage_window.destroy).pack(side=tk.LEFT, padx=5)

    async def _upload_public(self, file_path, from_queue=False):
        logger.info("Upload Public started for %s", file_path)
        self._current_operation = 'upload'
        self.status_label.config(text=f"Uploading file: {os.path.basename(file_path)}")
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            payment_option = PaymentOption.wallet(self.wallet)
            ant_balance = int(await self.wallet.balance())

            if ant_balance <= 0:
                self.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload. Add ANT to your wallet in the Wallet tab."))
                self.is_processing = False
                self.stop_status_animation()
                return

            chunk_price, chunk_addr = await asyncio.wait_for(
                self.client.data_put_public(file_data, payment_option),
                timeout=3000
            )
            logger.info("Chunk uploaded to address: %s for %s ANT", chunk_addr, chunk_price)

            file_name = os.path.basename(file_path)
            self.uploaded_files.append((file_name, chunk_addr))
            self.root.after(0, lambda: self._show_upload_success(chunk_addr, file_name, False))

        except asyncio.TimeoutError:
            self.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 3000 seconds. Check your network connection."))
            self.status_label.config(text="Upload timeout")
        except Exception as e:
            logger.error("Upload error: %s", e)
            self.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}\nCheck your ANT balance in the Wallet tab."))
            self.status_label.config(text="Upload failed")
        finally:
            if not from_queue:
                self.is_processing = False
                self.stop_status_animation()

    async def _upload_private(self, file_path, from_queue=False):
        logger.info("Upload Private started for %s", file_path)
        self._current_operation = 'upload'
        self.status_label.config(text=f"Uploading file: {os.path.basename(file_path)}")
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            payment_option = PaymentOption.wallet(self.wallet)
            ant_balance = int(await self.wallet.balance())

            if ant_balance > 0:
                result = await asyncio.wait_for(
                    self.client.data_put(file_data, payment_option),
                    timeout=1200
                )
                price, data_map_chunk = result
                access_token = data_map_chunk.to_hex()
                file_name = os.path.basename(file_path)
                self.local_archives.append((access_token, file_name, True))
                logger.info(f"Private data uploaded, price: {price}, access_token: {access_token}")
                self.root.after(0, lambda: self._show_upload_success(access_token, file_name, True))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload. Add ANT to your wallet in the Wallet tab."))
                self.is_processing = False
                self.stop_status_animation()

        except asyncio.TimeoutError:
            self.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 1200 seconds. Check your network connection."))
            self.status_label.config(text="Upload timeout")
        except Exception as e:
            logger.error("Upload error: %s", e)
            self.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}\nCheck your ANT balance in the Wallet tab."))
            self.status_label.config(text="Upload failed")
        finally:
            if not from_queue:
                self.is_processing = False
                self.stop_status_animation()

    def _show_upload_success(self, address, filename, is_private):
        success_window = tk.Toplevel(self.root)
        success_window.title(f"Upload Success - {filename}")
        success_window.geometry("400x200")
        success_window.transient(self.root)
        success_window.grab_set()

        frame = ttk.Frame(success_window)
        frame.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)

        ttk.Label(frame, text=f"{'Private Data Map' if is_private else 'Public Chunk Address'} for {filename}:").pack(anchor="w")
        addr_entry = ttk.Entry(frame, width=80)
        addr_entry.pack(fill=tk.X, pady=5)
        addr_entry.insert(0, address)
        addr_entry.config(state="readonly")
        add_context_menu(addr_entry)

        ttk.Label(frame, text="Use this address to retrieve your data. For public files, use 'Manage Public Files' to archive.").pack(anchor="w")

        def save_address():
            save_path = filedialog.asksaveasfilename(
                parent=success_window,
                initialdir=str(self.default_dir),
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title=f"Save {filename} Address"
            )
            if save_path:
                try:
                    with open(save_path, "w") as f:
                        f.write(address)
                    success_window.destroy()
                    messagebox.showinfo("Success", f"Address saved to {save_path}")
                except Exception as e:
                    logger.error("Failed to save address: %s", e)
                    messagebox.showerror("Error", f"Failed to save address: {e}")

        ttk.Button(success_window, text="Save", command=save_address).pack(pady=5)
        ttk.Button(success_window, text="Close", command=success_window.destroy).pack(pady=5)

    def retrieve_data(self):
        logger.info("Retrieve Data button clicked")
        self.status_label.config(text="Preparing retrieval...")
        address_input = self.retrieve_entry.get().strip()
        if not address_input or address_input == "Enter a data address (e.g., 0x123...)":
            messagebox.showwarning("Input Error", "Please enter a valid data address. It should be a long string of letters and numbers (e.g., 0x123...).")
            self.status_label.config(text="Ready")
            return

        self.is_processing = True
        self._current_operation = 'download'
        self.start_status_animation()
        
        async def _retrieve():
            try:
                data = None
                is_private = False
                archive = None
                is_single_chunk = False

                try:
                    data_map_chunk = DataMapChunk.from_hex(address_input)
                    data = await self.client.data_get(data_map_chunk)
                    is_private = True
                    logger.info("Successfully retrieved private data")
                except Exception as private_error:
                    logger.info("Not a private data map: %s", private_error)
                    try:
                        archive = await self.client.archive_get_public(address_input)
                        chunk_addr = list(archive.addresses())[0]
                        data = await self.client.data_get_public(chunk_addr)
                        is_private = False
                        logger.info("Successfully retrieved public archive")
                    except Exception as archive_error:
                        logger.info("Not a public archive: %s", archive_error)
                        try:
                            data = await self.client.data_get_public(address_input)
                            is_private = False
                            is_single_chunk = True
                            logger.info("Successfully retrieved single public chunk")
                        except Exception as chunk_error:
                            logger.error("Retrieval failed for all types: %s", chunk_error)
                            self.root.after(0, lambda: messagebox.showerror(
                                "Retrieval Failed",
                                "We couldn’t find your data. Make sure the address is correct and matches a private data map, public archive, or public chunk. Try copying it again."
                            ))
                            self.is_processing = False
                            self.stop_status_animation()
                            return

                def show_data_window():
                    view_window = tk.Toplevel(self.root)
                    view_window.title("Retrieved Data - Mission Ctrl")
                    view_window.geometry("650x450")
                    view_window.minsize(650, 450)
                    view_window.resizable(True, True)

                    top_frame = tk.Frame(view_window)
                    top_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

                    text = tk.Text(top_frame)
                    text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    scrollbar = tk.Scrollbar(top_frame, command=text.yview)
                    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                    text.config(yscrollcommand=scrollbar.set)
                    text.bind("<Key>", lambda e: "break")
                    add_context_menu(text)

                    if is_private:
                        text.insert(tk.END, "Retrieved Private Data:\n\n")
                        if data.startswith(b'\x89PNG') or data.startswith(b'\xff\xd8'):
                            try:
                                img = Image.open(io.BytesIO(data))
                                img.thumbnail((200, 200))
                                photo = ImageTk.PhotoImage(img)
                                text.image_create(tk.END, image=photo)
                                text.image_photos = getattr(text, 'image_photos', []) + [photo]
                                text.insert(tk.END, "\nPrivate Image\n")
                            except Exception as e:
                                logger.error("Failed to load image: %s", e)
                                text.insert(tk.END, f"Image Load Failed: {e}\n")
                        else:
                            try:
                                content = data.decode('utf-8')
                                text.insert(tk.END, f"Private Text:\n{content}\n\n")
                            except UnicodeDecodeError:
                                text.insert(tk.END, "Private Binary Data (Cannot Display)\n")
                    else:
                        if is_single_chunk:
                            text.insert(tk.END, "Retrieved Single Public Chunk:\n\n")
                            if data.startswith(b'\x89PNG') or data.startswith(b'\xff\xd8'):
                                try:
                                    img = Image.open(io.BytesIO(data))
                                    img.thumbnail((200, 200))
                                    photo = ImageTk.PhotoImage(img)
                                    text.image_create(tk.END, image=photo)
                                    text.image_photos = getattr(text, 'image_photos', []) + [photo]
                                    text.insert(tk.END, "\nPublic Image\n")
                                except Exception as e:
                                    logger.error("Failed to load image: %s", e)
                                    text.insert(tk.END, f"Image Load Failed: {e}\n")
                            else:
                                try:
                                    content = data.decode('utf-8')
                                    text.insert(tk.END, f"Public Text:\n{content}\n\n")
                                except UnicodeDecodeError:
                                    text.insert(tk.END, "Public Binary Data (Cannot Display)\n")
                        else:
                            text.insert(tk.END, "Retrieved Public Archive:\n\n")
                            file_list = list(archive.files())
                            if not file_list:
                                text.insert(tk.END, "No files found in archive.\n")
                            else:
                                text.insert(tk.END, "Files in Archive:\n")
                                chunk_addresses = list(archive.addresses())
                                file_names = [item[0] for item in file_list]
                                for name, addr in zip(file_names, chunk_addresses):
                                    text.insert(tk.END, f"- {name} (Address: {addr})\n")

                    button_frame = tk.Frame(view_window)
                    button_frame.pack(side=tk.BOTTOM, pady=5)

                    async def download_file(file_name, file_addr):
                        self.root.after(0, lambda: messagebox.showinfo("Download Started", f"Downloading {file_name}. Please wait..."))
                        self.is_processing = True
                        self._current_operation = 'download'
                        self.start_status_animation()
                        try:
                            file_data = await self.client.data_get_public(file_addr)
                            save_path = filedialog.asksaveasfilename(
                                parent=view_window,
                                initialfile=file_name,
                                initialdir=str(self.default_dir),
                                defaultextension=".bin",
                                filetypes=[("All files", "*.*")],
                                title=f"Save {file_name}"
                            )
                            if save_path:
                                with open(save_path, "wb") as f:
                                    f.write(file_data)
                                messagebox.showinfo("Success", f"File saved to {save_path}")
                        except Exception as ex:
                            logger.error("Failed to save file: %s", ex)
                            messagebox.showerror("Error", f"Failed to save file: {ex}")
                        finally:
                            self.is_processing = False
                            self.stop_status_animation()

                    def save_individual():
                        if is_private or is_single_chunk:
                            save_path = filedialog.asksaveasfilename(
                                parent=view_window,
                                initialdir=str(self.default_dir),
                                defaultextension=".bin",
                                filetypes=[("All files", "*.*")],
                                title="Save Retrieved Data"
                            )
                            if save_path:
                                try:
                                    with open(save_path, "wb") as f:
                                        f.write(data)
                                    messagebox.showinfo("Success", f"Data saved to {save_path}")
                                except Exception as ex:
                                    logger.error("Failed to save data: %s", ex)
                                    messagebox.showerror("Error", f"Failed to save data: {ex}")
                        else:
                            file_menu = tk.Menu(view_window, tearoff=0)
                            file_names = [item[0] for item in archive.files()]
                            chunk_addresses = list(archive.addresses())
                            for name, addr in zip(file_names, chunk_addresses):
                                file_menu.add_command(
                                    label=name,
                                    command=lambda n=name, a=addr: asyncio.run_coroutine_threadsafe(
                                        download_file(n, a), self.loop)
                                )
                            file_menu.tk_popup(button_frame.winfo_rootx(), button_frame.winfo_rooty())

                    async def save_all():
                        save_path = filedialog.askdirectory(
                            parent=view_window,
                            initialdir=str(self.default_dir),
                            title="Select Directory to Save All Files"
                        )
                        if save_path:
                            self.root.after(0, lambda: messagebox.showinfo("Download Started", "Downloading all files. Please wait..."))
                            self.is_processing = True
                            self._current_operation = 'download'
                            self.start_status_animation()
                            try:
                                file_list = list(archive.files())
                                chunk_addresses = list(archive.addresses())
                                file_names = [item[0] for item in file_list]
                                
                                if len(file_names) != len(chunk_addresses):
                                    raise ValueError("Mismatch between file names and chunk addresses")
                                
                                for name, addr in zip(file_names, chunk_addresses):
                                    file_data = await self.client.data_get_public(addr)
                                    file_path = os.path.join(save_path, name)
                                    with open(file_path, "wb") as f:
                                        f.write(file_data)
                                    logger.info(f"Saved {name} to {file_path}")
                                
                                self.root.after(0, lambda: messagebox.showinfo(
                                    "Success", f"All {len(file_names)} files saved to {save_path}"))
                            except Exception as ex:
                                logger.error("Failed to save all files: %s", ex)
                                self.root.after(0, lambda: messagebox.showerror(
                                    "Error", f"Failed to save all files: {ex}"))
                            finally:
                                self.is_processing = False
                                self.stop_status_animation()

                    tk.Button(button_frame, text="Save" if (is_private or is_single_chunk) else "Save File",
                            command=save_individual).pack(side=tk.LEFT, padx=5)
                    if not is_private and archive and not is_single_chunk:
                        tk.Button(button_frame, text="Save All",
                                command=lambda: asyncio.run_coroutine_threadsafe(save_all(), self.loop)
                                ).pack(side=tk.LEFT, padx=5)
                    tk.Button(button_frame, text="Close", command=view_window.destroy).pack(side=tk.LEFT, padx=5)

                self.root.after(0, show_data_window)

            except Exception as e:
                logger.error("Retrieval failed: %s", e)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Retrieval failed: {e}\nCheck your network connection or the address."))
            finally:
                self.is_processing = False
                self.stop_status_animation()

        asyncio.run_coroutine_threadsafe(_retrieve(), self.loop)

    async def initialize_client(self):
        try:
            network = Network(False)
            self.status_label.config(text="Initializing network connection")
            self.client = await Client.init()
            logger.info("Connected to Autonomi network")
            self.root.after(0, lambda: self.connection_label.config(
                text="Network: Connected"))
            self.status_label.config(text="Network connection established")
            
            def on_wallet_loaded(success):
                if not success:
                    logger.info("No valid wallet loaded")
                    self.status_label.config(text="No wallet loaded")
                    self.show_wallet_setup_wizard()
            
            if os.path.exists(self.wallet_file):
                self.show_wallet_password_prompt(on_wallet_loaded)
            else:
                on_wallet_loaded(False)
                
            await self._update_balances()
        except Exception as e:
            logger.error("Initialization failed: %s", e)
            self.root.after(0, lambda: self.connection_label.config(
                text=f"Network: Failed ({str(e)})"))
            self.status_label.config(text="Network connection failed")

    def show_wallet_setup_wizard(self):
        wizard_window = tk.Toplevel(self.root)
        wizard_window.title("Welcome to Mission Ctrl - Wallet Setup")
        wizard_window.geometry("400x300")
        wizard_window.resizable(False, False)
        wizard_window.transient(self.root)
        wizard_window.grab_set()

        tk.Label(wizard_window, text="Welcome! You need a wallet to use Mission Ctrl.", wraplength=350).pack(pady=10)
        tk.Label(wizard_window, text="A wallet stores your funds (ETH and ANT) and pays for uploads.", wraplength=350).pack(pady=5)
        tk.Label(wizard_window, text="Choose an option to get started:", wraplength=350).pack(pady=5)

        tk.Button(wizard_window, text="Create a New Wallet", command=lambda: [wizard_window.destroy(), self.create_wallet()]).pack(pady=5)
        tk.Button(wizard_window, text="Import an Existing Wallet", command=lambda: [wizard_window.destroy(), self.import_wallet()]).pack(pady=5)
        tk.Button(wizard_window, text="Learn More", command=self.show_help).pack(pady=5)

    async def _update_balances(self):
        if not self.wallet:
            self.root.after(0, lambda: self.ant_balance_label.config(
                text="ANT Balance: Not Connected"))
            self.root.after(0, lambda: self.eth_balance_label.config(
                text="ETH Balance: Not Connected"))
            return
        try:
            self.status_label.config(text="Fetching wallet balances")
            ant_balance = int(await self.wallet.balance())
            ant_formatted = ant_balance / 10**18
            
            eth_balance = self.w3.eth.get_balance(self.wallet.address())
            eth_formatted = self.w3.from_wei(eth_balance, 'ether')
            
            self.root.after(0, lambda: self.ant_balance_label.config(
                text=f"ANT Balance: {ant_formatted}"))
            self.root.after(0, lambda: self.eth_balance_label.config(
                text=f"ETH Balance: {eth_formatted:.6f}"))
            
            logger.info("Balances updated - ANT: %s, ETH: %s", 
                       ant_formatted, eth_formatted)
            self.status_label.config(text="Ready")
        except Exception as e:
            logger.error("Failed to update balances: %s", e)
            self.root.after(0, lambda: self.ant_balance_label.config(
                text="ANT Balance: Error"))
            self.root.after(0, lambda: self.eth_balance_label.config(
                text="ETH Balance: Error"))
            self.status_label.config(text="Balance fetch failed")

    def update_balances(self):
        self.status_label.config(text="Requesting balance update")
        asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
        self.root.after(60000, self.update_balances)

    def get_encryption_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_wallet(self, private_key, password):
        key, salt = self.get_encryption_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(private_key.encode())
        with open(self.wallet_file, 'wb') as f:
            f.write(salt + encrypted)

    def decrypt_wallet(self, password):
        try:
            with open(self.wallet_file, 'rb') as f:
                data = f.read()
            salt = data[:16]
            encrypted = data[16:]
            fernet = Fernet(self.get_encryption_key(password, salt)[0])
            return fernet.decrypt(encrypted).decode()
        except Exception:
            return None

    def show_wallet_password_prompt(self, callback):
        if not os.path.exists(self.wallet_file):
            callback(False)
            return
            
        password_window = tk.Toplevel(self.root)
        password_window.title("Wallet Password")
        password_window.geometry("300x150")
        
        tk.Label(password_window, text="Enter wallet password:").pack(pady=5)
        pw_entry = tk.Entry(password_window, show="*", width=30)
        pw_entry.pack(pady=5)
        add_context_menu(pw_entry)
        
        def try_load():
            password = pw_entry.get()
            private_key = self.decrypt_wallet(password)
            if private_key:
                try:
                    self.wallet = Wallet(private_key)
                    self.wallet_address_label.config(text=f"Wallet: {self.wallet.address()}")
                    asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
                    callback(True)
                    password_window.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Invalid wallet data: {str(e)}")
                    callback(False)
            else:
                messagebox.showerror("Error", "Incorrect password")
                callback(False)
        
        tk.Button(password_window, text="Unlock", command=try_load).pack(pady=5)

    def delete_wallet(self, wallet_window=None):
        if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete your wallet? You’ll need your private key to recover it later."):
            self.wallet = None
            if os.path.exists(self.wallet_file):
                os.remove(self.wallet_file)
            self.wallet_address_label.config(text="Wallet: Not Connected")
            self.ant_balance_label.config(text="ANT Balance: Not Connected")
            self.eth_balance_label.config(text="ETH Balance: Not Connected")
            messagebox.showinfo("Success", "Wallet deleted successfully")
            self.status_label.config(text="Wallet deleted")
        if wallet_window is not None:
            wallet_window.destroy()

    def import_wallet(self, wallet_window=None):
        import_window = tk.Toplevel(self.root)
        import_window.title("Import Wallet")
        import_window.geometry("400x200")
        
        tk.Label(import_window, text="Enter Private Key:").pack(pady=5)
        pk_entry = tk.Entry(import_window, width=50, show="*")
        pk_entry.pack(pady=5)
        add_context_menu(pk_entry)
        
        tk.Label(import_window, text="Set Password:").pack(pady=5)
        pw_entry = tk.Entry(import_window, width=30, show="*")
        pw_entry.pack(pady=5)
        add_context_menu(pw_entry)
        
        def do_import():
            private_key = pk_entry.get().strip()
            password = pw_entry.get()
            if not password:
                messagebox.showerror("Error", "Password is required")
                return
            try:
                self.wallet = Wallet(private_key)
                self.encrypt_wallet(private_key, password)
                self.wallet_address_label.config(text=f"Wallet: {self.wallet.address()}")
                asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
                messagebox.showinfo("Success", "Wallet imported successfully")
                self.status_label.config(text="Wallet imported")
                import_window.destroy()
                if wallet_window is not None:
                    wallet_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Invalid private key: {str(e)}")
        
        tk.Button(import_window, text="Import", command=do_import).pack(pady=5)

    def create_wallet(self, wallet_window=None):
        password_window = tk.Toplevel(self.root)
        password_window.title("Set Wallet Password")
        password_window.geometry("300x150")
        
        tk.Label(password_window, text="Set wallet password:").pack(pady=5)
        pw_entry = tk.Entry(password_window, show="*", width=30)
        pw_entry.pack(pady=5)
        add_context_menu(pw_entry)
        
        def do_create():
            password = pw_entry.get()
            if not password:
                messagebox.showerror("Error", "Password is required")
                return
            try:
                new_account = self.w3.eth.account.create()
                private_key = new_account.key.hex()
                self.wallet = Wallet(private_key)
                self.encrypt_wallet(private_key, password)
                self.wallet_address_label.config(text=f"Wallet: {self.wallet.address()}")
                asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
                self._show_wallet_created_info(self.wallet.address(), private_key[:8] + "..." + private_key[-8:])
                self.status_label.config(text="Wallet created")
                password_window.destroy()
                if wallet_window is not None:
                    wallet_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create wallet: {str(e)}")
        
        tk.Button(password_window, text="Create", command=do_create).pack(pady=5)

    def send_funds(self, wallet_window=None):
        if not self.wallet:
            messagebox.showerror("Error", "No wallet loaded")
            return

        send_window = tk.Toplevel(self.root)
        send_window.title("Send Funds")
        send_window.geometry("400x250")

        ttk.Label(send_window, text="Recipient Address:").pack(pady=5)
        addr_entry = ttk.Entry(send_window, width=50)
        addr_entry.pack(pady=5)
        add_context_menu(addr_entry)

        ttk.Label(send_window, text="Amount:").pack(pady=5)
        amount_entry = ttk.Entry(send_window)
        amount_entry.pack(pady=5)
        add_context_menu(amount_entry)

        currency_var = tk.StringVar(value="ETH")
        ttk.Radiobutton(send_window, text="ETH", variable=currency_var, value="ETH").pack(pady=2)
        ttk.Radiobutton(send_window, text="ANT", variable=currency_var, value="ANT").pack(pady=2)

        async def do_send():
            recipient = addr_entry.get().strip()
            amount_str = amount_entry.get().strip()
            currency = currency_var.get()

            if not self.w3.is_address(recipient):
                self.root.after(0, lambda: messagebox.showerror("Error", "Invalid recipient address. It should start with '0x' and be 42 characters long."))
                return
            
            try:
                amount = float(amount_str)
                if amount <= 0:
                    raise ValueError("Amount must be positive")
            except ValueError:
                self.root.after(0, lambda: messagebox.showerror("Error", "Invalid amount. Enter a positive number (e.g., 0.1)."))
                return

            if not messagebox.askyesno("Confirm Send", f"Send {amount} {currency} to {recipient[:8]}...? This cannot be undone."):
                return

            password = self._prompt_password("Enter password to sign transaction:")
            if not password:
                return
            private_key = self.decrypt_wallet(password)
            if not private_key:
                self.root.after(0, lambda: messagebox.showerror("Error", "Incorrect password"))
                return

            self.is_processing = True
            self.start_status_animation()
            try:
                if currency == "ETH":
                    tx = {
                        'to': recipient,
                        'value': self.w3.to_wei(amount, 'ether'),
                        'gas': 25000,
                        'gasPrice': self.w3.eth.gas_price,
                        'nonce': self.w3.eth.get_transaction_count(self.wallet.address()),
                        'chainId': 42161
                    }
                    signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
                    tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                else:
                    ant_contract = self.w3.eth.contract(address=ANT_TOKEN_ADDRESS, abi=ANT_ABI)
                    try:
                        ant_balance = ant_contract.functions.balanceOf(self.wallet.address()).call() / 10**18
                    except Exception as e:
                        raise ValueError(f"Failed to get ANT balance: {str(e)}")

                    if amount > ant_balance:
                        raise ValueError(f"Insufficient ANT balance: {ant_balance} available")

                    amount_wei = int(amount * 10**18)
                    gas_estimate = ant_contract.functions.transfer(
                        recipient,
                        amount_wei
                    ).estimate_gas({'from': self.wallet.address()})

                    tx = ant_contract.functions.transfer(
                        recipient,
                        amount_wei
                    ).build_transaction({
                        'from': self.wallet.address(),
                        'gas': int(gas_estimate * 1.5),
                        'gasPrice': self.w3.eth.gas_price,
                        'nonce': self.w3.eth.get_transaction_count(self.wallet.address()),
                        'chainId': 42161
                    })
                    signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
                    tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

                self.root.after(0, lambda h=tx_hash: messagebox.showinfo(
                    "Success", f"Sent {amount} {currency} - Tx Hash: {h.hex()}"))
                asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
                send_window.destroy()
                if wallet_window:
                    wallet_window.destroy()
                self.status_label.config(text=f"Sent {currency}")

            except Exception as e:
                error_msg = str(e)
                logger.error(f"Send {currency} failed: {error_msg}")
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"Send failed: {msg}\nCheck your {currency} balance in the Wallet tab."))
            finally:
                if 'private_key' in locals():
                    private_key = bytearray(private_key.encode())
                    for i in range(len(private_key)):
                        private_key[i] = 0
                self.is_processing = False
                self.stop_status_animation()

        ttk.Button(send_window, text="Send", command=lambda: asyncio.run_coroutine_threadsafe(do_send(), self.loop)).pack(pady=10)

    def _prompt_password(self, message):
        password_window = tk.Toplevel(self.root)
        password_window.title("Password Required")
        password_window.geometry("300x150")
        
        tk.Label(password_window, text=message).pack(pady=5)
        pw_entry = tk.Entry(password_window, show="*", width=30)
        pw_entry.pack(pady=5)
        add_context_menu(pw_entry)
        
        password = [None]
        def on_submit():
            password[0] = pw_entry.get()
            password_window.destroy()
        
        tk.Button(password_window, text="Submit", command=on_submit).pack(pady=5)
        password_window.wait_window()
        return password[0]

    def _show_wallet_created_info(self, address, pk_display):
        info_window = tk.Toplevel(self.root)
        info_window.title("New Wallet Info")
        info_window.geometry("400x250")
        
        text = tk.Text(info_window, height=8, width=50)
        text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
        text.insert(tk.END, f"Address: {address}\n")
        text.insert(tk.END, f"Private Key (partial): {pk_display}\n\n")
        text.insert(tk.END, "Please save your private key securely!\n")
        text.insert(tk.END, "Check the box below once you have saved it.")
        text.bind("<Key>", lambda e: "break")
        add_context_menu(text)
        
        var = tk.BooleanVar(value=False)
        
        def on_check():
            if var.get():
                close_button.config(state="normal")
            else:
                close_button.config(state="disabled")
        
        check = tk.Checkbutton(info_window, text="I have saved my private key", variable=var, command=on_check)
        check.pack(pady=5)
        
        close_button = tk.Button(info_window, text="Close", command=info_window.destroy, state="disabled")
        close_button.pack(pady=5)

    def show_wallet_options(self):
        wallet_window = tk.Toplevel(self.root)
        wallet_window.title("Wallet Options")
        wallet_window.geometry("300x250")
        
        tk.Button(wallet_window, text="Delete Current Wallet",
                  command=lambda: self.delete_wallet(wallet_window)).pack(pady=5)
        
        tk.Button(wallet_window, text="Import Wallet (Private Key)",
                  command=lambda: self.import_wallet(wallet_window)).pack(pady=5)
        
        tk.Button(wallet_window, text="Create New Wallet",
                  command=lambda: self.create_wallet(wallet_window)).pack(pady=5)
        
        tk.Button(wallet_window, text="Send Funds",
                  command=lambda: self.send_funds(wallet_window)).pack(pady=5)

        def copy_wallet_address():
            if self.wallet:
                self.root.clipboard_clear()
                self.root.clipboard_append(self.wallet.address())
                messagebox.showinfo("Success", "Wallet address copied to clipboard!")
            else:
                messagebox.showerror("Error", "No wallet loaded to copy address from.")
        
        tk.Button(wallet_window, text="Copy Wallet Address",
                  command=copy_wallet_address).pack(pady=5)
        
        tk.Button(wallet_window, text="Close",
                  command=wallet_window.destroy).pack(pady=5)

if __name__ == "__main__":
    app = TestApp()
    app.root.mainloop()