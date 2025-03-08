import asyncio
import json
import logging
import os
import threading
from pathlib import Path
from web3 import Web3
from autonomi_client import Client, Network, Wallet
import public
import private
import gui
import wallet
import view
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, Toplevel

logger = logging.getLogger("MissionCtrl")

class TestApp:
    def __init__(self):
        # Initialize attributes
        self.loop = None
        self.client = None
        self.wallet = None
        self.uploaded_files = []
        self.uploaded_private_files = []
        self.local_archives = []
        self.w3 = Web3(Web3.HTTPProvider('https://arb1.arbitrum.io/rpc'))
        import platform
        from pathlib import Path
        if platform.system() == "Linux":
            self.default_dir = Path(os.path.expanduser("~/.local/share/missionctrl"))
        else:
            self.default_dir = Path(os.path.expanduser("~/Documents/missionctrl"))
        self.default_dir.mkdir(parents=True, exist_ok=True)
        self.wallet_file = str(self.default_dir / "wallet.enc")
        self.data_file = str(self.default_dir / "mission_control_data.json")
        self.upload_queue = []
        self.status_dots = ["", ".", "..", "..."]
        self.current_dot_idx = 0
        self.status_update_task = None
        self._current_operation = None
        self.is_processing = False

        # Show warning before creating the root window
        if not messagebox.askokcancel(
            "Warning",
            "WARNING: Only send or import small amounts of funds. "
            "The app developer makes no guarantees that your funds will not be lost. Do you agree?"
        ):
            raise SystemExit("User declined the warning.")

        # Create the root window and set up the event loop
        self.root = tk.Tk()
        self.root.title("Mission Ctrl")
        self.root.withdraw()  # Hide initially
        self.is_public_var = tk.BooleanVar(master=self.root, value=False)
        self.is_private_var = tk.BooleanVar(master=self.root, value=False)
        self.perform_cost_calc_var = tk.BooleanVar(master=self.root, value=True)
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.initialize_app()

    def on_closing(self):
        self.save_persistent_data()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.root.destroy()
        logger.info("Closing window...")

    def initialize_app(self):
        self.load_persistent_data()
        asyncio.run_coroutine_threadsafe(self.init_client(), self.loop)
        self.root.after(100, self.check_client_connection)
        self.root.after(1000, self.update_balances)
        self.root.after(1000, self.start_status_update)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        gui.setup_main_gui(self)
        self.root.deiconify()

    async def init_client(self):
        self.client = await Client.init()
        self.connection_label.config(text="Network: Initializing...")
        logger.info("Client initialized: %s", self.client)
        if os.path.exists(self.wallet_file):
            self.root.after(0, self._schedule_wallet_prompt)
        else:
            self.wallet_address_label.config(text="Wallet: Not Created")
            logger.info("No wallet file found at %s", self.wallet_file)
        self.connection_label.config(text="Network: Connected to Autonomi")

    def _schedule_wallet_prompt(self):
        logger.info("Scheduling wallet password prompt")
        logger.info("Wallet file exists: %s", os.path.exists(self.wallet_file))
        def on_wallet_loaded(success):
            if not success:
                logger.info("No valid wallet loaded, prompting for wallet setup")
                self.show_wallet_setup_wizard()
        wallet.show_wallet_password_prompt(self, on_wallet_loaded)

    def show_wallet_setup_wizard(self):
        logger.info("Showing wallet setup wizard")
        wizard_window = Toplevel(self.root)
        wizard_window.title("Welcome to Mission Ctrl - Wallet Setup")
        wizard_window.geometry("400x300")
        wizard_window.minsize(400, 300)
        wizard_window.resizable(False, False)
        wizard_window.transient(self.root)
        wizard_window.grab_set()

        tk.Label(wizard_window, text="Welcome! You need a wallet to use Mission Ctrl.", wraplength=350).pack(pady=10)
        tk.Label(wizard_window, text="A wallet stores your funds (ETH and ANT) and pays for uploads.", wraplength=350).pack(pady=5)
        tk.Label(wizard_window, text="Choose an option to get started:", wraplength=350).pack(pady=5)

        tk.Button(wizard_window, text="Create a New Wallet", command=lambda: [wizard_window.destroy(), wallet.create_wallet(self)]).pack(pady=5)
        tk.Button(wizard_window, text="Import an Existing Wallet", command=lambda: [wizard_window.destroy(), wallet.import_wallet(self)]).pack(pady=5)
        tk.Button(wizard_window, text="Learn More", command=lambda: gui.show_help(self)).pack(pady=5)

    def check_client_connection(self):
        if self.client:
            self.connection_label.config(text="Network: Connected to Autonomi")
        else:
            self.connection_label.config(text="Network: Disconnected")
        self.root.after(5000, self.check_client_connection)

    def update_balances(self):
        if self.wallet:
            asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
        self.root.after(120000, self.update_balances)

    async def _update_balances(self):
        ant_balance = int(await self.wallet.balance())
        eth_balance = self.w3.eth.get_balance(self.wallet.address())
        self.ant_balance_label.config(text=f"ANT Balance: {ant_balance / 10**18:.6f}")
        self.eth_balance_label.config(text=f"ETH Balance: {eth_balance / 10**18:.6f}")
        logger.info("Balances updated - ANT: %s, ETH: %s", ant_balance / 10**18, eth_balance / 10**18)

    def upload_file(self):
        from tkinter import filedialog, messagebox, Toplevel, ttk, StringVar
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

        # Custom dialog for choosing upload type
        choice_window = Toplevel(self.root)
        choice_window.title("Upload Type")
        choice_window.geometry("300x150")
        choice_window.transient(self.root)
        choice_window.grab_set()

        choice_var = StringVar(value="files")
        ttk.Label(choice_window, text="Select upload type:").pack(pady=10)
        ttk.Radiobutton(choice_window, text="Files", variable=choice_var, value="files").pack(anchor="w", padx=20, pady=5)
        ttk.Radiobutton(choice_window, text="Directory", variable=choice_var, value="directory").pack(anchor="w", padx=20, pady=5)

        def on_ok():
            choice_window.destroy()
            initial_dir = os.path.expanduser("~")

            if choice_var.get() == "files":
                file_paths = filedialog.askopenfilenames(
                    title="Select Files to Upload",
                    filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")],
                    initialdir=initial_dir
                )
                if not file_paths:
                    self.status_label.config(text="Ready")
                    return
                paths_to_upload = file_paths
            else:
                dir_path = filedialog.askdirectory(
                    title="Select Directory to Upload",
                    initialdir=initial_dir
                )
                if not dir_path:
                    self.status_label.config(text="Ready")
                    return
                paths_to_upload = [dir_path]

            self.is_processing = True
            self._current_operation = 'cost_calc' if self.perform_cost_calc_var.get() else 'upload'

            for path in paths_to_upload:
                if os.path.isdir(path):
                    self.status_label.config(text=f"{'Getting upload cost quote, please wait...' if self.perform_cost_calc_var.get() else 'Uploading directory'} {os.path.basename(path)}")
                    if public_selected:
                        asyncio.run_coroutine_threadsafe(public.upload_public_directory(self, path), self.loop)
                    elif private_selected:
                        asyncio.run_coroutine_threadsafe(private.upload_private_directory(self, path), self.loop)
                else:
                    self.status_label.config(text=f"{'Getting upload cost quote, please wait...' if self.perform_cost_calc_var.get() else 'Uploading file'} {os.path.basename(path)}")
                    if public_selected:
                        asyncio.run_coroutine_threadsafe(public.upload_public(self, path), self.loop)
                    elif private_selected:
                        asyncio.run_coroutine_threadsafe(private.upload_private(self, path), self.loop)

            self.is_processing = False 
            self.stop_status_animation()
            self.status_label.config(text="Upload(s) scheduled")

        ttk.Button(choice_window, text="OK", command=on_ok).pack(pady=10)
        choice_window.protocol("WM_DELETE_WINDOW", lambda: [choice_window.destroy(), self.status_label.config(text="Ready")])

    def add_to_upload_queue(self):
        from tkinter import filedialog, messagebox
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
            filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")],
            initialdir=os.path.expanduser("~")
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

    def start_upload_queue(self):
        from tkinter import messagebox
        if not self.upload_queue:
            messagebox.showinfo("Queue Empty", "No files in the upload queue.")
            return
        if not getattr(self, "is_processing", False):
            if messagebox.askyesno("Confirm Upload", f"Start uploading {len(self.upload_queue)} files now? This will use ANT from your wallet."):
                self.is_processing = True
                self._current_operation = 'upload'
                self.start_status_animation()
                asyncio.run_coroutine_threadsafe(self.process_upload_queue(), self.loop)

    async def process_upload_queue(self):
        total_files = len(self.upload_queue)
        while self.upload_queue and getattr(self, "is_processing", False):
            upload_type, file_path = self.upload_queue[0]
            self.root.after(0, lambda: self.status_label.config(text=f"Uploading file 1 of {total_files}: {os.path.basename(file_path)}"))
            if upload_type == "public":
                await public.upload_public(self, file_path, from_queue=True)
            else:
                await private.upload_private(self, file_path, from_queue=True)
            if self.upload_queue:
                self.upload_queue.pop(0)
                self.queue_listbox.delete(0)
                self.root.after(0, lambda: self.queue_label.config(text=f"Queue: {len(self.upload_queue)} files"))
                self.root.after(0, lambda: self.status_label.config(text=f"Completed file {total_files - len(self.upload_queue)} of {total_files}"))
        self.is_processing = False
        self.stop_status_animation()
        self.root.after(0, lambda: self.status_label.config(text="Queue processing completed"))

    def remove_from_queue(self):
        from tkinter import messagebox
        selected = self.queue_listbox.curselection()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select at least one item to remove from the queue.")
            return
        for index in sorted(selected, reverse=True):
            self.upload_queue.pop(index)
            self.queue_listbox.delete(index)
        self.queue_label.config(text=f"Queue: {len(self.upload_queue)} files")
        self.status_label.config(text=f"Removed {len(selected)} items from queue")

    def manage_public_files(self):
        public.manage_public_files(self)

    def manage_private_files(self):
        private.manage_private_files(self)

    def retrieve_data(self):
        from get import retrieve_data
        retrieve_data(self)

    def show_wallet_options(self):
        wallet_window = Toplevel(self.root)
        wallet_window.title("Wallet Options")
        wallet_window.geometry("300x250")
        tk.Button(wallet_window, text="Delete Current Wallet",
                  command=lambda: wallet.delete_wallet(self, wallet_window)).pack(pady=5)
        tk.Button(wallet_window, text="Import Wallet (Private Key)",
                  command=lambda: wallet.import_wallet(self, wallet_window)).pack(pady=5)
        tk.Button(wallet_window, text="Create New Wallet",
                  command=lambda: wallet.create_wallet(self, wallet_window)).pack(pady=5)
        tk.Button(wallet_window, text="Send Funds",
                  command=lambda: wallet.send_funds(self, wallet_window)).pack(pady=5)
        def copy_wallet_address():
            if self.wallet:
                self.root.clipboard_clear()
                self.root.clipboard_append(self.wallet.address())
                from tkinter import messagebox
                messagebox.showinfo("Success", "Wallet address copied to clipboard!")
            else:
                from tkinter import messagebox
                messagebox.showerror("Error", "No wallet loaded to copy address from.")
        tk.Button(wallet_window, text="Copy Wallet Address",
                  command=copy_wallet_address).pack(pady=5)
        tk.Button(wallet_window, text="Close",
                  command=wallet_window.destroy).pack(pady=5)

    def view_archive_file(self, addr, name):
        view.view_file(self, addr, name)

    def start_status_update(self):
        if self.status_update_task:
            self.root.after_cancel(self.status_update_task)
        self.status_update_task = self.root.after(500, self.update_status)

    def update_status(self):
        if self.is_processing:
            self.status_label.config(text=f"{self.status_dots[self.current_dot_idx]} {self._current_operation_message()} {self.status_dots[self.current_dot_idx]}")
            self.current_dot_idx = (self.current_dot_idx + 1) % len(self.status_dots)
        self.start_status_update()

    def _current_operation_message(self):
        if self._current_operation == 'upload':
            return "Uploading files"
        elif self._current_operation == 'cost_calc':
            return "Getting upload cost quote, please wait"
        elif self._current_operation == 'archive':
            return "Archiving files"
        elif self._current_operation == 'download':
            return "Downloading data"
        return "Processing"

    def stop_status_animation(self):
        if self.status_update_task:
            self.root.after_cancel(self.status_update_task)
            self.status_update_task = None
            self.current_dot_idx = 0
            self.status_label.config(text="Ready")

    def start_status_animation(self):
        if not self.status_update_task:
            self.start_status_update()

    def _show_upload_success(self, address, filename, is_private):
        from tkinter import messagebox
        messagebox.showinfo("Success", f"Uploaded {filename} to address: {address[:10]}... ({'Private' if is_private else 'Public'})")
        self.status_label.config(text="Upload successful")

    def load_persistent_data(self):
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                self.uploaded_files = [(item["filename"], item["chunk_addr"]) for item in data.get("uploaded_files", [])]
                self.local_archives = [(item["addr"], item["nickname"], item["is_private"]) for item in data.get("local_archives", [])]
                self.upload_queue = [(item["type"], item["path"]) for item in data.get("upload_queue", [])]
                self.uploaded_private_files = [(item["filename"], item["access_token"]) for item in data.get("uploaded_private_files", [])]
                logger.info("Loaded persistent data from %s", self.data_file)
        except Exception as e:
            logger.error("Failed to load persistent data: %s", e)
            self.uploaded_files = []
            self.local_archives = []
            self.upload_queue = []
            self.uploaded_private_files = []

    def save_persistent_data(self):
        try:
            data = {
                "uploaded_files": [{"filename": f, "chunk_addr": a} for f, a in self.uploaded_files],
                "local_archives": [{"addr": a, "nickname": n, "is_private": p} for a, n, p in self.local_archives],
                "upload_queue": [{"type": t, "path": p} for t, p in self.upload_queue],
                "uploaded_private_files": [{"filename": f, "access_token": a} for f, a in self.uploaded_private_files]
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info("Saved persistent data to %s", self.data_file)
        except Exception as e:
            logger.error("Failed to save persistent data: %s", e)

TestApp._view_archive_file = view.view_file

if __name__ == "__main__":
    app = TestApp()
    app.root.mainloop()