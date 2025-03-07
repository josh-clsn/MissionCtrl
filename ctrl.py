# ctrl.py
import sys
import tkinter as tk
import asyncio
import os
import threading
import logging
import json
import platform
from pathlib import Path
from web3 import Web3
from tkinter import ttk, filedialog, messagebox

# Import our modules
import gui
import wallet
import public
import private
import get
import view

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

class TestApp:
    def __init__(self):
        self.loop = None
        self.client = None
        self.wallet = None
        self.uploaded_files = []      
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

        # Show warning before creating the root window
        from tkinter import messagebox, Tk
        if not messagebox.askokcancel(
            "Warning",
            "WARNING: Only send or import small amounts of funds. "
            "The app developer makes no guarantees that your funds will not be lost. Do you agree?"
        ):
            raise SystemExit("User declined the warning.")

        # Create the root window and set up the event loop
        self.root = Tk()
        self.root.withdraw()
        self.is_public_var = tk.BooleanVar(master=self.root, value=False)
        self.is_private_var = tk.BooleanVar(master=self.root, value=False)
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.initialize_app()

    def initialize_app(self):
        os.environ.setdefault("EVM_NETWORK", "arbitrum-one")
        
        # Configure the root window
        self.root.title("Mission Ctrl")
        self.root.geometry("630x550")
        self.root.configure(bg="#f0f2f5")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Load persistent data
        self.load_persistent_data()

        # Setup the GUI (delegated to gui.py)
        gui.setup_main_gui(self)

        # Initialize client asynchronously
        logger.info("Scheduling client initialization")
        asyncio.run_coroutine_threadsafe(self.initialize_client(), self.loop)
        
        # Schedule the first balance update
        self.root.after(1000, self.update_balances)

        # Show the main window
        self.root.deiconify()

    def start_status_animation(self):
        if self.status_update_task is None:
            def update_status():
                if getattr(self, "is_processing", False):
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
        
        # Schedule cleanup of the event loop asynchronously
        def schedule_cleanup():
            if self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self._cleanup_loop(), self.loop)
        
        self.root.after(0, schedule_cleanup)
        self.root.destroy()

    async def _cleanup_loop(self):
        logger.info("Cleaning up event loop")
        # Cancel all pending tasks
        tasks = [task for task in asyncio.all_tasks(self.loop) if task is not asyncio.current_task(self.loop)]
        for task in tasks:
            task.cancel()
        # Wait for tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        # Shutdown async generators
        await self.loop.shutdown_asyncgens()
        # Close the loop
        self.loop.close()

    def update_balances(self):
        if not hasattr(self, 'ant_balance_label') or not self.ant_balance_label.winfo_exists():
            logger.info("Skipping balance update: GUI not ready")
            return  # Skip if GUI elements are not yet initialized
        self.status_label.config(text="Requesting balance update")
        asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
        self.root.after(60000, self.update_balances) 

    async def _update_balances(self):
        if not self.wallet:
            self.ant_balance_label.config(text="ANT Balance: Not Connected")
            self.eth_balance_label.config(text="ETH Balance: Not Connected")
            return
        try:
            self.status_label.config(text="Fetching wallet balances")
            ant_balance = int(await self.wallet.balance())
            ant_formatted = ant_balance / 10**18
            eth_balance = self.w3.eth.get_balance(self.wallet.address())
            eth_formatted = self.w3.from_wei(eth_balance, 'ether')
            self.ant_balance_label.config(text=f"ANT Balance: {ant_formatted}")
            self.eth_balance_label.config(text=f"ETH Balance: {eth_formatted:.6f}")
            logger.info("Balances updated - ANT: %s, ETH: %s", ant_formatted, eth_formatted)
            self.status_label.config(text="Ready")
        except Exception as e:
            logger.error("Failed to update balances: %s", e)
            self.ant_balance_label.config(text="ANT Balance: Error")
            self.eth_balance_label.config(text="ETH Balance: Error")
            self.status_label.config(text="Balance fetch failed")

    async def initialize_client(self):
        try:
            from autonomi_client import Client, Network
            network = Network(False)
            self.status_label.config(text="Initializing network connection")
            self.client = await Client.init()
            logger.info("Connected to Autonomi network")
            self.connection_label.config(text="Network: Connected")
            self.status_label.config(text="Network connection established")
            
            # Schedule wallet prompt with a delay to ensure GUI is ready
            self.root.after(1000, self._schedule_wallet_prompt)
            
            await self._update_balances()
        except Exception as e:
            logger.error("Initialization failed: %s", e)
            self.connection_label.config(text=f"Network: Failed ({str(e)})")
            self.status_label.config(text="Network connection failed")

    def _schedule_wallet_prompt(self):
        logger.info("Scheduling wallet password prompt")
        logger.info("Wallet file exists: %s", os.path.exists(self.wallet_file))
        if os.path.exists(self.wallet_file):
            def on_wallet_loaded(success):
                if not success:
                    logger.info("No valid wallet loaded")
                    self.status_label.config(text="No wallet loaded")
                    self.show_wallet_setup_wizard()
            wallet.show_wallet_password_prompt(self, on_wallet_loaded)
        else:
            logger.info("No wallet file found, skipping prompt")
            def on_wallet_loaded(success):
                if not success:
                    logger.info("No valid wallet loaded")
                    self.status_label.config(text="No wallet loaded")
                    self.show_wallet_setup_wizard()
            on_wallet_loaded(False)

    def show_wallet_setup_wizard(self):
        logger.info("Showing wallet setup wizard")
        wizard_window = tk.Toplevel(self.root)
        wizard_window.title("Welcome to Mission Ctrl - Wallet Setup")
        wizard_window.geometry("400x300")
        wizard_window.resizable(False, False)
        wizard_window.transient(self.root)
        wizard_window.grab_set()

        tk.Label(wizard_window, text="Welcome! You need a wallet to use Mission Ctrl.", wraplength=350).pack(pady=10)
        tk.Label(wizard_window, text="A wallet stores your funds (ETH and ANT) and pays for uploads.", wraplength=350).pack(pady=5)
        tk.Label(wizard_window, text="Choose an option to get started:", wraplength=350).pack(pady=5)

        tk.Button(wizard_window, text="Create a New Wallet", command=lambda: [wizard_window.destroy(), wallet.create_wallet(self)]).pack(pady=5)
        tk.Button(wizard_window, text="Import an Existing Wallet", command=lambda: [wizard_window.destroy(), wallet.import_wallet(self)]).pack(pady=5)
        tk.Button(wizard_window, text="Learn More", command=gui.show_help).pack(pady=5)

    def _show_upload_success(self, address, filename, is_private):
        from tkinter import ttk, filedialog, messagebox
        from gui import add_context_menu 
        # Create a new Toplevel window for the upload success dialog.
        success_window = tk.Toplevel(self.root)
        success_window.title(f"Upload Success - {filename}")
        success_window.geometry("400x200")
        success_window.transient(self.root)
        success_window.grab_set()

        # Create a frame inside the dialog.
        frame = ttk.Frame(success_window)
        frame.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)

        # Determine the label text based on whether data is private.
        label_text = "Private Data Map" if is_private else "Public Chunk Address"
        ttk.Label(frame, text=f"{label_text} for {filename}:").pack(anchor="w")

        # Show the address in a readonly entry with context menu.
        addr_entry = ttk.Entry(frame, width=80)
        addr_entry.pack(fill=tk.X, pady=5)
        addr_entry.insert(0, address)
        addr_entry.config(state="readonly")
        add_context_menu(addr_entry) 

        ttk.Label(frame, text="Use this address to retrieve your data.").pack(anchor="w")

        # Define a function to save the address to a file.
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
                    messagebox.showerror("Error", f"Failed to save address: {e}")

        # Create Save and Close buttons in the dialog.
        ttk.Button(success_window, text="Save", command=save_address).pack(pady=5)
        ttk.Button(success_window, text="Close", command=success_window.destroy).pack(pady=5)

    # ----------------- Methods delegated to other modules -----------------

    def upload_file(self):
        from tkinter import filedialog, messagebox
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
            asyncio.run_coroutine_threadsafe(public.upload_public(self, file_path), self.loop)
        elif private_selected:
            asyncio.run_coroutine_threadsafe(private.upload_private(self, file_path), self.loop)

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
        from tkinter import messagebox
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

    def manage_public_files(self):
        public.manage_public_files(self)

    def manage_private_files(self):
        private.manage_private_files(self)

    def retrieve_data(self):
        get.retrieve_data(self)

    # A wallet options window combining wallet-related actions.
    def show_wallet_options(self):
        wallet_window = tk.Toplevel(self.root)
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

    # This method is used by view.py when the user clicks a "View" button on a file in an archive.
    def view_archive_file(self, addr, name):
        view.view_file(self, addr, name)

    # To allow view.py to call this method using our app, we assign it as _view_archive_file.
    _view_archive_file = view.view_file

if __name__ == "__main__":
    app = TestApp()
    app.root.mainloop()
