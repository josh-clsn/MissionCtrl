import sys
# Remove conflicting local path
sys.path = [p for p in sys.path if '/home/josh/autonomi/autonomi/python' not in p] + sys.path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from autonomi_client import Client, Network, Wallet, PaymentOption, DataMapChunk, PublicArchive, Metadata
import asyncio
import os
import threading
import logging
import io
from PIL import Image, ImageTk
from web3 import Web3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MissionControl")

def add_context_menu(widget):
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    widget.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))

class TestApp:
    def __init__(self):
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
        
        self.root.title("Mission Control")  # Renamed from "Autonomi App"
        self.root.geometry("630x550")
        self.root.configure(bg="#f0f2f5")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.loop = asyncio.new_event_loop()
        self.client = None
        self.wallet = None
        self.uploaded_files = []  # Persistent list of (filename, chunk_addr) for unarchived files
        self.local_archives = []  # Persistent list of (archive_addr, nickname, is_private)
        self.w3 = Web3(Web3.HTTPProvider('https://arb1.arbitrum.io/rpc'))
        self.wallet_file = "wallet.enc"
        
        self.is_public_var = tk.BooleanVar(value=False)
        self.is_private_var = tk.BooleanVar(value=False)

        self.setup_gui()
        
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        asyncio.run_coroutine_threadsafe(self.initialize_client(), self.loop)
        self.update_balances()

    def on_closing(self):
        logger.info("Closing window...")
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.root.destroy()

    def setup_gui(self):
        style = ttk.Style()
        style.configure("TButton", padding=6, font=("Arial", 10))
        style.configure("TLabel", background="#f0f2f5", font=("Arial", 10))
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("Accent.TButton", background="#b0c4de", foreground="black")
        style.configure("Status.TFrame", background="#e9ecef")

        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.connection_label = ttk.Label(main_frame, text="Network: Connecting...", foreground="#666666")
        self.connection_label.pack(pady=(0, 15))

        wallet_card = ttk.Frame(main_frame, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
        wallet_card.pack(fill=tk.X, pady=(0, 15))

        self.wallet_address_label = ttk.Label(wallet_card, text="Wallet: Not Connected", wraplength=400, foreground="#333333")
        self.wallet_address_label.pack(anchor="w")

        wallet_actions = ttk.Frame(wallet_card)
        wallet_actions.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(wallet_actions, text="Options", command=self.show_wallet_options).pack(side=tk.RIGHT)

        balance_card = ttk.Frame(main_frame, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
        balance_card.pack(fill=tk.X, pady=(0, 15))

        balances = ttk.Frame(balance_card)
        balances.pack(fill=tk.X)

        self.ant_balance_label = ttk.Label(balances, text="ANT Balance: Not Connected", foreground="#333333")
        self.ant_balance_label.pack(side=tk.LEFT)

        self.eth_balance_label = ttk.Label(balances, text="ETH Balance: Not Connected", foreground="#333333")
        self.eth_balance_label.pack(side=tk.RIGHT)

        ttk.Button(balance_card, text="Refresh", command=self.update_balances).pack(pady=(10, 0))

        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, pady=(0, 15))

        public_checkbox = ttk.Checkbutton(actions_frame, text="Public", variable=self.is_public_var)
        private_checkbox = ttk.Checkbutton(actions_frame, text="Private (encrypted)", variable=self.is_private_var)
        public_checkbox.pack(anchor="w")
        private_checkbox.pack(anchor="w")

        ttk.Button(actions_frame, text="Upload", command=self.upload_file, style="Accent.TButton").pack(fill=tk.X, pady=(10, 0))

        ttk.Button(actions_frame, text="Manage Public Files", command=self.manage_public_files, style="Accent.TButton").pack(fill=tk.X, pady=(5, 0))

        retrieve_frame = ttk.Frame(main_frame)
        retrieve_frame.pack(fill=tk.X)

        ttk.Label(retrieve_frame, text="Retrieve Data", font=("Arial", 11, "bold")).pack(anchor="w")
        retrieve_inner = ttk.Frame(retrieve_frame, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
        retrieve_inner.pack(fill=tk.X, pady=(5, 0))

        self.retrieve_entry = ttk.Entry(retrieve_inner)
        self.retrieve_entry.pack(fill=tk.X, pady=(0, 10))
        self.retrieve_entry.bind("<Return>", lambda event: self.retrieve_data())
        add_context_menu(self.retrieve_entry)

        ttk.Button(retrieve_inner, text="Get", command=self.retrieve_data, style="Accent.TButton").pack(fill=tk.X)

        status_bar = ttk.Frame(main_frame, relief="sunken", borderwidth=1, style="Status.TFrame")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Label(status_bar, text="v1.0.0", foreground="#666666").pack(side=tk.LEFT, padx=5)

        self.root.resizable(False, False)

    def upload_file(self):
        public_selected = self.is_public_var.get()
        private_selected = self.is_private_var.get()

        if (public_selected and private_selected) or (not public_selected and not private_selected):
            messagebox.showwarning(
                "Selection Required",
                "Public data is NOT encrypted.\nPrivate data IS encrypted.\n\n"
                "Please select one."
            )
            return

        if public_selected:
            self.upload_public()
        elif private_selected:
            self.upload_private()

    def manage_public_files(self):
        if not self.client:
            messagebox.showinfo("Simulation Mode", "File management not available in simulation mode.")
            return

        manage_window = tk.Toplevel(self.root)
        manage_window.title("Manage Public Files - Mission Control")  # Renamed
        manage_window.geometry("600x500")

        def refresh_content():
            # Clear existing content
            for widget in files_inner_frame.winfo_children():
                widget.destroy()
            for widget in archives_inner_frame.winfo_children():
                widget.destroy()

            # Refresh Uploaded Files
            check_vars.clear()
            for filename, chunk_addr in self.uploaded_files:
                var = tk.BooleanVar(value=False)
                check_vars.append((var, filename, chunk_addr))
                frame = ttk.Frame(files_inner_frame)
                frame.pack(anchor="w", padx=5, pady=2)
                chk = ttk.Checkbutton(frame, text=f"{filename} - ", variable=var)
                chk.pack(side=tk.LEFT)
                addr_entry = ttk.Entry(frame, width=40)
                addr_entry.insert(0, chunk_addr)
                addr_entry.config(state="readonly")
                addr_entry.pack(side=tk.LEFT)
                add_context_menu(addr_entry)

            # Refresh Archives
            public_archives = [(addr, name) for addr, name, is_private in self.local_archives if not is_private]
            for addr, nickname in public_archives:
                frame = ttk.Frame(archives_inner_frame)
                frame.pack(anchor="w", padx=5, pady=2)
                label = ttk.Label(frame, text=f"{nickname} - ")
                label.pack(side=tk.LEFT)
                addr_entry = ttk.Entry(frame, width=40)
                addr_entry.insert(0, addr)
                addr_entry.config(state="readonly")
                addr_entry.pack(side=tk.LEFT)
                add_context_menu(addr_entry)

            files_inner_frame.update_idletasks()
            files_canvas.configure(scrollregion=files_canvas.bbox("all"))
            archives_inner_frame.update_idletasks()
            archives_canvas.configure(scrollregion=archives_canvas.bbox("all"))

            # Schedule next refresh
            manage_window.after(5000, refresh_content)  # Refresh every 5 seconds

        # Unarchived Files Section
        files_frame = ttk.LabelFrame(manage_window, text="Uploaded Files (Unarchived)", padding=5)
        files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        files_canvas = tk.Canvas(files_frame)
        files_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
        files_inner_frame = ttk.Frame(files_canvas)
        files_canvas.configure(yscrollcommand=files_scrollbar.set)

        files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")

        check_vars = []

        # Archives Section
        archives_frame = ttk.LabelFrame(manage_window, text="Archives", padding=5)
        archives_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        archives_canvas = tk.Canvas(archives_frame)
        archives_scrollbar = ttk.Scrollbar(archives_frame, orient="vertical", command=archives_canvas.yview)
        archives_inner_frame = ttk.Frame(archives_canvas)
        archives_canvas.configure(yscrollcommand=archives_scrollbar.set)

        archives_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        archives_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        archives_canvas.create_window((0, 0), window=archives_inner_frame, anchor="nw")

        # Initial population and start auto-refresh
        refresh_content()

        buttons_frame = ttk.Frame(manage_window)
        buttons_frame.pack(fill=tk.X, pady=10)

        def add_to_archive():
            selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
            if not selected:
                messagebox.showwarning("Selection Error", "Please select at least one file to archive.")
                return

            archive_window = tk.Toplevel(manage_window)
            archive_window.title("Add to Archive - Mission Control")  # Renamed
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
                    self.root.after(0, lambda: messagebox.showwarning("Input Error", "Please enter a nickname."))
                    return

                selected_files = [(fn, addr, Metadata(size=0)) for fn, addr in selected]
                progress_win = self.show_progress_window("Archiving Files...")
                try:
                    payment_option = PaymentOption.wallet(self.wallet)
                    if archive_combo.get() == "Create New Archive":
                        archive = PublicArchive()
                        for filename, chunk_addr, metadata in selected_files:
                            archive.add_file(filename, chunk_addr, metadata)
                        _, archive_addr = await self.client.archive_put_public(archive, self.wallet)
                        self.local_archives.append((archive_addr, nickname, False))
                    else:
                        archive_addr = archive_combo.get().split(" - ")[1]
                        archive = await self.client.archive_get_public(archive_addr)
                        for filename, chunk_addr, metadata in selected_files:
                            archive.add_file(filename, chunk_addr, metadata)
                        _, new_archive_addr = await self.client.archive_put_public(archive, self.wallet)
                        for i, (addr, _, is_private) in enumerate(self.local_archives):
                            if addr == archive_addr and not is_private:
                                self.local_archives[i] = (new_archive_addr, nickname, False)
                                break
                        archive_addr = new_archive_addr

                    if remove_var.get():
                        for filename, chunk_addr in selected:
                            self.uploaded_files.remove((filename, chunk_addr))

                    self.root.after(0, lambda: messagebox.showinfo("Success", f"Files archived at {archive_addr}"))
                    self.root.after(0, manage_window.destroy)
                except Exception as e:
                    logger.error("Archiving error: %s", e)
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Archiving failed: {e}"))
                finally:
                    self.root.after(0, lambda: self.hide_progress_window(progress_win))

            ttk.Button(archive_window, text="Archive", command=lambda: asyncio.run_coroutine_threadsafe(do_archive(), self.loop)).pack(pady=10)

        def append_to_archive():
            selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
            if not selected:
                messagebox.showwarning("Selection Error", "Please select at least one file to append.")
                return
            if not public_archives:
                messagebox.showwarning("No Archives", "No existing archives to append to. Use 'Add to Archive' to create one.")
                return

            append_window = tk.Toplevel(manage_window)
            append_window.title("Append to Archive - Mission Control")  # Renamed
            append_window.geometry("400x200")

            ttk.Label(append_window, text="Select Archive to Append To:").pack(pady=5)
            archive_combo = ttk.Combobox(append_window, values=[f"{n} - {a}" for a, n in public_archives])
            archive_combo.pack(pady=5)
            if public_archives:
                archive_combo.set(f"{public_archives[0][1]} - {public_archives[0][0]}")

            remove_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(append_window, text="Remove selected files from Uploaded Files list", variable=remove_var).pack(pady=5)

            async def do_append():
                if not archive_combo.get():
                    self.root.after(0, lambda: messagebox.showwarning("Input Error", "Please select an archive."))
                    return

                archive_addr = archive_combo.get().split(" - ")[1]
                selected_files = [(fn, addr, Metadata(size=0)) for fn, addr in selected]
                progress_win = self.show_progress_window("Appending Files to Archive...")
                try:
                    payment_option = PaymentOption.wallet(self.wallet)
                    archive = await self.client.archive_get_public(archive_addr)
                    for filename, chunk_addr, metadata in selected_files:
                        archive.add_file(filename, chunk_addr, metadata)
                    _, new_archive_addr = await self.client.archive_put_public(archive, self.wallet)
                    
                    for i, (addr, nickname, is_private) in enumerate(self.local_archives):
                        if addr == archive_addr and not is_private:
                            self.local_archives[i] = (new_archive_addr, nickname, False)
                            break

                    if remove_var.get():
                        for filename, chunk_addr in selected:
                            self.uploaded_files.remove((filename, chunk_addr))

                    self.root.after(0, lambda: messagebox.showinfo("Success", f"Files appended to archive at {new_archive_addr}"))
                    self.root.after(0, manage_window.destroy)
                except Exception as e:
                    logger.error("Appending error: %s", e)
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Appending failed: {e}"))
                finally:
                    self.root.after(0, lambda: self.hide_progress_window(progress_win))

            ttk.Button(append_window, text="Append", command=lambda: asyncio.run_coroutine_threadsafe(do_append(), self.loop)).pack(pady=10)

        def remove_selected_files():
            selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
            if not selected:
                messagebox.showwarning("Selection Error", "Please select at least one file to remove.")
                return
            if messagebox.askyesno("Confirm", "Remove selected files from the Uploaded Files list?"):
                for filename, chunk_addr in selected:
                    self.uploaded_files.remove((filename, chunk_addr))
                manage_window.destroy()

        ttk.Button(buttons_frame, text="Add to Archive", command=add_to_archive).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Append to Archive", command=append_to_archive).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Remove from List", command=remove_selected_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Close", command=manage_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_progress_window(self, message):
        progress_win = tk.Toplevel(self.root)
        progress_win.title("Please Wait")
        progress_win.geometry("300x100")
        progress_win.transient(self.root)
        progress_win.grab_set()

        label = ttk.Label(progress_win, text=message, anchor="center")
        label.pack(pady=10)

        progress_bar = ttk.Progressbar(progress_win, mode="indeterminate")
        progress_bar.pack(padx=10, pady=10, fill=tk.X)
        progress_bar.start(10)

        return progress_win

    def hide_progress_window(self, progress_win):
        if progress_win and progress_win.winfo_exists():
            progress_win.destroy()

    def upload_public(self):
        logger.info("Upload Public button clicked")
        if not self.client:
            file_path = filedialog.askopenfilename(
                title="Select a Public File",
                filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")]
            )
            if not file_path:
                return
            file_name = os.path.basename(file_path)
            fake_addr = f"simulated_public_address_{file_name}"
            self.uploaded_files.append((file_name, fake_addr))
            self._show_upload_success(fake_addr, file_name, False)
            return

        async def _upload_public():
            file_path = filedialog.askopenfilename(
                title="Select a Public File",
                filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")]
            )
            if not file_path:
                logger.info("No file selected")
                return

            progress_win = None
            try:
                def create_progress():
                    nonlocal progress_win
                    progress_win = self.show_progress_window("Uploading Public Data...")
                self.root.after(0, create_progress)

                with open(file_path, "rb") as f:
                    file_data = f.read()

                payment_option = PaymentOption.wallet(self.wallet)
                ant_balance = int(await self.wallet.balance())

                if ant_balance <= 0:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload"))
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
                self.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 3000 seconds"))
            except Exception as e:
                logger.error("Upload error: %s", e)
                self.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}"))
            finally:
                self.root.after(0, lambda: self.hide_progress_window(progress_win))

        asyncio.run_coroutine_threadsafe(_upload_public(), self.loop)

    def upload_private(self):
        logger.info("Upload Private button clicked")
        if not self.client:
            file_path = filedialog.askopenfilename(
                title="Select a Private File",
                filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")]
            )
            if not file_path:
                return
            file_name = os.path.basename(file_path)
            fake_addr = f"simulated_private_address_{file_name}"
            self.local_archives.append((fake_addr, file_name, True))
            self._show_upload_success(fake_addr, file_name, True)
            return

        async def _upload_private():
            file_path = filedialog.askopenfilename(
                title="Select a Private File",
                filetypes=[("All Files", "*.*"), ("Images", "*.png *.jpg *.jpeg")]
            )
            if not file_path:
                logger.info("No file selected")
                return

            progress_win = None
            try:
                def create_progress():
                    nonlocal progress_win
                    progress_win = self.show_progress_window("Uploading Private Data...")
                self.root.after(0, create_progress)

                with open(file_path, "rb") as f:
                    file_data = f.read()

                payment_option = PaymentOption.wallet(self.wallet)
                ant_balance = int(await self.wallet.balance())

                if ant_balance > 0:
                    result = await asyncio.wait_for(
                        self.client.data_put(file_data, payment_option),
                        timeout=600
                    )
                    price, data_map_chunk = result
                    access_token = data_map_chunk.to_hex()
                    file_name = os.path.basename(file_path)
                    self.local_archives.append((access_token, file_name, True))
                    logger.info(f"Private data uploaded, price: {price}, access token: {access_token}")
                    self.root.after(0, lambda: self._show_upload_success(access_token, file_name, True))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload"))

            except asyncio.TimeoutError:
                self.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 600 seconds"))
            except Exception as e:
                logger.error("Upload error: %s", e)
                self.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}"))
            finally:
                self.root.after(0, lambda: self.hide_progress_window(progress_win))

        asyncio.run_coroutine_threadsafe(_upload_private(), self.loop)

    def _show_upload_success(self, address, filename, is_private):
        success_window = tk.Toplevel(self.root)
        success_window.title(f"Upload Success - {filename}")
        success_window.geometry("400x200")
        success_window.transient(self.root)
        success_window.grab_set()

        frame = ttk.Frame(success_window)
        frame.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)

        ttk.Label(frame, text=f"{'Private Data Map' if is_private else 'Public Chunk Address'} for {filename}:").pack(anchor="w")
        addr_entry = ttk.Entry(frame)
        addr_entry.pack(fill=tk.X, pady=5)
        addr_entry.insert(0, address)
        addr_entry.config(state="readonly")
        add_context_menu(addr_entry)

        ttk.Label(frame, text="Use this address to retrieve your data. For public files, use 'Manage Public Files' to archive.").pack(anchor="w")

        def save_address():
            save_path = filedialog.asksaveasfilename(
                parent=success_window,
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
        address_input = self.retrieve_entry.get().strip()
        if not address_input:
            messagebox.showwarning("Input Error", "Please enter an address to retrieve.")
            return

        if not self.client:
            messagebox.showinfo("Simulation Mode", "Cannot retrieve data in simulation mode.")
            return

        async def _retrieve():
            progress_win = None
            try:
                def create_progress():
                    nonlocal progress_win
                    progress_win = self.show_progress_window("Downloading Data...")
                self.root.after(0, create_progress)

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
                                "Invalid address or data not found. Use a hex-encoded DataMapChunk for private data, "
                                "a Public Archive Address, or a single chunk address for public data."
                            ))
                            return

                def show_data_window():
                    view_window = tk.Toplevel(self.root)
                    view_window.title("Retrieved Data - Mission Control")  # Renamed
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
                        file_data = await self.client.data_get_public(file_addr)
                        save_path = filedialog.asksaveasfilename(
                            parent=view_window,
                            initialfile=file_name,
                            defaultextension=".bin",
                            filetypes=[("All files", "*.*")],
                            title=f"Save {file_name}"
                        )
                        if save_path:
                            try:
                                with open(save_path, "wb") as f:
                                    f.write(file_data)
                                messagebox.showinfo("Success", f"File saved to {save_path}")
                            except Exception as ex:
                                logger.error("Failed to save file: %s", ex)
                                messagebox.showerror("Error", f"Failed to save file: {ex}")

                    def save_individual():
                        if is_private or is_single_chunk:
                            save_path = filedialog.asksaveasfilename(
                                parent=view_window,
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
                            title="Select Directory to Save All Files"
                        )
                        if save_path:
                            progress_win = self.show_progress_window("Downloading All Files...")
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
                                self.root.after(0, lambda: self.hide_progress_window(progress_win))

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
                self.root.after(0, lambda: messagebox.showerror("Error", f"Retrieval Failed: {e}"))
            finally:
                self.root.after(0, lambda: self.hide_progress_window(progress_win))

        asyncio.run_coroutine_threadsafe(_retrieve(), self.loop)

    async def initialize_client(self):
        try:
            network = Network(False)
            self.client = await Client.init()
            logger.info("Connected to Autonomi network")
            self.root.after(0, lambda: self.connection_label.config(
                text="Network: Connected"))
            
            def on_wallet_loaded(success):
                if not success:
                    logger.info("No valid wallet loaded")
            
            if os.path.exists(self.wallet_file):
                self.show_wallet_password_prompt(on_wallet_loaded)
            else:
                on_wallet_loaded(False)
                
            await self._update_balances()
        except Exception as e:
            logger.error("Initialization failed: %s", e)
            self.root.after(0, lambda: self.connection_label.config(
                text=f"Network: Failed ({str(e)})"))
            self.client = None

    async def _update_balances(self):
        if not self.wallet:
            self.root.after(0, lambda: self.ant_balance_label.config(
                text="ANT Balance: Not Connected"))
            self.root.after(0, lambda: self.eth_balance_label.config(
                text="ETH Balance: Not Connected"))
            return
        try:
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
        except Exception as e:
            logger.error("Failed to update balances: %s", e)
            self.root.after(0, lambda: self.ant_balance_label.config(
                text="ANT Balance: Error"))
            self.root.after(0, lambda: self.eth_balance_label.config(
                text="ETH Balance: Error"))

    def update_balances(self):
        asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
        self.root.after(30000, self.update_balances)

    def get_encryption_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt_',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_wallet(self, key, password):
        fernet = Fernet(self.get_encryption_key(password))
        encrypted = fernet.encrypt(key.encode())
        with open(self.wallet_file, 'wb') as f:
            f.write(encrypted)

    def decrypt_wallet(self, password):
        try:
            with open(self.wallet_file, 'rb') as f:
                encrypted = f.read()
            fernet = Fernet(self.get_encryption_key(password))
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
            key = self.decrypt_wallet(password)
            if key:
                try:
                    self.wallet = Wallet(key)
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
        if messagebox.askyesno("Confirm", "Are you sure you want to delete the current wallet?"):
            self.wallet = None
            if os.path.exists(self.wallet_file):
                os.remove(self.wallet_file)
            self.wallet_address_label.config(text="Wallet: Not Connected")
            self.ant_balance_label.config(text="ANT Balance: Not Connected")
            self.eth_balance_label.config(text="ETH Balance: Not Connected")
            messagebox.showinfo("Success", "Wallet deleted successfully")
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
            pk = pk_entry.get().strip()
            password = pw_entry.get()
            if not password:
                messagebox.showerror("Error", "Password is required")
                return
            try:
                self.wallet = Wallet(pk)
                self.encrypt_wallet(pk, password)
                self.wallet_address_label.config(text=f"Wallet: {self.wallet.address()}")
                asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
                messagebox.showinfo("Success", "Wallet imported successfully")
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
                self.wallet = Wallet(new_account.key.hex())
                self.encrypt_wallet(new_account.key.hex(), password)
                self.wallet_address_label.config(text=f"Wallet: {self.wallet.address()}")
                asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
                self._show_wallet_created_info(self.wallet.address(), new_account.key.hex())
                password_window.destroy()
                if wallet_window is not None:
                    wallet_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create wallet: {str(e)}")
        
        tk.Button(password_window, text="Create", command=do_create).pack(pady=5)

    def _show_wallet_created_info(self, address, pk):
        info_window = tk.Toplevel(self.root)
        info_window.title("New Wallet Info")
        info_window.geometry("400x250")
        
        text = tk.Text(info_window, height=8, width=50)
        text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
        text.insert(tk.END, f"Address: {address}\n")
        text.insert(tk.END, f"Private Key: {pk}\n\n")
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
        wallet_window.geometry("300x200")
        
        tk.Button(wallet_window, text="Delete Current Wallet",
                  command=lambda: self.delete_wallet(wallet_window)).pack(pady=5)
        
        tk.Button(wallet_window, text="Import Wallet (Private Key)",
                  command=lambda: self.import_wallet(wallet_window)).pack(pady=5)
        
        tk.Button(wallet_window, text="Create New Wallet",
                  command=lambda: self.create_wallet(wallet_window)).pack(pady=5)
        
        tk.Button(wallet_window, text="Close",
                  command=wallet_window.destroy).pack(pady=5)

if __name__ == "__main__":
    app = TestApp()
    app.root.mainloop()