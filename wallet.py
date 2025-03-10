import os
import json
import base64
import logging
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import platform
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import asyncio
from queue import Queue

logger = logging.getLogger("MissionCtrl")

# ANT token contract address and ABI for Arbitrum
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

def get_encryption_key(password, salt=None):
    """Derives encryption key from password using PBKDF2."""
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

def encrypt_wallet(app, private_key, password):
    """Encrypts private key and saves to file."""
    key, salt = get_encryption_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(private_key.encode())
    with open(app.wallet_file, 'wb') as f:
        f.write(salt + encrypted)

def decrypt_wallet(app, password):
    """Decrypts wallet file with provided password."""
    try:
        with open(app.wallet_file, 'rb') as f:
            data = f.read()
        salt = data[:16]
        encrypted = data[16:]
        key, _ = get_encryption_key(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted).decode()
    except Exception:
        return None

def show_wallet_password_prompt(app, callback):
    """Prompts for wallet password and loads wallet if valid."""
    if not os.path.exists(app.wallet_file):
        callback(False)
        return
        
    password_window = tk.Toplevel(app.root)
    password_window.title("Wallet Password")
    password_window.geometry("300x150")
    
    tk.Label(password_window, text="Enter wallet password:").pack(pady=5)
    pw_entry = tk.Entry(password_window, show="*", width=30)
    pw_entry.pack(pady=5)
    from gui import add_context_menu
    add_context_menu(pw_entry)
    
    def try_load():
        password = pw_entry.get()
        private_key = decrypt_wallet(app, password)
        if private_key:
            try:
                from autonomi_client import Wallet
                app.wallet = Wallet(private_key)
                app.wallet_address_label.config(text=f"Wallet: {app.wallet.address()}")
                import asyncio
                asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
                callback(True)
                password_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Invalid wallet data: {str(e)}")
                callback(False)
        else:
            messagebox.showerror("Error", "Incorrect password")
            callback(False)
    
    tk.Button(password_window, text="Unlock", command=try_load).pack(pady=5)

def delete_wallet(app, wallet_window=None):
    """Deletes wallet file after user confirmation."""
    if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete your wallet? You’ll need your private key to recover it later."):
        app.wallet = None
        if os.path.exists(app.wallet_file):
            os.remove(app.wallet_file)
        app.wallet_address_label.config(text="Wallet: Not Connected")
        app.ant_balance_label.config(text="ANT Balance: Not Connected")
        app.eth_balance_label.config(text="ETH Balance: Not Connected")
        messagebox.showinfo("Success", "Wallet deleted successfully")
        app.status_label.config(text="Wallet deleted")
    if wallet_window is not None:
        wallet_window.destroy()

def import_wallet(app, wallet_window=None):
    """Imports an existing wallet via private key."""
    import_window = tk.Toplevel(app.root)
    import_window.title("Import Wallet")
    import_window.geometry("400x200")
    
    tk.Label(import_window, text="Enter Private Key:").pack(pady=5)
    pk_entry = tk.Entry(import_window, width=50, show="*")
    pk_entry.pack(pady=5)
    from gui import add_context_menu
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
            from autonomi_client import Wallet
            app.wallet = Wallet(private_key)
            encrypt_wallet(app, private_key, password)
            app.wallet_address_label.config(text=f"Wallet: {app.wallet.address()}")
            import asyncio
            asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
            messagebox.showinfo("Success", "Wallet imported successfully")
            app.status_label.config(text="Wallet imported")
            import_window.destroy()
            if wallet_window is not None:
                wallet_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Invalid private key: {str(e)}")
    
    tk.Button(import_window, text="Import", command=do_import).pack(pady=5)

def create_wallet(app, wallet_window=None):
    """Creates a new wallet and encrypts it."""
    password_window = tk.Toplevel(app.root)
    password_window.title("Set Wallet Password")
    password_window.geometry("300x150")
    
    tk.Label(password_window, text="Set wallet password:").pack(pady=5)
    pw_entry = tk.Entry(password_window, show="*", width=30)
    pw_entry.pack(pady=5)
    from gui import add_context_menu
    add_context_menu(pw_entry)
    
    def do_create():
        password = pw_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required")
            return
        try:
            from web3 import Web3
            from autonomi_client import Wallet
            new_account = app.w3.eth.account.create()
            private_key = new_account.key.hex()
            app.wallet = Wallet(private_key)
            _show_wallet_creation_info(app, app.wallet.address(), private_key)
            encrypt_wallet(app, private_key, password)
            app.wallet_address_label.config(text=f"Wallet: {app.wallet.address()}")
            import asyncio
            asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
            app.status_label.config(text="Wallet created")
            password_window.destroy()
            if wallet_window is not None:
                wallet_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create wallet: {str(e)}")
    
    tk.Button(password_window, text="Create", command=do_create).pack(pady=5)

def _show_wallet_creation_info(app, address, private_key):
    """Displays new wallet details with private key warning."""
    info_window = tk.Toplevel(app.root)
    info_window.title("New Wallet Info")
    info_window.geometry("400x250")
    
    text = tk.Text(info_window, height=8, width=50)
    text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
    text.insert(tk.END, f"Address: {address}\n")
    text.insert(tk.END, f"Private Key: {private_key}\n\n")
    text.insert(tk.END, "Please save your private key securely!\n")
    text.insert(tk.END, "This is the ONLY time it will be shown. Check the box below once you have saved it.")
    text.bind("<Key>", lambda e: "break")
    from gui import add_context_menu
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

def send_funds(app, wallet_window=None):
    """Handles sending ETH or ANT from wallet."""
    if not app.wallet:
        messagebox.showerror("Error", "No wallet loaded")
        return

    send_window = tk.Toplevel(app.root)
    send_window.title("Send Funds")
    send_window.geometry("400x250")

    ttk.Label(send_window, text="Recipient Address:").pack(pady=5)
    addr_entry = ttk.Entry(send_window, width=50)
    addr_entry.pack(pady=5)
    from gui import add_context_menu
    add_context_menu(addr_entry)

    ttk.Label(send_window, text="Amount:").pack(pady=5)
    amount_entry = ttk.Entry(send_window)
    amount_entry.pack(pady=5)
    add_context_menu(amount_entry)

    currency_var = tk.StringVar(value="ETH")
    ttk.Radiobutton(send_window, text="ETH", variable=currency_var, value="ETH").pack(pady=2)
    ttk.Radiobutton(send_window, text="ANT", variable=currency_var, value="ANT").pack(pady=2)

    async def do_send():
        logger.info("do_send coroutine started")
        recipient = addr_entry.get().strip()
        amount_str = amount_entry.get().strip()
        currency = currency_var.get()

        logger.info(f"Processing transaction: recipient={recipient}, amount={amount_str}, currency={currency}")
        if not app.w3.is_address(recipient):
            logger.error(f"Invalid recipient address: {recipient}")
            app.root.after(0, lambda: messagebox.showerror("Error", "Invalid recipient address. It should start with '0x' and be 42 characters long."))
            return
        
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            logger.info(f"Validated amount: {amount}")
        except ValueError as e:
            logger.error(f"Invalid amount: {str(e)}")
            app.root.after(0, lambda: messagebox.showerror("Error", "Invalid amount. Enter a positive number (e.g., 0.1)."))
            return

        if not messagebox.askyesno("Confirm Send", f"Send {amount} {currency} to {recipient[:8]}...? This cannot be undone."):
            logger.info("Transaction cancelled by user")
            return

        # Non-blocking password prompt using Queue
        password_queue = Queue()
        def set_password(password):
            logger.info("Password submitted to queue")
            password_queue.put(password)

        logger.info("Launching password prompt")
        app.root.after(0, lambda: _prompt_password(app, "Enter password to sign transaction:", set_password))
        password = await app.loop.run_in_executor(None, lambda: password_queue.get())
        logger.info(f"Password received: {password is not None}")
        if not password:
            logger.warning("No password provided")
            return
        private_key = decrypt_wallet(app, password)
        if not private_key:
            logger.error("Failed to decrypt wallet with provided password")
            app.root.after(0, lambda: messagebox.showerror("Error", "Incorrect password"))
            return

        app.is_processing = True
        app.start_status_animation()
        try:
            logger.info("Preparing transaction")
            latest_block = app.w3.eth.get_block('latest')
            base_fee = latest_block['baseFeePerGas']
            max_priority_fee = app.w3.eth.max_priority_fee  # Fetch a suggested priority fee
            max_fee_per_gas = int(max(base_fee * 1.1, base_fee + max_priority_fee))  # Convert to integer
            max_priority_fee = int(max_priority_fee)  # Convert to integer

            if currency == "ETH":
                tx = {
                    'to': recipient,
                    'value': app.w3.to_wei(amount, 'ether'),
                    'gas': 25000,
                    'maxFeePerGas': max_fee_per_gas,
                    'maxPriorityFeePerGas': max_priority_fee,
                    'nonce': app.w3.eth.get_transaction_count(app.wallet.address()),
                    'chainId': 42161  # Arbitrum chain ID
                }
                signed_tx = app.w3.eth.account.sign_transaction(tx, private_key)
                logger.info("Signed ETH transaction")
                tx_hash = app.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            else:
                ant_contract = app.w3.eth.contract(address=ANT_TOKEN_ADDRESS, abi=ANT_ABI)
                logger.info("Fetching ANT balance")
                ant_balance = ant_contract.functions.balanceOf(app.wallet.address()).call() / 10**18
                if amount > ant_balance:
                    raise ValueError(f"Insufficient ANT balance: {ant_balance} available")
                amount_wei = int(amount * 10**18)
                logger.info(f"Estimating gas for ANT transfer of {amount_wei} wei")
                gas_estimate = ant_contract.functions.transfer(
                    recipient,
                    amount_wei
                ).estimate_gas({'from': app.wallet.address()})
                tx = ant_contract.functions.transfer(
                    recipient,
                    amount_wei
                ).build_transaction({
                    'from': app.wallet.address(),
                    'gas': int(gas_estimate * 1.5),
                    'maxFeePerGas': max_fee_per_gas,
                    'maxPriorityFeePerGas': max_priority_fee,
                    'nonce': app.w3.eth.get_transaction_count(app.wallet.address()),
                    'chainId': 42161
                })
                signed_tx = app.w3.eth.account.sign_transaction(tx, private_key)
                logger.info("Signed ANT transaction")
                tx_hash = app.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"Transaction sent, hash: {tx_hash.hex()}")
            app.root.after(0, lambda h=tx_hash: messagebox.showinfo(
                "Success", f"Sent {amount} {currency} - Tx Hash: {h.hex()}"))
            import asyncio
            asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
            send_window.destroy()
            if wallet_window:
                wallet_window.destroy()
            app.status_label.config(text=f"Sent {currency}")
        except Exception as e:
            import traceback
            error_msg = str(e)
            logger.error(f"Send {currency} failed: {error_msg}\n{traceback.format_exc()}")
            app.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"Send failed: {msg}\nDetails: {traceback.format_exc()}"))
        finally:
            if 'private_key' in locals():
                private_key = bytearray(private_key.encode())
                for i in range(len(private_key)):
                    private_key[i] = 0  # Zero out private key in memory
            app.is_processing = False
            app.stop_status_animation()

    logger.info("Setting up Send button command")
    tk.Button(send_window, text="Send", command=lambda: [logger.info("Send button clicked"), asyncio.run_coroutine_threadsafe(do_send(), app.loop)]).pack(pady=5)

def _prompt_password(app, message, callback):
    """Prompts for password in a non-blocking dialog."""
    password_window = tk.Toplevel(app.root)
    password_window.title("Password Required")
    password_window.geometry("300x150")
    
    tk.Label(password_window, text=message).pack(pady=5)
    pw_entry = tk.Entry(password_window, show="*", width=30)
    pw_entry.pack(pady=5)
    from gui import add_context_menu
    add_context_menu(pw_entry)
    
    def on_submit():
        logger.info("Password submitted")
        callback(pw_entry.get())
        password_window.destroy()
    
    tk.Button(password_window, text="Submit", command=on_submit).pack(pady=5)

def _show_wallet_created_info(app, address, pk_display):
    """Unused variant of wallet creation info display."""
    info_window = tk.Toplevel(app.root)
    info_window.title("New Wallet Info")
    info_window.geometry("400x250")
    
    text = tk.Text(info_window, height=8, width=50)
    text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
    text.insert(tk.END, f"Address: {address}\n")
    text.insert(tk.END, f"Private Key (partial): {pk_display}\n\n")
    text.insert(tk.END, "Please save your private key securely!\n")
    text.insert(tk.END, "Check the box below once you have saved it.")
    text.bind("<Key>", lambda e: "break")
    from gui import add_context_menu
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