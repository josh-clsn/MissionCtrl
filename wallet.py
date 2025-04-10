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

try:
    from gui import COLORS
except ImportError:
    COLORS = {
        "bg_light": "#FFFFFF",
        "bg_secondary": "#F5F7FA",
        "text_primary": "#1A1D21", 
        "text_secondary": "#5F6368",
        "accent_primary": "#4F46E5",
        "accent_secondary": "#7C3AED",
        "accent_tertiary": "#06B6D4",
        "success": "#10B981",
        "warning": "#F59E0B",
        "error": "#EF4444",
        "border": "#E5E7EB"
    }

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
        iterations=1000000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_wallet(app, private_key, password):
    """Encrypts private key and saves to file."""
    try:
        key, salt = get_encryption_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(private_key.encode())
        with open(app.wallet_file, 'wb') as f:
            f.write(salt + encrypted)
        return True
    except Exception as e:
        logger.error(f"Failed to encrypt wallet: {str(e)}")
        return False

def decrypt_wallet(app, password):
    """Decrypts wallet file with provided password."""
    if not os.path.exists(app.wallet_file):
        logger.error("Wallet file does not exist")
        return None
        
    try:
        with open(app.wallet_file, 'rb') as f:
            data = f.read()
        
        if len(data) <= 16:
            logger.error("Wallet file is invalid or corrupted")
            return None
            
        salt = data[:16]
        encrypted = data[16:]
        key, _ = get_encryption_key(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted).decode()
    except Exception as e:
        # Don't log the actual password error to avoid security issues
        logger.error(f"Failed to decrypt wallet: {e.__class__.__name__}")
        return None

def get_wallet_password(app, create=False):
    """Show a dialog to get the wallet password"""
    from tkinter import StringVar, TclError
    import gui

    action = "Create" if create else "Unlock"
    
    # Use the new dialog creator function for consistent sizing and positioning
    pwd_window, main_frame = gui.create_centered_dialog(
        parent=app.root,
        title="Wallet Password",
        min_width=350,
        min_height=260
    )
    
    # Add a heading
    ttk.Label(main_frame, text=f"{action} Your Wallet", 
              font=("Inter", 16, "bold"), 
              foreground=gui.CURRENT_COLORS["accent_primary"]).pack(pady=(0, 5))
    
    # Add a subheading
    subtext = "Enter a strong password to secure your wallet" if create else "Enter your password to access your wallet"
    ttk.Label(main_frame, text=subtext, 
              foreground=gui.CURRENT_COLORS["text_primary"]).pack(pady=(0, 20))
    
    # Create a frame for the password input
    input_frame = ttk.Frame(main_frame, style="TFrame")
    input_frame.pack(pady=5, fill="x")
    
    # Add the password label and input
    ttk.Label(input_frame, text="Password:").pack(side="left", padx=(0, 5))
    
    pwd_var = StringVar()
    pwd_entry = ttk.Entry(input_frame, textvariable=pwd_var, show="*", width=25)
    pwd_entry.pack(side="right", expand=True, fill="x")
    pwd_entry.focus_set()
    
    # Add password confirmation input if creating a new wallet
    confirm_frame = None
    confirm_var = StringVar()
    if create:
        # Create a frame for the password confirmation
        confirm_frame = ttk.Frame(main_frame, style="TFrame")
        confirm_frame.pack(pady=5, fill="x")
        
        # Add the confirmation label and input
        ttk.Label(confirm_frame, text="Confirm:").pack(side="left", padx=(0, 5))
        
        confirm_entry = ttk.Entry(confirm_frame, textvariable=confirm_var, show="*", width=25)
        confirm_entry.pack(side="right", expand=True, fill="x")
    
    # Error message label (initially hidden)
    error_label = ttk.Label(main_frame, text="", 
                      foreground=gui.CURRENT_COLORS["error"])
    error_label.pack(pady=(5, 0))
    
    # Create a frame for the buttons
    button_frame = ttk.Frame(main_frame, style="TFrame")
    button_frame.pack(pady=(20, 0), side="bottom", fill="x")
    
    result = [None] 
    
    def validate_password(password):
        """Validates password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        # Check for password complexity if creating a new wallet
        if create:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(not c.isalnum() for c in password)
            
            if not (has_upper and has_lower and has_digit):
                return False, "Password must contain uppercase, lowercase, and numbers"
                
            if not has_special:
                return False, "Password should include at least one special character"
                
        return True, ""
    
    def on_ok():
        password = pwd_var.get()
        
        # Check if password is empty
        if not password:
            error_label.config(text="Password cannot be empty")
            return
            
        # Validate password strength
        valid, message = validate_password(password)
        if not valid:
            error_label.config(text=message)
            return
            
        # Check password confirmation if creating new wallet
        if create and password != confirm_var.get():
            error_label.config(text="Passwords do not match")
            return
            
        # All validation passed, proceed
        result[0] = password
        try:
            pwd_window.grab_release()
            pwd_window.destroy()
        except TclError:
            pass  
    
    def on_cancel():
        result[0] = None
        try:
            pwd_window.grab_release()
            pwd_window.destroy()
        except TclError:
            pass  
    
    # Add the OK and cancel buttons
    btn_text = "Create" if create else "Unlock"
    cancel_btn = ttk.Button(button_frame, text="Cancel", 
                          command=on_cancel,
                          style="Secondary.TButton")
    cancel_btn.pack(side="left")
    
    ok_btn = ttk.Button(button_frame, text=btn_text, 
                       command=on_ok,
                       style="Accent.TButton")
    ok_btn.pack(side="right")
    
    # Bind the Enter key to OK
    pwd_window.bind("<Return>", lambda event: on_ok())
    pwd_window.bind("<Escape>", lambda event: on_cancel())
    
    # Wait for user input
    app.root.wait_window(pwd_window)
    return result[0]

def delete_wallet(app, wallet_window=None):
    """Deletes wallet file after user confirmation."""
    # Create custom styled confirmation dialog with the new dialog creator function
    import gui
    
    confirm_window, frame = gui.create_centered_dialog(
        parent=wallet_window if wallet_window else app.root,
        title="Confirm Deletion",
        min_width=450,
        min_height=250
    )
    
    # Warning icon and header
    ttk.Label(frame, text="⚠️", font=("Inter", 24), 
             foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 10))
    ttk.Label(frame, text="Delete Wallet?", 
             font=("Inter", 16, "bold")).pack(pady=(0, 10))
    
    # Warning message
    message = "Are you sure you want to delete your wallet?\nYou'll need your private key to recover it later."
    ttk.Label(frame, text=message, wraplength=380, justify="center").pack(pady=(0, 20))
    
    # Buttons
    button_frame = ttk.Frame(frame, style="TFrame")
    button_frame.pack(fill=tk.X, side=tk.BOTTOM)
    
    result = [False]  
    
    def on_yes():
        result[0] = True
        confirm_window.destroy()
    
    def on_no():
        result[0] = False
        confirm_window.destroy()
    
    no_btn = ttk.Button(button_frame, text="Cancel", style="Secondary.TButton", command=on_no)
    no_btn.pack(side=tk.LEFT, padx=(0, 10))
    
    yes_btn = ttk.Button(button_frame, text="Yes, Delete Wallet", style="Accent.TButton", command=on_yes)
    yes_btn.pack(side=tk.RIGHT)
    
    # Wait for user response
    confirm_window.wait_window()
    
    # If confirmed, proceed with deletion
    if result[0]:
        app.wallet = None
        if os.path.exists(app.wallet_file):
            os.remove(app.wallet_file)
        app.wallet_address_label.config(text="Wallet: Not Connected")
        app.ant_balance_label.config(text="ANT Balance: Not Connected")
        app.eth_balance_label.config(text="ETH Balance: Not Connected")
        
        # Show success message with custom dialog
        success_window, success_frame = gui.create_centered_dialog(
            parent=app.root,
            title="Success",
            min_width=350,
            min_height=180
        )
        
        ttk.Label(success_frame, text="✅", font=("Inter", 24), 
                 foreground=gui.CURRENT_COLORS["success"]).pack(pady=(0, 10))
        ttk.Label(success_frame, text="Wallet Deleted Successfully", 
                 font=("Inter", 14, "bold")).pack(pady=(0, 20))
        
        ok_btn = ttk.Button(success_frame, text="OK", style="Accent.TButton", 
                         command=success_window.destroy)
        ok_btn.pack()
        
        app.status_label.config(text="Wallet deleted")
        
        # Wait for success dialog to close
        success_window.wait_window()
        
    # Close wallet options window if provided
    if wallet_window is not None:
        wallet_window.destroy()

def is_valid_private_key(private_key):
    """Validate an Ethereum private key."""
    try:
        # Clean the key (remove whitespace, etc.)
        private_key = private_key.strip()
        
        # Add 0x prefix if missing
        if not private_key.startswith("0x"):
            private_key = "0x" + private_key
            
        # Remove 0x prefix for length check
        key = private_key[2:]
        if len(key) != 64:
            return False
            
        # Check if key is valid hex
        try:
            int(key, 16)
        except ValueError:
            return False
        
        try:
            from autonomi_client import Wallet
            wallet = Wallet(private_key)
            address = wallet.address()
            
            # Verify address is valid Ethereum format (0x followed by 40 hex chars)
            if not address.startswith("0x") or len(address) != 42:
                return False
        except Exception as e:
            # Log but don't fail - the key might still be valid
            logger.warning(f"Wallet creation warning: {type(e).__name__}")
            # We'll still try to use the key if it passed the basic checks
            
        return True
    except Exception as e:
        logger.error(f"Private key validation error: {type(e).__name__}")
        return False

def import_wallet(app, wallet_window=None):
    """Imports an existing wallet via private key."""
    import gui
    
    # Confirm if overwriting an existing wallet
    if os.path.exists(app.wallet_file):
        # Use the new dialog creator function for the warning dialog
        is_dark = hasattr(app, 'is_dark_mode') and app.is_dark_mode
        
        warning_window, warning_frame = gui.create_centered_dialog(
            parent=app.root,
            title="Warning",
            min_width=450,
            min_height=250
        )
        
        # Warning icon
        ttk.Label(warning_frame, text="⚠️", font=("Inter", 28), 
                foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 10))
                
        # Warning title
        ttk.Label(warning_frame, text="Replace Existing Wallet?", 
                font=("Inter", 14, "bold")).pack(pady=(0, 10))
        
        # Warning message
        message = "You already have a wallet. Importing a new one will replace your current wallet permanently."
        ttk.Label(warning_frame, text=message, 
                wraplength=380, justify="center").pack(pady=(0, 20))
        
        # Buttons
        button_frame = ttk.Frame(warning_frame)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        result = [False]  
        
        def on_yes():
            result[0] = True
            warning_window.destroy()
        
        def on_no():
            result[0] = False
            warning_window.destroy()
        
        no_btn = ttk.Button(button_frame, text="Cancel", style="Secondary.TButton", command=on_no)
        no_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        yes_btn = ttk.Button(button_frame, text="Yes, Replace My Wallet", style="Accent.TButton", command=on_yes)
        yes_btn.pack(side=tk.RIGHT)
            
        # Wait for user response
        warning_window.wait_window()
        
        if not result[0]:
            return
    
    # Main import window using the dialog creator function
    import_window, main_frame = gui.create_centered_dialog(
        parent=app.root,
        title="Import Wallet",
        min_width=450,
        min_height=580
    )
    
    # Header
    ttk.Label(main_frame, text="Import Existing Wallet", 
            font=("Inter", 16, "bold"), 
            foreground=gui.CURRENT_COLORS["accent_primary"]).pack(anchor="w", pady=(0, 5))
    
    ttk.Label(main_frame, text="Enter your wallet's private key", 
            font=("Inter", 11),
            foreground=gui.CURRENT_COLORS["text_secondary"]).pack(anchor="w", pady=(0, 20))
    
    # Security warning box
    warning_bg = gui.CURRENT_COLORS["bg_secondary"]
    warning_fg = gui.CURRENT_COLORS["warning"]
    
    warning_frame = tk.Frame(main_frame, bg=warning_bg, padx=15, pady=15)
    warning_frame.pack(fill=tk.X, pady=(0, 20))
    
    tk.Label(warning_frame, 
          text="⚠️ WARNING: Never share your private key",
          wraplength=380, justify="left",
          font=("Inter", 11, "bold"),
          bg=warning_bg, fg=warning_fg).pack(anchor="w")
    
    tk.Label(warning_frame, 
          text="Only import your private key on devices you trust. Anyone with your private key can access your wallet.",
          wraplength=380, justify="left",
          font=("Inter", 10),
          bg=warning_bg, fg=warning_fg).pack(anchor="w", pady=(5, 0))
    
    # Private key entry
    ttk.Label(main_frame, text="Private Key").pack(anchor="w", pady=(0, 5))
    
    from tkinter import StringVar
    pk_var = StringVar()
    pk_entry = ttk.Entry(main_frame, textvariable=pk_var, width=40)
    pk_entry.pack(fill=tk.X, pady=(0, 10))
    pk_entry.focus_set()
    
    # Add paste button for convenience
    def paste_from_clipboard():
        try:
            pk_entry.delete(0, tk.END)
            pk_entry.insert(0, app.root.clipboard_get())
        except:
            pass
    
    paste_btn = ttk.Button(main_frame, text="Paste from Clipboard", 
                        command=paste_from_clipboard,
                        style="Secondary.TButton")
    paste_btn.pack(anchor="w", pady=(0, 20))
    
    # Password section
    ttk.Label(main_frame, text="Encrypt with Password", 
            font=("Inter", 12, "bold")).pack(anchor="w", pady=(0, 10))
    
    ttk.Label(main_frame, text="This will encrypt your private key").pack(anchor="w", pady=(0, 5))
            
    # Password field 
    pw_frame = ttk.Frame(main_frame)
    pw_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(pw_frame, text="Password:").pack(side=tk.LEFT, padx=(0, 10))
    
    pw_var = StringVar()
    pw_entry = ttk.Entry(pw_frame, textvariable=pw_var, show="•")
    pw_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)
    
    # Confirm password field
    confirm_frame = ttk.Frame(main_frame)
    confirm_frame.pack(fill=tk.X, pady=(0, 20))
    
    ttk.Label(confirm_frame, text="Confirm:").pack(side=tk.LEFT, padx=(0, 10))
    
    confirm_var = StringVar()
    confirm_entry = ttk.Entry(confirm_frame, textvariable=confirm_var, show="•")
    confirm_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)
    
    # Error message label (initially empty)
    error_label = ttk.Label(main_frame, text="", foreground=gui.CURRENT_COLORS["error"])
    error_label.pack(pady=(0, 20))
    
    # Buttons
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(fill=tk.X, side=tk.BOTTOM)
    
    def cancel():
        import_window.destroy()
    
    def import_key():
        # Get the private key
        private_key = pk_var.get().strip()
        
        # Validate private key
        if not private_key:
            error_label.config(text="Please enter a private key")
            pk_entry.focus_set()
            return
            
        # Verify private key format (should be a 64-character hex string)
        if private_key.startswith("0x"):
            private_key = private_key[2:]
            
        if not all(c in "0123456789abcdefABCDEF" for c in private_key) or len(private_key) != 64:
            error_label.config(text="Invalid private key format")
            pk_entry.focus_set()
            return
            
        # Check password
        password = pw_var.get()
        confirm = confirm_var.get()
        
        if not password:
            error_label.config(text="Please enter a password")
            pw_entry.focus_set()
            return
            
        if password != confirm:
            error_label.config(text="Passwords don't match")
            confirm_entry.focus_set()
            return
            
        # Passwords match, now encrypt and save the wallet
        if encrypt_wallet(app, private_key, password):
            # Load the wallet
            from autonomi_client import Wallet
            app.wallet = Wallet(private_key)
            app.wallet_address_label.config(text=f"Wallet: {app.wallet.address()}")
            import asyncio
            asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
            
            # Close all windows
            import_window.destroy()
            if wallet_window:
                wallet_window.destroy()
                
            # Show success message
            messagebox.showinfo("Success", "Wallet imported successfully")
        else:
            error_label.config(text="Failed to save wallet file")
    
    cancel_btn = ttk.Button(button_frame, text="Cancel", 
                         command=cancel,
                         style="Secondary.TButton")
    cancel_btn.pack(side=tk.LEFT)
    
    import_btn = ttk.Button(button_frame, text="Import Wallet", 
                         command=import_key,
                         style="Accent.TButton")
    import_btn.pack(side=tk.RIGHT)
    
    # Bind keyboard shortcuts
    import_window.bind("<Return>", lambda e: import_key())
    import_window.bind("<Escape>", lambda e: cancel())

def generate_keys():
    """Generate a new Ethereum private key."""
    import secrets
    private_key = "0x" + secrets.token_hex(32)
    return private_key

def create_wallet(app, wallet_window=None):
    """Create a new wallet."""
    try:
        # Check if wallet already exists and warn user
        if os.path.exists(app.wallet_file):
            # Create a properly styled and positioned confirmation dialog
            import gui
            
            confirm_window, frame = gui.create_centered_dialog(
                parent=app.root,
                title="Wallet Exists",
                min_width=450,
                min_height=250
            )
            
            # Warning icon instead of question mark
            ttk.Label(frame, text="⚠️", font=("Inter", 32), 
                    foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 10))
            
            # Warning message
            message = "A wallet file already exists. Creating a new wallet will overwrite the existing one. Continue?"
            ttk.Label(frame, text=message, 
                   wraplength=400, justify="center").pack(pady=(0, 20))
            
            # Buttons
            button_frame = ttk.Frame(frame, style="TFrame")
            button_frame.pack(fill=tk.X, side=tk.BOTTOM)
            
            def on_no():
                confirm_window.destroy()
                return
                
            def on_yes():
                confirm_window.destroy()
                # Continue with wallet creation
                _create_wallet_after_confirmation(app, wallet_window)
            
            # No button
            no_btn = ttk.Button(button_frame, text="No", 
                             command=on_no,
                             style="Secondary.TButton")
            no_btn.pack(side=tk.LEFT, padx=10)
            
            # Yes button
            yes_btn = ttk.Button(button_frame, text="Yes", 
                              command=on_yes,
                              style="Accent.TButton")
            yes_btn.pack(side=tk.RIGHT, padx=10)
            
            # Wait for user response
            app.root.wait_window(confirm_window)
            return
        else:
            _create_wallet_after_confirmation(app, wallet_window)
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        app.logger.error(f"Error creating wallet: {error_msg}\n{traceback_str}")
        messagebox.showerror("Error", f"Failed to create wallet: {error_msg}")

def _create_wallet_after_confirmation(app, wallet_window=None):
    """Continue wallet creation after confirmation."""
    # Get the password for the new wallet
    password = get_wallet_password(app, create=True)
    
    if not password:
        return  # User cancelled
    
    # Generate a new private key
    private_key = generate_keys()
    
    # Encrypt and save the wallet
    success = encrypt_wallet(app, private_key, password)
    if success:
        messagebox.showinfo("Success", "Wallet created successfully.")
        
        # Load the wallet right away
        from autonomi_client import Wallet
        app.wallet = Wallet(private_key)
        app.wallet_address_label.config(text=f"Wallet: {app.wallet.address()}")
        import asyncio
        asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
        
        # Close the wallet window if it exists
        if wallet_window:
            wallet_window.destroy()
    else:
        messagebox.showerror("Error", "Failed to create wallet.")

def _show_wallet_created_info(app, address, pk_display):
    """Unused variant of wallet creation info display."""
    info_window = tk.Toplevel(app.root)
    info_window.title("New Wallet Info")
    info_window.minsize(400, 250)
    info_window.resizable(True, True)
    
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

def prompt_wallet_password(app, callback, download_only=False):
    """Prompts for wallet password and loads wallet if valid."""
    if not os.path.exists(app.wallet_file):
        callback(False)
        return
    
    # Use the new password dialog function
    password = get_wallet_password(app, create=False)
    
    if password:
        # Try to load the wallet with the provided password
        private_key = decrypt_wallet(app, password)
        if private_key:
            try:
                from autonomi_client import Wallet
                app.wallet = Wallet(private_key)
                app.wallet_address_label.config(text=f"Wallet: {app.wallet.address()}")
                import asyncio
                asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
                
                # Hide the unlock button if it exists
                if hasattr(app, 'unlock_button'):
                    app.unlock_button.pack_forget()
                
                callback(True)
                return
            except Exception as e:
                show_styled_error(app, "Error", f"Invalid wallet data: {str(e)}")
                callback(False)
                return
        else:
            show_styled_error(app, "Error", "Incorrect password")
            callback(False)
            return
    
    # If password is None, it means user canceled
    was_canceled = True
    
    if download_only:
        callback(True)
    else:
        callback(False, was_canceled)

def _prompt_password(app, message, callback, parent_window=None):
    """Prompts user for wallet password."""
    if parent_window is None:
        parent_window = app.root
    
    import gui
    from tkinter import StringVar, TclError
    
    # Use the new dialog creator function for consistent sizing and positioning
    password_window, main_frame = gui.create_centered_dialog(
        parent=parent_window,
        title="Wallet Password",
        min_width=400,
        min_height=200
    )
    
    # Header
    ttk.Label(main_frame, text="Authentication Required", 
                       font=("Inter", 14, "bold"), 
              foreground=gui.CURRENT_COLORS["accent_primary"]).pack(anchor="w", pady=(0, 10))
    
    # Password message
    ttk.Label(main_frame, 
        text=message, 
              wraplength=350).pack(pady=(0, 15))
    
    # Password entry
    pw_var = StringVar()
    pw_entry = ttk.Entry(main_frame, 
                   textvariable=pw_var,
                   show="•", 
                         width=30)
    pw_entry.pack(fill="x", pady=(0, 15))
    pw_entry.focus_set()
    
    # Footer with buttons
    footer_frame = ttk.Frame(main_frame, style="TFrame")
    footer_frame.pack(fill="x", pady=(0, 0))
    
    def on_submit():
        password = pw_var.get()
        try:
            password_window.destroy()
            callback(password)
        except TclError:
            pass
    
    def on_cancel():
        try:
            password_window.destroy()
            callback(None)
        except TclError:
            pass
    
    # Cancel button
    cancel_btn = ttk.Button(footer_frame, 
                      text="Cancel",
                      command=on_cancel,
                          style="Secondary.TButton")
    cancel_btn.pack(side="left")
    
    # Confirm button
    ok_btn = ttk.Button(footer_frame, 
                  text="Confirm",
                  command=on_submit,
                      style="Accent.TButton")
    ok_btn.pack(side="right")
    
    # Bind enter key to submit
    password_window.bind("<Return>", lambda e: on_submit())
    password_window.bind("<Escape>", lambda e: on_cancel())
    password_window.protocol("WM_DELETE_WINDOW", on_cancel)

def display_private_key(app, parent_window=None):
    """Shows private key after confirming wallet password."""
    app.logger.info("display_private_key function called.")
    # First check if wallet exists
    if not os.path.exists(app.wallet_file):
        app.logger.warning("Wallet file not found in display_private_key.")
        show_styled_error(app, "Error", "No wallet file found. Create or import a wallet first.", parent_window)
        return
        
    # Create a confirmation dialog
    import gui
    app.logger.info("Creating password confirmation dialog for private key.")
    # Use the new dialog creator function for consistent sizing
    confirm_window, frame = gui.create_centered_dialog(
        parent=app.root,
        title="Security Verification",
        min_width=450,
        min_height=400,
        topmost=True,
        parent_window=parent_window if parent_window else app.root
    )
    
    # Warning icon and header
    ttk.Label(frame, text="⚠️", font=("Inter", 24), 
             foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 10))
    ttk.Label(frame, text="Security Verification Required", 
             font=("Inter", 16, "bold")).pack(pady=(0, 10))
    
    # Warning message
    message = "Your private key provides full access to your wallet and funds. For security, you must enter your password to view it."
    ttk.Label(frame, text=message, wraplength=380, justify="center").pack(pady=(0, 20))
    
    # Security notice - using custom bg/fg colors for dark mode compatibility
    security_bg = gui.CURRENT_COLORS["bg_secondary"]
    security_fg = gui.CURRENT_COLORS["text_secondary"]
    
    security_frame = tk.Frame(frame, bg=security_bg, padx=10, pady=10, bd=0, highlightthickness=0)
    security_frame.pack(fill=tk.X, pady=(0, 20))
    
    security_label = tk.Label(security_frame, 
                           text="🔒 Never share your private key with anyone. No legitimate support person will ever ask for it.",
                           justify="left", wraplength=380,
                           fg=security_fg, bg=security_bg,
                           font=("Inter", 9, "italic"))
    security_label.pack()
    
    # Password input
    input_frame = ttk.Frame(frame)
    input_frame.pack(fill=tk.X, pady=(0, 20))
    
    ttk.Label(input_frame, text="Password:").pack(side=tk.LEFT, padx=(0, 10))
    
    from tkinter import StringVar
    password_var = StringVar()
    password_entry = ttk.Entry(input_frame, textvariable=password_var, show="•", width=20)
    password_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
    password_entry.focus_set()
    
    # Buttons
    button_frame = ttk.Frame(frame)
    button_frame.pack(fill=tk.X, side=tk.BOTTOM)
    
    cancel_btn = ttk.Button(button_frame, text="Cancel", 
                         style="Secondary.TButton",
                         command=confirm_window.destroy)
    cancel_btn.pack(side=tk.LEFT)
    
    def on_submit():
        app.logger.info("Password submitted for private key view.")
        password = password_var.get()
        if not password:
            app.logger.warning("Empty password submitted.")
            show_styled_error(app, "Error", "Please enter your password")
            return
            
        private_key = decrypt_wallet(app, password)
        if not private_key:
            app.logger.warning("Incorrect password submitted for private key view.")
            show_styled_error(app, "Error", "Incorrect password")
            return
            
        # Correctly indented block: Destroy confirm window and show key *after* successful decryption
        app.logger.info("Password correct, showing private key.")
        confirm_window.destroy()
        _show_private_key(app, private_key, parent_window)
    
    submit_btn = ttk.Button(button_frame, text="Submit", 
                         style="Accent.TButton",
                         command=on_submit)
    submit_btn.pack(side=tk.RIGHT)
    
    # Bind Enter key
    confirm_window.bind("<Return>", lambda e: on_submit())
    confirm_window.bind("<Escape>", lambda e: confirm_window.destroy())

def _show_private_key(app, private_key, parent_window=None):
    """Displays the private key in a secure dialog."""
    import gui
    
    # Use the new dialog creator function for consistent sizing
    key_window, main_frame = gui.create_centered_dialog(
        parent=app.root,
        title="Private Key",
        min_width=550,
        min_height=580,
        topmost=True,
        parent_window=parent_window if parent_window else app.root
    )
    
    # Header - with high contrast color
    header_color = gui.CURRENT_COLORS["accent_primary"]
    ttk.Label(main_frame, text="Your Private Key", 
          font=("Inter", 18, "bold"), 
            foreground=header_color).pack(anchor="w", pady=(0, 15))
    
    # Top warning - using native Frame with background color
    warning_bg = gui.CURRENT_COLORS["bg_secondary"]
    warning_fg = gui.CURRENT_COLORS["warning"]
    
    warning_frame = tk.Frame(main_frame, bg=warning_bg,
                          padx=10, pady=10, bd=0, highlightthickness=0)
    warning_frame.pack(fill=tk.X, pady=(0, 15))
    
    tk.Label(warning_frame, 
           text="⚠️ WARNING: Never share your private key with anyone or enter it on any website.",
           fg=warning_fg, bg=warning_bg,
           font=("Inter", 10, "bold"),
           wraplength=480, justify="left").pack(anchor="w")
    
    tk.Label(warning_frame, 
           text="Anyone with your private key can access and steal your funds.",
           fg=warning_fg, bg=warning_bg,
          font=("Inter", 10),
           wraplength=480, justify="left").pack(anchor="w", pady=(5, 0))
    
    # Private Key Display
    key_frame = ttk.Frame(main_frame, padding=15)
    key_frame.pack(fill=tk.X, pady=(0, 15))
    
    # First show a partially hidden key (first 6 chars + ... + last 4 chars)
    hidden_key = private_key[:6] + "..." + private_key[-4:]
    
    reveal_var = tk.BooleanVar(value=False)
    key_text_var = tk.StringVar(value=hidden_key)
    
    # Key display field (read-only)
    key_display = ttk.Entry(key_frame, 
                          textvariable=key_text_var, 
                          state="readonly",
                          width=40)
    key_display.pack(fill=tk.X, pady=(0, 10))
    
    def toggle_reveal():
        if reveal_var.get():
            key_text_var.set(private_key)
        else:
            key_text_var.set(hidden_key)
    
    # Reveal checkbox
    reveal_check = ttk.Checkbutton(key_frame, 
                                text="Show full private key", 
                                variable=reveal_var,
                                command=toggle_reveal)
    reveal_check.pack(anchor="w")
    
    # QR code if PIL is available
    try:
        # If QR code support is available
        import qrcode
        from PIL import Image, ImageTk
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=5,
            border=4,
        )
        qr.add_data(private_key)
        qr.make(fit=True)
        
        # Create image with appropriate colors
        fill_color = "black" if not hasattr(app, 'is_dark_mode') or not app.is_dark_mode else "white"
        back_color = "white" if not hasattr(app, 'is_dark_mode') or not app.is_dark_mode else "#1E1E1E"
        
        img = qr.make_image(fill_color=fill_color, back_color=back_color)
        
        # Convert to PhotoImage
        photo_img = ImageTk.PhotoImage(img)
        
        # QR Code Label
        ttk.Label(main_frame, text="QR Code:", 
                font=("Inter", 12, "bold")).pack(anchor="w", pady=(10, 5))
        
        # QR code container
        qr_frame = ttk.Frame(main_frame)
        qr_frame.pack(pady=(0, 15))
        
        # QR code image
        qr_label = ttk.Label(qr_frame, image=photo_img)
        qr_label.image = photo_img  # Keep reference to prevent GC
        qr_label.pack()
        
    except (ImportError, Exception) as e:
        # QR code support not available
        error_msg = f"QR code generation unavailable: {str(e)}"
        app.logger.warning(error_msg)
        ttk.Label(main_frame, text="QR code generation unavailable.", 
                font=("Inter", 10, "italic"),
                foreground=gui.CURRENT_COLORS["text_secondary"]).pack(pady=(10, 15))
    
    # Copy button
    copy_frame = ttk.Frame(main_frame)
    copy_frame.pack(fill=tk.X, pady=(0, 15))
    
    def copy_to_clipboard():
        app.root.clipboard_clear()
        app.root.clipboard_append(private_key)
        status_label.config(text="✓ Private key copied to clipboard!")
        
        # Reset message after 3 seconds
        key_window.after(3000, lambda: status_label.config(text=""))
    
    copy_btn = ttk.Button(copy_frame, text="Copy to Clipboard", 
                      command=copy_to_clipboard,
                      style="Secondary.TButton")
    copy_btn.pack(side=tk.LEFT)
    
    # Status label for copy confirmation
    status_label = ttk.Label(copy_frame, text="", 
                          foreground=gui.CURRENT_COLORS["success"])
    status_label.pack(side=tk.LEFT, padx=(10, 0))
    
    # Close button
    close_btn = ttk.Button(main_frame, text="Close", 
                        command=key_window.destroy,
                        style="Accent.TButton")
    close_btn.pack(side=tk.RIGHT, pady=(20, 0))
    
    # Bind escape key
    key_window.bind("<Escape>", lambda e: key_window.destroy())

def show_styled_error(app, title, message, parent=None):
    """Shows a styled error dialog that's always visible on top."""
    import gui
    
    # Use the new dialog creator function for consistent sizing and positioning
    error_window, main_frame = gui.create_centered_dialog(
        parent=parent if parent else app.root,
        title=title,
        min_width=400,
        min_height=200
    )
    
    # Error icon and message
    icon_frame = ttk.Frame(main_frame)
    icon_frame.pack(pady=(0, 15))
    
    # Error icon
    ttk.Label(icon_frame, text="⛔", font=("Inter", 24), 
             foreground=gui.CURRENT_COLORS["error"]).pack()
    
    # Error message
    ttk.Label(main_frame, text=message, 
             font=("Inter", 11), 
             wraplength=350, 
             justify="center").pack(pady=(0, 20))
    
    # OK button
    ok_btn = ttk.Button(main_frame, text="OK", 
                      command=error_window.destroy,
                      style="Accent.TButton")
    ok_btn.pack()
    
    error_window.bind("<Return>", lambda e: error_window.destroy())
    error_window.bind("<Escape>", lambda e: error_window.destroy())
    
    # Return focus to parent if provided
    if parent:
        error_window.wait_window()
        try:
            parent.focus_set()
        except:
            pass
    
    return error_window

def send_funds(app, wallet_window=None):
    """Handles sending ETH or ANT from wallet."""
    if not app.wallet:
        show_styled_error(app, "Error", "No wallet loaded")
        return

    # Very explicit coloring for debugging
    import gui
    is_dark = hasattr(app, 'is_dark_mode') and app.is_dark_mode
    
    # Create main window with fixed colors
    send_window = tk.Toplevel(app.root)
    send_window.title("Send Funds")
    send_window.geometry("500x700")
    send_window.configure(bg="#222222")  # Dark gray
    send_window.transient(app.root)
    send_window.grab_set()
    send_window.lift()
    send_window.focus_force()
    send_window.attributes("-topmost", True)
    # Ensure resizable
    send_window.resizable(True, True)
    
    # Main content container - force a specific layout
    main_container = tk.Frame(send_window, bg="#222222", padx=20, pady=20)
    main_container.pack(fill=tk.BOTH, expand=True)
    
    # Header with title
    header = tk.Label(main_container, text="Send Funds",
                   font=("Inter", 18, "bold"),
                   fg="#8B5CF6", bg="#222222")  # Purple text on dark gray
    header.pack(anchor=tk.W, pady=(0, 5))
    
    subtitle = tk.Label(main_container, text="Transfer ETH or ANT tokens to another address",
                      font=("Inter", 12),
                      fg="#AAAAAA", bg="#222222")  # Light gray on dark gray
    subtitle.pack(anchor=tk.W, pady=(0, 20))
    
    # Recipient section
    recipient_label = tk.Label(main_container, text="Recipient Address",
                            font=("Inter", 13, "bold"),
                            fg="#FFFFFF", bg="#222222")  # White on dark gray
    recipient_label.pack(anchor=tk.W, pady=(0, 5))
    
    recipient_entry = tk.Entry(main_container, 
                            bg="#111111",  # Very dark gray
                            fg="#FFFFFF",  # White text
                            insertbackground="#FFFFFF",  # White cursor
                            font=("Inter", 11))
    recipient_entry.pack(fill=tk.X, pady=(0, 5))
    
    # Enable clipboard operations
    from gui import add_context_menu
    add_context_menu(recipient_entry)
    
    recipient_help = tk.Label(main_container, text="Enter the full wallet address (0x...)",
                           font=("Inter", 10),
                           fg="#AAAAAA", bg="#222222")  # Light gray on dark gray
    recipient_help.pack(anchor=tk.W, pady=(0, 20))
    
    # Amount section
    amount_label = tk.Label(main_container, text="Amount to Send",
                         font=("Inter", 13, "bold"),
                         fg="#FFFFFF", bg="#222222")  # White on dark gray
    amount_label.pack(anchor=tk.W, pady=(0, 5))
    
    amount_entry = tk.Entry(main_container, 
                         bg="#111111",  # Very dark gray
                         fg="#FFFFFF",  # White text
                         insertbackground="#FFFFFF",  # White cursor
                         font=("Inter", 11))
    amount_entry.pack(fill=tk.X, pady=(0, 5))
    
    amount_help = tk.Label(main_container, text="Enter the amount to send",
                        font=("Inter", 10),
                        fg="#AAAAAA", bg="#222222")  # Light gray on dark gray
    amount_help.pack(anchor=tk.W, pady=(0, 20))
    
    # Currency selection
    currency_label = tk.Label(main_container, text="Choose Currency",
                           font=("Inter", 13, "bold"),
                           fg="#FFFFFF", bg="#222222")  # White on dark gray
    currency_label.pack(anchor=tk.W, pady=(0, 10))
    
    currency_var = tk.StringVar(value="ETH")
    
    currency_frame = tk.Frame(main_container, bg="#222222")
    currency_frame.pack(fill=tk.X, pady=(0, 20))
    
    eth_radio = tk.Radiobutton(currency_frame, text="ETH (Ethereum)",
                             variable=currency_var, value="ETH",
                             fg="#FFFFFF", bg="#222222",
                             selectcolor="#111111",
                             font=("Inter", 11))
    eth_radio.pack(side=tk.LEFT, padx=(0, 20))
    
    ant_radio = tk.Radiobutton(currency_frame, text="ANT (Autonomi Token)",
                             variable=currency_var, value="ANT",
                             fg="#FFFFFF", bg="#222222",
                             selectcolor="#111111",
                             font=("Inter", 11))
    ant_radio.pack(side=tk.LEFT)
    
    # Security notice
    security_frame = tk.Frame(main_container, bg="#111111", padx=15, pady=15)
    security_frame.pack(fill=tk.X, pady=(0, 20))
    
    security_label = tk.Label(security_frame, text="⚠️ Security Notice",
                           font=("Inter", 11, "bold"),
                           fg="#F59E0B", bg="#111111")  # Yellow on very dark gray
    security_label.pack(anchor=tk.W, pady=(0, 5))
    
    security_text = "• Double-check the recipient address before sending\n"\
                   "• Transactions cannot be reversed once sent\n"\
                   "• Make sure you have enough funds for transaction fees"
    security_notice = tk.Label(security_frame, text=security_text,
                             font=("Inter", 10),
                             fg="#AAAAAA", bg="#111111",  # Light gray on very dark gray
                             justify=tk.LEFT)
    security_notice.pack(anchor=tk.W)
    
    # Action buttons at the bottom
    button_frame = tk.Frame(main_container, bg="#222222")
    button_frame.pack(fill=tk.X, pady=(10, 0))
    
    cancel_btn = tk.Button(button_frame, text="Cancel",
                        bg="#444444", fg="#FFFFFF",  # Gray button with white text
                        activebackground="#555555", activeforeground="#FFFFFF",
                        font=("Inter", 11), padx=15, pady=8,
                        relief=tk.FLAT, bd=0,
                        command=send_window.destroy)
    cancel_btn.pack(side=tk.LEFT)
    
    async def do_send():
        app.logger.info("do_send coroutine started")
        recipient = recipient_entry.get().strip()
        amount_str = amount_entry.get().strip()
        currency = currency_var.get()
        
        app.logger.info(f"Processing transaction: recipient={recipient}, amount={amount_str}, currency={currency}")
        if not app.w3.is_address(recipient):
            app.logger.error(f"Invalid recipient address: {recipient}")
            show_styled_error(app, "Error", "Invalid recipient address. It should start with '0x' and be 42 characters long.")
            return
        
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            app.logger.info(f"Validated amount: {amount}")
        except ValueError as e:
            app.logger.error(f"Invalid amount: {str(e)}")
            show_styled_error(app, "Error", "Invalid amount. Enter a positive number (e.g., 0.1).")
            return
            
        # Create transaction confirmation dialog
        confirm_window = tk.Toplevel(send_window)  # Use send_window as parent
        confirm_window.title("Confirm Transaction")
        confirm_window.geometry("450x300")
        confirm_window.configure(bg="#222222")
        confirm_window.transient(send_window)
        confirm_window.grab_set()
        confirm_window.lift()
        confirm_window.focus_force()
        confirm_window.attributes("-topmost", True)
        
        # Container frame - use tk.Frame with explicit background instead of ttk
        frame = tk.Frame(confirm_window, bg="#222222", padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Warning icon and header with proper background
        tk.Label(frame, text="⚠️", font=("Inter", 24), 
             fg="#F59E0B",
             bg="#222222").pack(pady=(0, 10))
             
        tk.Label(frame, text="Confirm Transaction", 
             font=("Inter", 14, "bold"),
             fg="#FFFFFF",
             bg="#222222").pack(pady=(0, 15))
        
        # Transaction details with proper background
        details_text = f"Send {amount} {currency} to:\n{recipient}"
        tk.Label(frame, text=details_text, 
               wraplength=380, justify="center",
               fg="#FFFFFF",
               bg="#222222").pack(pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(frame, bg="#222222")
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        tx_confirmed = [False]  # Use a list to store the result
        
        def on_confirm():
            tx_confirmed[0] = True
            confirm_window.destroy()
        
        def on_cancel():
            tx_confirmed[0] = False
            confirm_window.destroy()
        
        # Cancel button with proper colors
        cancel_btn = tk.Button(button_frame, text="Cancel", 
                            bg="#444444", fg="#FFFFFF",
                            activebackground="#555555", activeforeground="#FFFFFF",
                            font=("Inter", 10), padx=10, pady=5,
                            relief=tk.FLAT, bd=0,
                            command=on_cancel)
        cancel_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Confirm button with proper colors
        confirm_btn = tk.Button(button_frame, text="Confirm Send", 
                             bg="#8B5CF6", fg="#FFFFFF",
                             activebackground="#9F7AEA", activeforeground="#FFFFFF",
                             font=("Inter", 10), padx=10, pady=5,
                             relief=tk.FLAT, bd=0,
                             command=on_confirm)
        confirm_btn.pack(side=tk.RIGHT)
        
        # Make sure confirm button has focus
        confirm_btn.focus_set()
        
        # Wait for user response
        app.root.wait_window(confirm_window)
        
        if not tx_confirmed[0]:
            app.logger.info("Transaction cancelled by user")
            return
                
        # Password confirmation
        from queue import Queue
        password_queue = Queue()
        
        def set_password(password):
            app.logger.info("Password submitted to queue")
            password_queue.put(password)
            
        app.logger.info("Launching password prompt")
        _prompt_password(app, "Enter password to sign transaction:", set_password, parent_window=send_window)
        password = await app.loop.run_in_executor(None, lambda: password_queue.get())
        
        app.logger.info(f"Password received: {password is not None}")
        if not password:
            app.logger.warning("No password provided")
            return
            
        private_key = decrypt_wallet(app, password)
        if not private_key:
            app.logger.error("Failed to decrypt wallet with provided password")
            show_styled_error(app, "Error", "Incorrect password")
            return
            
        app.is_processing = True
        app._current_operation = 'transaction'
        app.start_status_animation()
        
        try:
            app.logger.info("Preparing transaction")
            latest_block = app.w3.eth.get_block('latest')
            base_fee = latest_block['baseFeePerGas']
            max_priority_fee = app.w3.eth.max_priority_fee  # Fetch a suggested priority fee
            max_fee_per_gas = int(max(base_fee * 1.1, base_fee + max_priority_fee))  # Convert to integer
            max_priority_fee = int(max_priority_fee)  # Convert to integer
            
            from web3 import Web3
            
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
                app.logger.info("Signed ETH transaction")
                tx_hash = app.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            else:  # ANT
                ant_contract = app.w3.eth.contract(address=ANT_TOKEN_ADDRESS, abi=ANT_ABI)
                app.logger.info("Fetching ANT balance")
                ant_balance = ant_contract.functions.balanceOf(app.wallet.address()).call() / 10**18
                if amount > ant_balance:
                    raise ValueError(f"Insufficient ANT balance: {ant_balance} available")
                    
                amount_wei = int(amount * 10**18)
                app.logger.info(f"Estimating gas for ANT transfer of {amount_wei} wei")
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
                app.logger.info("Signed ANT transaction")
                tx_hash = app.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            app.logger.info(f"Transaction sent, hash: {tx_hash.hex()}")
            
            # Custom success popup with TX hash
            success_window = tk.Toplevel(send_window)  # Use send_window as parent
            success_window.title("Transaction Sent")
            success_window.geometry("500x300")
            success_window.configure(bg="#222222")
            success_window.transient(send_window)
            success_window.grab_set()
            success_window.lift()
            success_window.focus_force()
            success_window.attributes("-topmost", True)
            
            # Instead of using ttk Frame, use a regular frame with explicit background color
            success_frame = tk.Frame(success_window, bg="#222222", padx=20, pady=20)
            success_frame.pack(fill=tk.BOTH, expand=True)
            
            # Success icon with properly themed background
            tk.Label(success_frame, text="✅", font=("Inter", 24), 
                  fg="#10B981", 
                  bg="#222222").pack(pady=(0, 10))
                  
            # Text with properly themed background
            tk.Label(success_frame, text=f"Sent {amount} {currency} Successfully", 
                  font=("Inter", 14, "bold"),
                  fg="#FFFFFF", 
                  bg="#222222").pack(pady=(0, 10))
            
            # Transaction hash frame with proper theming
            tx_hash_frame = tk.Frame(success_frame, bg="#333333", padx=10, pady=10)
            tx_hash_frame.pack(fill=tk.X, pady=(5, 15))
            
            # Transaction hash label with proper background
            tk.Label(tx_hash_frame, text="Transaction Hash:", 
                  font=("Inter", 10, "bold"),
                  fg="#FFFFFF",
                  bg="#333333").pack(anchor="w")
                  
            # Entry widget for transaction hash with dark mode styling
            tx_hash_text = tk.Entry(tx_hash_frame, font=("Inter", 9),
                                 bg="#111111", fg="#FFFFFF",
                                 readonlybackground="#111111")
            tx_hash_text.insert(0, tx_hash.hex())
            tx_hash_text.configure(state="readonly")
            tx_hash_text.pack(fill=tk.X, pady=(5, 0))
            
            # Copy button frame with correct background
            copy_btn_frame = tk.Frame(tx_hash_frame, bg="#333333")
            copy_btn_frame.pack(anchor="e", pady=(5, 0))
            
            # Copy button function
            def copy_tx_hash():
                app.root.clipboard_clear()
                app.root.clipboard_append(tx_hash.hex())
                # Silent copy without messagebox
                success_window.lift()
                success_window.focus_force()
            
            # Styled copy button that matches theme    
            copy_btn = tk.Button(copy_btn_frame, text="Copy Hash", 
                             bg="#444444", fg="#FFFFFF",
                             activebackground="#555555", activeforeground="#FFFFFF",
                             font=("Inter", 10), padx=10, pady=5,
                             relief=tk.FLAT, bd=0,
                             command=copy_tx_hash,
                             width=15)
            copy_btn.pack()
            
            # OK button with themed colors
            ok_btn = tk.Button(success_frame, text="OK", 
                           bg="#8B5CF6", fg="#FFFFFF",
                           activebackground="#9F7AEA", activeforeground="#FFFFFF",
                           font=("Inter", 10), padx=10, pady=5,
                           relief=tk.FLAT, bd=0,
                           command=success_window.destroy,
                           width=15)
            ok_btn.pack()
                
            # Make sure ok button has focus
            ok_btn.focus_set()
            
            # Wait for success window to close
            app.root.wait_window(success_window)
            
            # Update balances
            asyncio.create_task(app._update_balances())
            app.status_label.config(text=f"Sent {amount} {currency}")
            
            # Close windows
            send_window.destroy()
            if wallet_window:
                wallet_window.destroy()
                
        except Exception as e:
            import traceback
            error_msg = str(e)
            app.logger.error(f"Send {currency} failed: {error_msg}\n{traceback.format_exc()}")
            show_styled_error(app, "Error", f"Send failed: {error_msg}")
            # Re-focus on the send window after error
            send_window.lift()
            send_window.focus_force()
        finally:
            if 'private_key' in locals():
                # Zero out private key in memory for security
                private_key = bytearray(private_key.encode())
                for i in range(len(private_key)):
                    private_key[i] = 0
            app.is_processing = False
            app.stop_status_animation()
    
    # Send button
    send_btn = tk.Button(button_frame, text="Send Funds",
                     bg="#8B5CF6", fg="#FFFFFF",  # Purple button with white text
                     activebackground="#9F7AEA", activeforeground="#FFFFFF",
                     font=("Inter", 11), padx=15, pady=8,
                     relief=tk.FLAT, bd=0,
                     command=lambda: asyncio.run_coroutine_threadsafe(do_send(), app.loop))
    send_btn.pack(side=tk.RIGHT)
