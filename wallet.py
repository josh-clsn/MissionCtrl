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
        iterations=1000000,  # Increased from 600000 for better security
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
    from tkinter import Toplevel, Label, Entry, Button, StringVar, TclError
    import gui

    action = "Create" if create else "Unlock"
    pwd_window = Toplevel(app.root)
    pwd_window.title(f"Wallet Password")
    
    # Make window size fixed
    pwd_window.resizable(False, False)
    pwd_window.geometry("350x300" if create else "350x220")  # Increased height for better spacing
    pwd_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
    
    # Set window on top of other windows
    pwd_window.transient(app.root)
    pwd_window.lift()
    pwd_window.focus_force()
    pwd_window.grab_set()
    
    # Center window
    pwd_window.update_idletasks()
    width = pwd_window.winfo_width()
    height = pwd_window.winfo_height()
    x = (pwd_window.winfo_screenwidth() // 2) - (width // 2)
    y = (pwd_window.winfo_screenheight() // 2) - (height // 2)
    pwd_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    # Add a heading
    heading = Label(pwd_window, text=f"{action} Your Wallet", font=("Inter", 16, "bold"), 
                  fg=gui.CURRENT_COLORS["accent_primary"], bg=gui.CURRENT_COLORS["bg_light"])
    heading.pack(pady=(20, 5))
    
    # Add a subheading
    subtext = "Enter a strong password to secure your wallet" if create else "Enter your password to access your wallet"
    subheading = Label(pwd_window, text=subtext, 
                     fg=gui.CURRENT_COLORS["text_primary"], bg=gui.CURRENT_COLORS["bg_light"])
    subheading.pack(pady=(0, 20))
    
    # Create a frame for the password input
    input_frame = Label(pwd_window, bg=gui.CURRENT_COLORS["bg_light"], bd=0, highlightthickness=0)
    input_frame.pack(pady=5, fill="x", padx=30)
    
    # Add the password label and input
    pwd_label = Label(input_frame, text="Password:", bg=gui.CURRENT_COLORS["bg_light"], 
                    fg=gui.CURRENT_COLORS["text_primary"], anchor="w")
    pwd_label.pack(side="left", padx=(0, 5))
    
    pwd_var = StringVar()
    pwd_entry = Entry(input_frame, textvariable=pwd_var, show="*", width=25,
                    bg=gui.CURRENT_COLORS["bg_input"], 
                    fg=gui.CURRENT_COLORS["text_primary"],
                    insertbackground=gui.CURRENT_COLORS["text_primary"],
                    relief="solid", bd=1,
                    highlightthickness=1, highlightcolor=gui.CURRENT_COLORS["accent_primary"],
                    highlightbackground=gui.CURRENT_COLORS["border"])
    pwd_entry.pack(side="right", expand=True, fill="x")
    pwd_entry.focus_set()
    
    # Add password confirmation input if creating a new wallet
    confirm_frame = None
    confirm_var = StringVar()
    if create:
        # Create a frame for the password confirmation
        confirm_frame = Label(pwd_window, bg=gui.CURRENT_COLORS["bg_light"], bd=0, highlightthickness=0)
        confirm_frame.pack(pady=5, fill="x", padx=30)
        
        # Add the confirmation label and input
        confirm_label = Label(confirm_frame, text="Confirm:", bg=gui.CURRENT_COLORS["bg_light"], 
                            fg=gui.CURRENT_COLORS["text_primary"], anchor="w")
        confirm_label.pack(side="left", padx=(0, 5))
        
        confirm_entry = Entry(confirm_frame, textvariable=confirm_var, show="*", width=25,
                            bg=gui.CURRENT_COLORS["bg_input"], 
                            fg=gui.CURRENT_COLORS["text_primary"],
                            insertbackground=gui.CURRENT_COLORS["text_primary"],
                            relief="solid", bd=1,
                            highlightthickness=1, highlightcolor=gui.CURRENT_COLORS["accent_primary"],
                            highlightbackground=gui.CURRENT_COLORS["border"])
        confirm_entry.pack(side="right", expand=True, fill="x")
    
    # Error message label (initially hidden)
    error_label = Label(pwd_window, text="", 
                      fg=gui.CURRENT_COLORS["error"], bg=gui.CURRENT_COLORS["bg_light"])
    error_label.pack(pady=(5, 0))
    
    # Create a frame for the buttons
    button_frame = Label(pwd_window, bg=gui.CURRENT_COLORS["bg_light"], bd=0, highlightthickness=0)
    button_frame.pack(pady=(20, 25), side="bottom", fill="x", padx=15)
    
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
    ok_btn = Button(button_frame, text=btn_text, command=on_ok, width=10,
                  bg=gui.CURRENT_COLORS["accent_primary"], fg="white",
                  activebackground=gui.CURRENT_COLORS["accent_secondary"], 
                  activeforeground="white",
                  relief="flat", bd=0,
                  padx=10, pady=6)
    ok_btn.pack(side="right", padx=5)
    
    cancel_btn = Button(button_frame, text="Cancel", command=on_cancel, width=10,
                      bg=gui.CURRENT_COLORS["bg_secondary"], 
                      fg=gui.CURRENT_COLORS["text_primary"],
                      activebackground=gui.CURRENT_COLORS["bg_light"], 
                      activeforeground=gui.CURRENT_COLORS["text_primary"],
                      relief="flat", bd=0,
                      padx=10, pady=6)
    cancel_btn.pack(side="right", padx=5)
    
    # Apply theme if we're in dark mode
    if hasattr(app, 'is_dark_mode') and app.is_dark_mode:
        gui.apply_theme_to_toplevel(pwd_window, True)
    
    # Bind the Enter key to OK
    pwd_window.bind("<Return>", lambda event: on_ok())
    pwd_window.bind("<Escape>", lambda event: on_cancel())
    
    # Wait for user input
    app.root.wait_window(pwd_window)
    return result[0]

def delete_wallet(app, wallet_window=None):
    """Deletes wallet file after user confirmation."""
    # Create custom styled confirmation dialog
    confirm_window = tk.Toplevel(app.root)
    confirm_window.title("Confirm Deletion")
    confirm_window.geometry("450x250")
    confirm_window.configure(bg=COLORS["bg_light"])
    confirm_window.transient(wallet_window if wallet_window else app.root)
    confirm_window.grab_set()
    confirm_window.lift() 
    confirm_window.focus_force() 
    
    # Add window attributes to keep it on top
    confirm_window.attributes("-topmost", True)
    
    # Container frame
    frame = ttk.Frame(confirm_window, style="TFrame", padding=20)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Warning icon and header
    ttk.Label(frame, text="⚠️", font=("Inter", 24), foreground=COLORS["warning"]).pack(pady=(0, 10))
    ttk.Label(frame, text="Delete Wallet?", font=("Inter", 16, "bold")).pack(pady=(0, 10))
    
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
        success_window = tk.Toplevel(app.root)
        success_window.title("Success")
        success_window.geometry("400x200")
        success_window.configure(bg=COLORS["bg_light"])
        success_window.transient(app.root)
        success_window.grab_set()
        success_window.lift()
        success_window.focus_force()
        success_window.attributes("-topmost", True)
        
        success_frame = ttk.Frame(success_window, style="TFrame", padding=20)
        success_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(success_frame, text="✅", font=("Inter", 24), foreground=COLORS["success"]).pack(pady=(0, 10))
        ttk.Label(success_frame, text="Wallet Deleted Successfully", font=("Inter", 14, "bold")).pack(pady=(0, 20))
        
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
        if len(key) != 64:  # 32 bytes = 64 hex chars
            return False
            
        # Check if key is valid hex
        try:
            int(key, 16)  # will raise ValueError if not valid hex
        except ValueError:
            return False
        
        # We'll attempt to create a wallet, but we won't fail validation if it fails
        # This allows for keys that don't follow the expected format but are still valid
        try:
            from autonomi_client import Wallet
            wallet = Wallet(private_key)
            address = wallet.address()  # This will throw an exception if key is invalid
            
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
    # Check if wallet already exists and warn user with a more prominent dialog
    if os.path.exists(app.wallet_file):
        # Create custom styled warning dialog
        warning_window = tk.Toplevel(app.root)
        warning_window.title("Warning: Existing Wallet")
        warning_window.geometry("500x300")
        
        # Use proper theme colors
        import gui
        is_dark = hasattr(app, 'is_dark_mode') and app.is_dark_mode
        bg_color = "#1E1E1E" if is_dark else gui.CURRENT_COLORS["bg_light"]
        
        warning_window.configure(bg=bg_color)
        warning_window.transient(app.root)
        warning_window.grab_set()
        warning_window.lift()  
        warning_window.focus_force()  
        warning_window.attributes("-topmost", True) 
        
        # Container frame
        frame = ttk.Frame(warning_window, style="TFrame", padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Warning icon and header
        ttk.Label(frame, text="⚠️", font=("Inter", 32), foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 10))
        ttk.Label(frame, text="Replace Existing Wallet?", font=("Inter", 16, "bold"), foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 15))
        
        # Warning message
        message = "You already have a wallet. Creating a new one or importing another wallet will replace your current wallet.\n\nIf you haven't backed up your current wallet's private key, you may lose access to any funds it contains."
        ttk.Label(frame, text=message, wraplength=420, justify="center").pack(pady=(0, 20))
        
        # Buttons
        button_frame = ttk.Frame(frame, style="TFrame")
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
        
        # Apply theme if in dark mode
        if is_dark:
            gui.apply_theme_to_toplevel(warning_window, True)
            
        # Wait for user response
        warning_window.wait_window()
        
        if not result[0]:
            return
    
    # Main import window
    import_window = tk.Toplevel(app.root)
    import_window.title("Import Wallet")
    import_window.geometry("460x580")  # Increased height for password confirmation field
    import_window.minsize(450, 580)
    
    # Use proper theme colors
    import gui
    is_dark = hasattr(app, 'is_dark_mode') and app.is_dark_mode
    bg_color = "#1E1E1E" if is_dark else gui.CURRENT_COLORS["bg_light"]
    
    import_window.configure(bg=bg_color)
    import_window.transient(app.root)
    import_window.grab_set()
    import_window.lift() 
    import_window.focus_force() 
    import_window.attributes("-topmost", True) 
    
    # Header with proper colors
    header_frame = tk.Frame(import_window, bg=bg_color, padx=20, pady=20)
    header_frame.pack(fill=tk.X)
    
    header_color = "#7C3AED" if is_dark else gui.CURRENT_COLORS["accent_primary"]
    text_color = "#FFFFFF" if is_dark else gui.CURRENT_COLORS["text_primary"]
    secondary_color = "#E0E0E0" if is_dark else gui.CURRENT_COLORS["text_secondary"]
    
    tk.Label(header_frame, text="Import Existing Wallet", 
            font=("Inter", 16, "bold"), 
            fg=header_color,
            bg=bg_color).pack(anchor="w")
    
    tk.Label(header_frame, text="Use your private key to access your existing wallet", 
            font=("Inter", 11),
            fg=secondary_color,
            bg=bg_color).pack(anchor="w", pady=(5, 0))
    
    # Content frame with dark mode compatibility
    content_bg = "#2D2D2D" if is_dark else "#F5F7FA"
    content_frame = tk.Frame(import_window, bg=content_bg, padx=20, pady=20)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
    
    # Private Key Section
    key_frame = tk.Frame(content_frame, bg=content_bg)
    key_frame.pack(fill=tk.X, pady=(0, 15))
    
    tk.Label(key_frame, text="Private Key", 
            font=("Inter", 12, "bold"),
            fg=text_color,
            bg=content_bg).pack(anchor="w", pady=(0, 10))
    
    # Entry with improved styling
    pk_entry = tk.Entry(key_frame, width=50, show="•", 
                      bg="#121212" if is_dark else "#FFFFFF",
                      fg="#FFFFFF" if is_dark else "#000000",
                      insertbackground="#FFFFFF" if is_dark else "#000000",
                      relief="solid", bd=1)
    pk_entry.pack(fill=tk.X, pady=(0, 5))
    from gui import add_context_menu
    add_context_menu(pk_entry)
    
    tk.Label(key_frame, text="Enter your private key (starts with 0x)", 
            fg=secondary_color,
            bg=content_bg,
            font=("Inter", 9)).pack(anchor="w")
    
    # Password Section
    password_frame = tk.Frame(content_frame, bg=content_bg)
    password_frame.pack(fill=tk.X, pady=(0, 15))
    
    tk.Label(password_frame, text="Wallet Password", 
            font=("Inter", 12, "bold"),
            fg=text_color,
            bg=content_bg).pack(anchor="w", pady=(0, 10))
    
    # Password entry with better styling
    pw_entry = tk.Entry(password_frame, width=30, show="•",
                      bg="#121212" if is_dark else "#FFFFFF",
                      fg="#FFFFFF" if is_dark else "#000000",
                      insertbackground="#FFFFFF" if is_dark else "#000000",
                      relief="solid", bd=1)
    pw_entry.pack(fill=tk.X, pady=(0, 5))
    add_context_menu(pw_entry)
    
    tk.Label(password_frame, text="Create a strong password to encrypt your wallet", 
            fg=secondary_color,
            bg=content_bg,
            font=("Inter", 9)).pack(anchor="w")
            
    # Password Confirmation Section
    confirm_frame = tk.Frame(content_frame, bg=content_bg)
    confirm_frame.pack(fill=tk.X, pady=(0, 15))
    
    tk.Label(confirm_frame, text="Confirm Password", 
            font=("Inter", 12, "bold"),
            fg=text_color,
            bg=content_bg).pack(anchor="w", pady=(0, 10))
    
    # Confirmation entry with matching styling
    pw_confirm_entry = tk.Entry(confirm_frame, width=30, show="•",
                             bg="#121212" if is_dark else "#FFFFFF",
                             fg="#FFFFFF" if is_dark else "#000000",
                             insertbackground="#FFFFFF" if is_dark else "#000000",
                             relief="solid", bd=1)
    pw_confirm_entry.pack(fill=tk.X, pady=(0, 5))
    add_context_menu(pw_confirm_entry)
    
    tk.Label(confirm_frame, text="Re-enter your password to confirm", 
            fg=secondary_color,
            bg=content_bg,
            font=("Inter", 9)).pack(anchor="w")
    
    # Security notice
    security_bg = "#3D3D3D" if is_dark else "#E5E7EB"
    security_frame = tk.Frame(content_frame, bg=security_bg, padx=10, pady=10)
    security_frame.pack(fill=tk.X, pady=(5, 0))
    
    tk.Label(security_frame, text="🔒 Your private key will be encrypted locally and never shared", 
            fg=secondary_color,
            bg=security_bg,
            font=("Inter", 9)).pack(anchor="w")
    
    # Error message label (initially hidden)
    error_frame = tk.Frame(content_frame, bg=content_bg)
    error_frame.pack(fill=tk.X, pady=(10, 0))
    
    error_label = tk.Label(error_frame, text="", 
                         fg="#EF4444", bg=content_bg,
                         font=("Inter", 10, "bold"))
    error_label.pack(pady=(0, 0))
    
    def improved_key_validation(private_key):
        """More flexible private key validation"""
        try:
            # Clean the key (remove whitespace, etc.)
            private_key = private_key.strip()
            
            # Add 0x prefix if missing
            if not private_key.startswith("0x"):
                private_key = "0x" + private_key
                
            # Check basic length (should be 64 hex chars + 0x prefix)
            key_hex = private_key[2:]  # Remove 0x prefix
            if len(key_hex) != 64:
                return False, "Private key must be 64 hexadecimal characters (32 bytes)"
                
            # Validate it's hex
            try:
                int(key_hex, 16)  # Convert to int to verify it's valid hex
            except ValueError:
                return False, "Private key must contain only hexadecimal characters (0-9, a-f)"
            
            # Basic validation passed, should be a valid key
            return True, private_key
        except Exception as e:
            logger.error(f"Key validation error: {type(e).__name__}")
            return False, "Invalid private key format"
    
    def do_import():
        private_key = pk_entry.get().strip()
        password = pw_entry.get()
        confirm_password = pw_confirm_entry.get()
        
        # Validate inputs
        if not private_key:
            error_label.config(text="Private key is required")
            return
            
        if not password:
            error_label.config(text="Password is required")
            return
            
        # Verify passwords match
        if password != confirm_password:
            error_label.config(text="Passwords do not match")
            return
            
        # Password strength check
        if len(password) < 8:
            error_label.config(text="Password must be at least 8 characters long")
            return
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if not (has_upper and has_lower and has_digit):
            error_label.config(text="Password must contain uppercase, lowercase, and numbers")
            return
            
        if not has_special:
            error_label.config(text="Password should include at least one special character")
            return
            
        # Use improved key validation
        valid, result = improved_key_validation(private_key)
        if valid:
            private_key = result  # Use normalized key
        else:
            error_label.config(text=result)  # Display error message
            return
        
        # Show loading message
        error_label.config(text="Processing...", fg=secondary_color)
        import_window.update()
            
        try:
            from autonomi_client import Wallet
            app.wallet = Wallet(private_key)
            encrypt_wallet(app, private_key, password)
            app.wallet_address_label.config(text=f"Wallet: {app.wallet.address()}")
            import asyncio
            asyncio.run_coroutine_threadsafe(app._update_balances(), app.loop)
            
            # Custom success popup with theme support
            success_window = tk.Toplevel(app.root)
            success_window.title("Success")
            success_window.geometry("350x180")
            success_window.minsize(350, 180)
            success_window.configure(bg=bg_color)
            success_window.transient(app.root)
            success_window.grab_set()
            success_window.lift() 
            success_window.focus_force()  
            success_window.attributes("-topmost", True)
            
            # Content
            frame = tk.Frame(success_window, bg=bg_color, padx=20, pady=20)
            frame.pack(fill=tk.BOTH, expand=True)
            
            success_color = "#10B981"  # Green for success
            tk.Label(frame, text="💡", font=("Inter", 24), 
                  fg=success_color, bg=bg_color).pack(pady=(0, 10))
            tk.Label(frame, text="Wallet imported successfully", 
                  font=("Inter", 14, "bold"),
                  fg=text_color, bg=bg_color).pack(pady=(0, 20))
            
            ok_btn = tk.Button(frame, text="OK", 
                            bg="#4F46E5", fg="white",
                            activebackground="#7C3AED", activeforeground="white",
                            font=("Inter", 10), padx=10, pady=5,
                            relief="flat", bd=0,
                            command=success_window.destroy,
                            width=15)
            ok_btn.pack()
            
            # Apply theme if needed
            if is_dark:
                gui.apply_theme_to_toplevel(success_window, True)
            
            # Wait for dialog to close
            app.root.wait_window(success_window)
            
            app.status_label.config(text="Wallet imported")
            import_window.destroy()
            if wallet_window is not None:
                wallet_window.destroy()
        except Exception as e:
            logger.error(f"Wallet import error: {str(e)}")
            error_label.config(text=f"Error: {str(e)}", fg="#EF4444")
    
    # Footer with buttons
    footer_frame = tk.Frame(import_window, bg=bg_color, padx=20, pady=20)
    footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
    
    cancel_btn = tk.Button(footer_frame, text="Cancel",
                        bg="#6B7280" if is_dark else "#E5E7EB",
                        fg="white" if is_dark else "#1F2937",
                        activebackground="#4B5563" if is_dark else "#D1D5DB",
                        activeforeground="white" if is_dark else "#1F2937",
                        relief="flat", bd=0, padx=10, pady=6,
                        command=import_window.destroy)
    cancel_btn.pack(side=tk.LEFT)
    
    import_btn = tk.Button(footer_frame, text="Import Wallet",
                        bg="#4F46E5", fg="white",
                        activebackground="#7C3AED", activeforeground="white",
                        relief="flat", bd=0, padx=10, pady=6,
                        command=do_import)
    import_btn.pack(side=tk.RIGHT)
    
    # Apply theme if needed
    if is_dark:
        gui.apply_theme_to_toplevel(import_window, True)
        
    # Bind Enter key to import action
    import_window.bind("<Return>", lambda event: do_import())

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
            confirm_window = tk.Toplevel(app.root)
            confirm_window.title("Wallet Exists")
            confirm_window.geometry("450x250")
            
            # Use proper theme colors
            import gui
            is_dark = hasattr(app, 'is_dark_mode') and app.is_dark_mode
            bg_color = "#1E1E1E" if is_dark else gui.CURRENT_COLORS["bg_light"]
            text_color = "#FFFFFF" if is_dark else gui.CURRENT_COLORS["text_primary"]
            
            confirm_window.configure(bg=bg_color)
            confirm_window.transient(app.root)
            confirm_window.grab_set()
            
            # Ensure window is brought to the front
            confirm_window.lift()
            confirm_window.focus_force()
            confirm_window.attributes("-topmost", True)
            confirm_window.resizable(False, False)
            
            # Main frame
            frame = tk.Frame(confirm_window, bg=bg_color, padx=20, pady=20)
            frame.pack(fill=tk.BOTH, expand=True)
            
            # Warning icon instead of question mark
            import gui
            ttk.Label(frame, text="⚠️", font=("Inter", 32), foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 10))
            
            # Warning message
            message = "A wallet file already exists. Creating a new wallet will overwrite the existing one. Continue?"
            tk.Label(frame, text=message, 
                   font=("Inter", 11), fg=text_color, bg=bg_color,
                   wraplength=400, justify="center").pack(pady=(0, 20))
            
            # Buttons
            button_frame = tk.Frame(frame, bg=bg_color)
            button_frame.pack(fill=tk.X, side=tk.BOTTOM)
            
            def on_no():
                confirm_window.destroy()
                return
                
            def on_yes():
                confirm_window.destroy()
                # Continue with wallet creation
                _create_wallet_after_confirmation(app, wallet_window)
            
            # No button
            no_btn = tk.Button(button_frame, text="No", 
                             command=on_no,
                             bg="#6B7280", fg="white",
                             activebackground="#4B5563", activeforeground="white",
                             font=("Inter", 10), padx=15, pady=5, bd=0)
            no_btn.pack(side=tk.LEFT, padx=10)
            
            # Yes button
            yes_btn = tk.Button(button_frame, text="Yes", 
                              command=on_yes,
                              bg="#4F46E5", fg="white",
                              activebackground="#7C3AED", activeforeground="white",
                              font=("Inter", 10), padx=15, pady=5, bd=0)
            yes_btn.pack(side=tk.RIGHT, padx=10)
            
            # Apply theme if needed
            if is_dark:
                gui.apply_theme_to_toplevel(confirm_window, True)
                
            # Center the dialog
            confirm_window.update_idletasks()
            width = confirm_window.winfo_width()
            height = confirm_window.winfo_height()
            x = (confirm_window.winfo_screenwidth() // 2) - (width // 2)
            y = (confirm_window.winfo_screenheight() // 2) - (height // 2)
            confirm_window.geometry(f"{width}x{height}+{x}+{y}")
            
            # Wait for user response
            app.root.wait_window(confirm_window)
            return
        else:
            _create_wallet_after_confirmation(app, wallet_window)
    except Exception as e:
        messagebox.showerror("Error", f"Error creating wallet: {str(e)}")
        logger.error("Wallet creation error: %s", e)

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
        callback(True)  # Return success so download can proceed without wallet
    else:
        callback(False, was_canceled)

def _prompt_password(app, message, callback, parent_window=None):
    """Prompts user for wallet password."""
    if parent_window is None:
        parent_window = app.root
    
    import gui
    from tkinter import Toplevel, Label, Entry, Button, StringVar, TclError
    
    password_window = Toplevel(parent_window)
    password_window.title("Wallet Password")
    password_window.geometry("400x200")
    password_window.minsize(400, 200)
    password_window.transient(parent_window)
    password_window.grab_set()
    password_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
    password_window.lift()
    password_window.focus_force()
    
    # Header frame
    header_frame = Label(password_window, 
                       text="Authentication Required",
                       font=("Inter", 14, "bold"), 
                       fg=gui.CURRENT_COLORS["accent_primary"],
                       bg=gui.CURRENT_COLORS["bg_light"])
    header_frame.pack(fill="x", padx=20, pady=(20, 10))
    
    # Content frame
    content_frame = Label(password_window, 
                        bg=gui.CURRENT_COLORS["bg_light"], 
                        bd=0, highlightthickness=0)
    content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    
    # Password message
    Label(content_frame, 
        text=message, 
        wraplength=350,
        bg=gui.CURRENT_COLORS["bg_light"],
        fg=gui.CURRENT_COLORS["text_primary"]).pack(pady=(0, 15))
    
    # Password entry
    pw_var = StringVar()
    pw_entry = Entry(content_frame, 
                   textvariable=pw_var,
                   show="•", 
                   width=30,
                   bg=gui.CURRENT_COLORS["bg_input"],
                   fg=gui.CURRENT_COLORS["text_primary"],
                   insertbackground=gui.CURRENT_COLORS["text_primary"],
                   relief="solid", 
                   bd=1)
    pw_entry.pack(fill="x", pady=(0, 15))
    pw_entry.focus_set()
    
    # Footer with buttons
    footer_frame = Label(password_window, 
                       bg=gui.CURRENT_COLORS["bg_light"], 
                       bd=0, highlightthickness=0)
    footer_frame.pack(fill="x", pady=(0, 20), padx=20)
    
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
    cancel_btn = Button(footer_frame, 
                      text="Cancel",
                      command=on_cancel,
                      bg=gui.CURRENT_COLORS["bg_secondary"],
                      fg=gui.CURRENT_COLORS["text_primary"],
                      activebackground=gui.CURRENT_COLORS["bg_light"],
                      activeforeground=gui.CURRENT_COLORS["text_primary"],
                      relief="flat", 
                      bd=0)
    cancel_btn.pack(side="left")
    
    # Confirm button
    ok_btn = Button(footer_frame, 
                  text="Confirm",
                  command=on_submit,
                  bg=gui.CURRENT_COLORS["accent_primary"],
                  fg="white",
                  activebackground=gui.CURRENT_COLORS["accent_secondary"],
                  activeforeground="white",
                  relief="flat", 
                  bd=0)
    ok_btn.pack(side="right")
    
    # Apply theme if in dark mode
    if hasattr(app, 'is_dark_mode') and app.is_dark_mode:
        gui.apply_theme_to_toplevel(password_window, True)
    
    # Bind enter key to submit
    password_window.bind("<Return>", lambda e: on_submit())
    password_window.bind("<Escape>", lambda e: on_cancel())
    password_window.protocol("WM_DELETE_WINDOW", on_cancel)

def display_private_key(app, parent_window=None):
    """Shows private key after confirming wallet password."""
    # First check if wallet exists
    if not os.path.exists(app.wallet_file):
        show_styled_error(app, "Error", "No wallet file found. Create or import a wallet first.", parent_window)
        return
        
    # Create a confirmation dialog
    confirm_window = tk.Toplevel(app.root)
    confirm_window.title("Security Verification")
    confirm_window.geometry("450x400")  # Increased height for better display
    
    # Use proper theme colors
    import gui
    confirm_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
    confirm_window.transient(parent_window if parent_window else app.root)
    confirm_window.grab_set()
    confirm_window.lift() 
    confirm_window.focus_force() 
    
    # Add window attributes to keep it on top
    confirm_window.attributes("-topmost", True)
    confirm_window.resizable(False, False)
    
    # Container frame
    frame = ttk.Frame(confirm_window, style="TFrame", padding=20)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Warning icon and header
    ttk.Label(frame, text="⚠️", font=("Inter", 24), foreground=gui.CURRENT_COLORS["warning"]).pack(pady=(0, 10))
    ttk.Label(frame, text="Security Verification Required", font=("Inter", 16, "bold")).pack(pady=(0, 10))
    
    # Warning message
    message = "Your private key provides full access to your wallet and funds. For security, you must enter your password to view it."
    ttk.Label(frame, text=message, wraplength=380, justify="center").pack(pady=(0, 20))
    
    # Security notice - using custom bg/fg colors for dark mode compatibility
    security_bg = gui.CURRENT_COLORS["bg_secondary"]
    security_fg = gui.CURRENT_COLORS["text_secondary"]
    
    security_frame = tk.Frame(frame, bg=security_bg, padx=10, pady=10, bd=0, highlightthickness=0)
    security_frame.pack(fill=tk.X, pady=(0, 15))
    
    security_text = "Never share your private key or enter it on any website, even if they claim to be Autonomi. We will never ask for your private key."
    tk.Label(security_frame, text=security_text, wraplength=380, 
            fg=security_fg,
            bg=security_bg,
            font=("Inter", 9),
            justify="left").pack(anchor="w")
    
    # Password field
    password_frame = ttk.Frame(frame, style="TFrame")
    password_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(password_frame, text="Password:", anchor="w").pack(side=tk.LEFT, padx=(0, 10))
    
    password_var = tk.StringVar()
    password_entry = ttk.Entry(password_frame, textvariable=password_var, show="•", width=25)
    password_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True)
    password_entry.focus_set()
    
    # Error message label (initially hidden)
    error_label = ttk.Label(frame, text="", foreground=gui.CURRENT_COLORS["error"])
    error_label.pack(pady=(0, 10))
    
    # Buttons
    button_frame = ttk.Frame(frame, style="TFrame")
    button_frame.pack(fill=tk.X, side=tk.BOTTOM)
    
    def on_cancel():
        confirm_window.destroy()
    
    def on_verify():
        password = password_var.get()
        if not password:
            error_label.config(text="Password cannot be empty")
            return
            
        # Show a loading message while decrypting
        error_label.config(text="Verifying...", foreground=gui.CURRENT_COLORS["text_secondary"])
        confirm_window.update()
            
        # Attempt to decrypt the wallet with the provided password
        private_key = decrypt_wallet(app, password)
        if private_key:
            confirm_window.destroy()
            _show_private_key(app, private_key, parent_window)
        else:
            error_label.config(text="Incorrect password", foreground=gui.CURRENT_COLORS["error"])
            # Clear the password field for security
            password_entry.delete(0, tk.END)
            password_entry.focus()
    
    cancel_btn = ttk.Button(button_frame, text="Cancel", style="Secondary.TButton", command=on_cancel)
    cancel_btn.pack(side=tk.LEFT)
    
    verify_btn = ttk.Button(button_frame, text="View Private Key", style="Accent.TButton", command=on_verify)
    verify_btn.pack(side=tk.RIGHT)
    
    # Apply theme if in dark mode
    if hasattr(app, 'is_dark_mode') and app.is_dark_mode:
        gui.apply_theme_to_toplevel(confirm_window, True)
    
    # Bind Enter key to verification
    confirm_window.bind("<Return>", lambda event: on_verify())
    # Bind Escape key to cancel
    confirm_window.bind("<Escape>", lambda event: on_cancel())

def _show_private_key(app, private_key, parent_window=None):
    """Displays the private key in a secure dialog."""
    key_window = tk.Toplevel(app.root)
    key_window.title("Private Key")
    key_window.geometry("550x580")  # Further increased height to ensure all content is visible
    
    # Use proper theme colors
    import gui
    is_dark = hasattr(app, 'is_dark_mode') and app.is_dark_mode
    
    # Set background to a slightly lighter shade in dark mode for better contrast
    bg_color = "#1E1E1E" if is_dark else gui.CURRENT_COLORS["bg_light"]
    key_window.configure(bg=bg_color)
    key_window.transient(parent_window if parent_window else app.root)
    key_window.grab_set()
    key_window.lift() 
    key_window.focus_force() 
    key_window.resizable(False, False)
    
    # Add window attributes to keep it on top
    key_window.attributes("-topmost", True)
    
    # Main container - use native frame with explicit background instead of ttk.Frame
    main_frame = tk.Frame(key_window, bg=bg_color, padx=20, pady=20)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Header - with high contrast color
    header_color = "#7C3AED" if is_dark else gui.CURRENT_COLORS["accent_primary"]
    tk.Label(main_frame, text="Your Private Key", 
          font=("Inter", 18, "bold"), 
          fg=header_color, 
          bg=bg_color).pack(anchor="w", pady=(0, 15))
    
    # Top warning - using native Frame with background color
    warning_bg = "#2D2D2D" if is_dark else "#FFF3E0"
    warning_fg = "#FFB74D" if is_dark else "#D84315"  # Brighter orange for dark mode
    
    warning_frame = tk.Frame(main_frame, bg=warning_bg,
                          padx=10, pady=10, bd=0, highlightthickness=0)
    warning_frame.pack(fill=tk.X, pady=(0, 15))
    
    warning_header = tk.Label(warning_frame, 
                           text="⚠️ SECURITY WARNING", 
                           font=("Inter", 12, "bold"),
                           fg=warning_fg,
                           bg=warning_bg)
    warning_header.pack(anchor="w")
    
    warning_text = (
        "• NEVER share this key with anyone or enter it on any website\n"
        "• DO NOT take screenshots of this screen\n"
        "• Anyone who has this key can access ALL your funds\n"
        "• Copy it to a secure password manager immediately"
    )
    
    tk.Label(warning_frame, text=warning_text, 
          font=("Inter", 10),
          wraplength=480,
          fg=warning_fg,
          bg=warning_bg,
          justify="left").pack(anchor="w", pady=(5, 0))
    
    # Private key display with dark background and high contrast
    key_bg = "#121212" if is_dark else gui.CURRENT_COLORS["bg_secondary"]
    key_fg = "#FFFFFF" if is_dark else gui.CURRENT_COLORS["text_primary"]
    
    key_frame = tk.Frame(main_frame, bg=key_bg, 
                      padx=15, pady=15, bd=0, highlightthickness=0)
    key_frame.pack(fill=tk.X, pady=(0, 15))
    
    # Text widget for easy copying with monospace font and larger size
    from gui import add_context_menu
    key_text = tk.Text(key_frame, height=2, width=40, font=("Courier New", 12, "bold"),
                     bg="#121212" if is_dark else "#F5F7FA",
                     fg="#FFFFFF" if is_dark else "#1A1D21",
                     relief="flat", padx=15, pady=10)
    key_text.pack(fill=tk.X)
    key_text.insert(tk.END, private_key)
    key_text.config(state="normal")  # Allow copying
    add_context_menu(key_text)
    
    # Add copy button for convenience
    copy_frame = tk.Frame(main_frame, bg=bg_color)
    copy_frame.pack(fill=tk.X, pady=(0, 15))
    
    def copy_to_clipboard():
        app.root.clipboard_clear()
        app.root.clipboard_append(private_key)
        copy_btn.config(text="✓ Copied to clipboard!", bg="#10B981", fg="white")
        key_window.after(2000, lambda: copy_btn.config(text="Copy to Clipboard", bg="#4F46E5", fg="white"))
    
    # Use a native button with explicit colors for better visibility
    copy_btn = tk.Button(copy_frame, text="Copy to Clipboard", 
                      bg="#4F46E5", fg="white",
                      activebackground="#7C3AED", activeforeground="white",
                      font=("Inter", 10),
                      padx=10, pady=5, bd=0,
                      command=copy_to_clipboard)
    copy_btn.pack(side=tk.RIGHT)
    
    # Security reminder with improved styling and format
    reminder_bg = "#2D2D2D" if is_dark else gui.CURRENT_COLORS["bg_secondary"]
    reminder_frame = tk.Frame(main_frame, bg=reminder_bg, 
                           padx=15, pady=15, bd=0, highlightthickness=0)
    reminder_frame.pack(fill=tk.X, pady=(0, 15))
    
    # Create a label with high-contrast text color
    header_color = "#FFFFFF" if is_dark else "#222222"
    
    # Use a native button for the close button with explicit colors
    close_btn = tk.Button(main_frame, text="Close", 
                       bg="#4F46E5", fg="white",
                       activebackground="#7C3AED", activeforeground="white",
                       font=("Inter", 10),
                       padx=10, pady=5, bd=0,
                       command=key_window.destroy)
    close_btn.pack(side=tk.RIGHT, pady=(5, 0))
    
    # Auto-close timer with high contrast
    timer_color = "#E0E0E0" if is_dark else gui.CURRENT_COLORS["text_secondary"]
    timer_label = tk.Label(main_frame, text=f"This window will auto-close in 120 seconds", 
                        fg=timer_color, bg=bg_color,
                        font=("Inter", 9))
    timer_label.pack(side=tk.LEFT, pady=(5, 0))
    
    # Timer countdown function
    def update_timer(seconds_left):
        if seconds_left > 0:
            timer_label.config(text=f"This window will auto-close in {seconds_left} seconds")
            key_window.after(1000, update_timer, seconds_left - 1)
        else:
            try:
                key_window.destroy()
            except:
                pass
    
    # Start the timer
    update_timer(120)
    
    # Disable printscreen/capture on some platforms
    if platform.system() == "Windows":
        try:
            # Use windows specific API to disable print screen
            import ctypes
            ctypes.windll.user32.SetWindowDisplayAffinity(
                ctypes.windll.user32.GetForegroundWindow(), 1)  # WDA_MONITOR = 1
        except:
            pass

def show_styled_error(app, title, message, parent=None):
    """Shows a styled error dialog that's always visible on top."""
    import gui
    
    # Get theme colors
    is_dark = hasattr(app, 'is_dark_mode') and app.is_dark_mode
    bg_color = "#1E1E1E" if is_dark else gui.CURRENT_COLORS["bg_light"]
    text_color = "#FFFFFF" if is_dark else gui.CURRENT_COLORS["text_primary"]
    
    # Create error dialog
    error_window = tk.Toplevel(parent if parent else app.root)
    error_window.title(title)
    error_window.geometry("400x200")
    error_window.configure(bg=bg_color)
    
    # Ensure it's on top and has focus
    error_window.attributes("-topmost", True)
    error_window.transient(parent if parent else app.root)
    error_window.grab_set()
    error_window.lift()
    error_window.focus_force()
    error_window.resizable(False, False)
    
    # Create main frame
    frame = tk.Frame(error_window, bg=bg_color, padx=20, pady=20)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Error icon and message
    icon_frame = tk.Frame(frame, bg=bg_color)
    icon_frame.pack(pady=(0, 15))
    
    # Error icon
    tk.Label(icon_frame, text="⛔", font=("Inter", 24), 
             fg="#EF4444", bg=bg_color).pack()
    
    # Error message
    tk.Label(frame, text=message, 
             font=("Inter", 11), 
             fg=text_color, bg=bg_color,
             wraplength=350, 
             justify="center").pack(pady=(0, 20))
    
    # OK button
    ok_btn = tk.Button(frame, text="OK", 
                     bg="#4F46E5", fg="white",
                     activebackground="#7C3AED", activeforeground="white",
                     font=("Inter", 10), padx=30, pady=6,
                     relief="flat", bd=0,
                     command=error_window.destroy)
    ok_btn.pack()
    
    # Apply theme if needed
    if is_dark:
        gui.apply_theme_to_toplevel(error_window, True)
    
    # Bind Enter/Escape to close
    error_window.bind("<Return>", lambda event: error_window.destroy())
    error_window.bind("<Escape>", lambda event: error_window.destroy())
    
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