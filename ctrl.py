import asyncio
import json
import logging
import os
import threading
import datetime
import requests
from collections import deque
from pathlib import Path
from web3 import Web3
from autonomi_client import Client, Network, Wallet
import public
import private
import gui
from gui import COLORS
import wallet
import view
import connectivity
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, Toplevel, StringVar
import platform
import sys
from PIL import Image, ImageTk
import traceback

class TestApp:
    def __init__(self):
        # Logger setup with console and file handlers
        self.logger = logging.getLogger("MissionCtrl")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = []
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        log_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "missionctrl", "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "missionctrl.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Tkinter root setup
        self.root = tk.Tk()
        self.root.title("Mission Ctrl")
        
        # Set up persistent data file
        self.data_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "missionctrl")
        self.data_file = os.path.join(self.data_dir, "mission_control_data.json")
        
        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Instance variables
        self.client = None
        self.wallet = None
        self.is_public_var = tk.BooleanVar(value=False)
        self.is_private_var = tk.BooleanVar(value=False)
        self.perform_cost_calc_var = tk.BooleanVar(value=True)
        self.loop = None
        self.is_processing = False
        self._current_operation = None
        self.upload_queue = []
        self.download_queue = []
        self.local_archives = []  # Each archive is (address, nickname, is_private)
        self.uploaded_files = []  # Each item is (filename, chunk_address)
        self.uploaded_private_files = []  # Each item is (filename, access_token)
        self.ant_balance = 0.0
        self.eth_balance = 0.0
        self.ant_price_usd = 0.0
        self.eth_price_usd = 0.0
        self.balance_history = deque(maxlen=50)  # Use deque instead of list for appendleft operation
        self.dark_mode_enabled = False  # Default to light mode
        
        self.load_persistent_data()

        # Core instance variables
        self.w3 = Web3(Web3.HTTPProvider('https://arb1.arbitrum.io/rpc'))
        self.wallet_file = str(Path(self.data_dir) / "wallet.enc")
        self.status_dots = ["", ".", "..", "..."]
        self.current_dot_idx = 0
        self.status_update_task = None
        self.previous_ant_balance = None
        self.previous_eth_balance = None
        self.last_price_update = None

        # Platform-specific log file location
        if platform.system() == "Linux":
            self.default_dir = Path(os.path.expanduser("~/.local/share/missionctrl"))
        else:
            self.default_dir = Path(os.path.expanduser("~/Documents/missionctrl"))
        self.default_dir.mkdir(parents=True, exist_ok=True)
        self.data_file = str(self.default_dir / "mission_control_data.json")
        self.wallet_file = str(self.default_dir / "wallet.enc")
        self.upload_queue = []
        self.download_queue = []

        # Tkinter root setup
        self.root.title("Mission Ctrl")
        self.root.minsize(600, 500)
        self.root.withdraw()
        
        # Initial user consent for fund risk - styled warning
        warning_window = Toplevel(self.root)
        warning_window.title("Warning")
        warning_window.configure(bg=COLORS["bg_light"])
        warning_window.resizable(True, True)
        warning_window.grab_set()
        
        warning_frame = ttk.Frame(warning_window, style="TFrame", padding=20)
        warning_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(warning_frame, text="⚠️ Important Warning", 
                font=("Inter", 16, "bold"), 
                foreground=COLORS["warning"]).pack(anchor="w", pady=(0, 15))
        
        warning_text = "Only send or import small amounts of funds. The app developer makes no guarantees that your funds will not be lost."
        ttk.Label(warning_frame, text=warning_text, 
                wraplength=380,
                font=("Inter", 11)).pack(anchor="w", pady=(0, 20))
        
        button_frame = ttk.Frame(warning_frame, style="TFrame")
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        cancel_btn = ttk.Button(button_frame, text="Decline",
                            style="Secondary.TButton",
                            command=lambda: [warning_window.destroy(), sys.exit("User declined the warning.")])
        cancel_btn.pack(side=tk.LEFT)
        
        accept_btn = ttk.Button(button_frame, text="I Understand and Accept",
                            style="Accent.TButton",
                            command=warning_window.destroy)
        accept_btn.pack(side=tk.RIGHT)
        
        warning_window.wait_window()
        
        # Initialize asyncio event loop
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.initialize_app()

    def on_closing(self):
        self.save_persistent_data()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.root.destroy()
        self.logger.info("Closing window...")

    def initialize_app(self):
        self.load_persistent_data()
        asyncio.run_coroutine_threadsafe(self.init_client(), self.loop)
        # After first check, schedule regular checks every 5 minutes
        self.root.after(5000, lambda: connectivity.schedule_connection_check(self, first_check=False))
        self.root.after(1000, self.update_balances)
        self.root.after(1000, self.start_status_update)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        gui.setup_main_gui(self)
        
        # Initialize price display
        self.root.after(1500, self._initial_price_display)
        
        self.root.deiconify()

    def _initial_price_display(self):
        """Set initial price display when the app starts"""
        if hasattr(self, 'ant_price_label'):
            if self.ant_price_usd <= 0:
                ant_price_text = "Loading..."
            elif self.ant_price_usd < 1:
                ant_price_text = f"${self.ant_price_usd:.4f}"
            else:
                ant_price_text = f"${self.ant_price_usd:.2f}"
            
            self.ant_price_label.config(text=ant_price_text, foreground=COLORS["text_primary"])
        
        if hasattr(self, 'eth_price_label'):
            if self.eth_price_usd <= 0:
                eth_price_text = "Loading..."
            else:
                eth_price_text = f"${self.eth_price_usd:.2f}"
                
            self.eth_price_label.config(text=eth_price_text, foreground=COLORS["text_primary"])
            
        self.logger.info(f"Initial price display set - ANT: {self.ant_price_usd}, ETH: {self.eth_price_usd}")

    async def init_client(self):
        self.client = await Client.init()
        self.connection_label.config(text="Network: Initializing...")
        self.logger.info("Client initialized: %s", self.client)
        
        # Start connectivity checks with quote - first time and periodic checks
        self.root.after(0, lambda: connectivity.schedule_connection_check(self, first_check=True))
        # After first check, schedule regular checks every 5 minutes
        self.root.after(5000, lambda: connectivity.schedule_connection_check(self, first_check=False))
        
        if os.path.exists(self.wallet_file):
            self.root.after(0, self._schedule_wallet_prompt)
        else:
            self.wallet_address_label.config(text="Wallet: Not Created")
            self.logger.info("No wallet file found at %s", self.wallet_file)
            self.root.after(0, self.show_wallet_setup_wizard)  # Automatically show wallet setup wizard
        
        # The status will be updated by the connectivity module
        # self.connection_label.config(text="Network: Connected to Autonomi")

    def _schedule_wallet_prompt(self):
        self.logger.info("Scheduling wallet password prompt")
        self.logger.info("Wallet file exists: %s", os.path.exists(self.wallet_file))
        def on_wallet_loaded(success, was_canceled=False):
            if not success and not was_canceled:
                # Only show wallet setup wizard if the user didn't cancel the dialog
                # but actually failed to authenticate (wrong password)
                self.logger.info("No valid wallet loaded, prompting for wallet setup")
                self.show_wallet_setup_wizard()
            elif was_canceled:
                # Only show the unlock button if the user specifically canceled the dialog
                self.logger.info("User canceled wallet unlock dialog, showing unlock button")
                if hasattr(self, 'unlock_button'):
                    self.unlock_button.pack(side=tk.RIGHT, padx=(0, 10))
        
        download_only = False
        if hasattr(self, 'current_view'):
            download_only = self.current_view.get() == "download"
        
        wallet.prompt_wallet_password(self, on_wallet_loaded, download_only=download_only)

    def show_wallet_setup_wizard(self):
        # Wallet setup UI for new users
        self.logger.info("Showing wallet setup wizard")
        wizard_window = tk.Toplevel(self.root)
        wizard_window.title("Setup Wizard")
        wizard_window.resizable(True, True)
        wizard_window.transient(self.root)
        wizard_window.grab_set()
        wizard_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
        
        header_frame = ttk.Frame(wizard_window, style="TFrame", padding="30 30 30 20")
        header_frame.pack(fill=tk.X)
        
        ttk.Label(header_frame, text="Welcome to Mission Ctrl", 
                font=("Inter", 20, "bold"), 
                foreground=COLORS["accent_primary"]).pack(anchor="w")
        
        ttk.Label(header_frame, text="Let's set up your wallet", 
                font=("Inter", 14), 
                foreground=COLORS["text_secondary"]).pack(anchor="w", pady=(5, 0))
        
        # Content section
        content_frame = ttk.Frame(wizard_window, style="RoundedCard.TFrame", padding="30")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))
        
        # Info text
        info_label = ttk.Label(content_frame, 
                text="You need a wallet to use Mission Ctrl. A wallet stores your funds (ETH and ANT) and pays for uploads.", 
                wraplength=400,
                style="CardText.TLabel")
        info_label.pack(anchor="w", pady=(0, 20))
        
        # Simple instruction
        instruction_label = ttk.Label(content_frame, 
                text="Click 'Let's Go' below to create a new wallet or import an existing one.", 
                wraplength=400,
                style="CardText.TLabel")
        instruction_label.pack(anchor="w", pady=(10, 60))
        
        button_frame = ttk.Frame(content_frame, style="CardContent.TFrame", padding="0 0 0 0")
        button_frame.pack(fill=tk.X)
        
        def go_to_wallet_options():
            wizard_window.destroy()
            self.show_wallet_options()
            
        go_btn = ttk.Button(button_frame, text="Let's Go",
                          style="Accent.TButton",
                          command=go_to_wallet_options,
                          width=20)
        go_btn.pack(side=tk.RIGHT, padx=10)
        
        # Apply theme if in dark mode
        if hasattr(self, 'is_dark_mode') and self.is_dark_mode:
            gui.apply_theme_to_toplevel(wizard_window, True)

    def update_balances(self):
        if self.wallet:
            asyncio.run_coroutine_threadsafe(self._update_balances(), self.loop)
        self.root.after(300000, self.update_balances)  # 5 minutes

    async def _update_balances(self):
        """Updates wallet balances asynchronously"""
        if not self.wallet:
            return
        
        from wallet import show_styled_error
        
        try:
            # First, update cryptocurrency prices
            await self._update_crypto_prices()
             
            # Async balance fetch from blockchain
            ant_balance = int(await self.wallet.balance())
            eth_balance = self.w3.eth.get_balance(self.wallet.address())
             
            # Convert to floats for display
            ant_balance_float = ant_balance / 10**18
            eth_balance_float = eth_balance / 10**18
             
            # Calculate USD values
            ant_usd_value = ant_balance_float * self.ant_price_usd
            eth_usd_value = eth_balance_float * self.eth_price_usd
             
            # Update UI labels with USD value
            self.ant_balance_label.config(text=f"ANT Balance: {ant_balance_float:.10f}\n(${ant_usd_value:.2f})")
            self.eth_balance_label.config(text=f"ETH Balance: {eth_balance_float:.10f}\n(${eth_usd_value:.2f})")
            
            # Check if balances have changed
            if (self.previous_ant_balance is None or 
                    self.previous_eth_balance is None or 
                    ant_balance_float != self.previous_ant_balance or 
                    eth_balance_float != self.previous_eth_balance):
                
                now = datetime.datetime.now()
                
                # Calculate changes if previous values exist
                ant_change = 0
                eth_change = 0
                ant_usd_change = 0
                eth_usd_change = 0
                
                if self.previous_ant_balance is not None:
                    ant_change = ant_balance_float - self.previous_ant_balance
                    ant_usd_change = ant_change * self.ant_price_usd
                    
                if self.previous_eth_balance is not None:
                    eth_change = eth_balance_float - self.previous_eth_balance
                    eth_usd_change = eth_change * self.eth_price_usd
                
                # Format small numbers properly for logging
                ant_change_str = f"{ant_change:.12f}" if abs(ant_change) < 0.0001 else f"{ant_change:.8f}"
                eth_change_str = f"{eth_change:.12f}" if abs(eth_change) < 0.0001 else f"{eth_change:.8f}"
                ant_usd_change_str = f"{ant_usd_change:.12f}" if abs(ant_usd_change) < 0.0001 else f"{ant_usd_change:.6f}"
                eth_usd_change_str = f"{eth_usd_change:.12f}" if abs(eth_usd_change) < 0.0001 else f"{eth_usd_change:.6f}"
                
                # Log the changes with better formatting
                self.logger.info("Balances updated - ANT: %s (change: %s ANT, $%s), ETH: %s (change: %s ETH, $%s)", 
                                  f"{ant_balance_float:.10f}", ant_change_str, ant_usd_change_str, 
                                  f"{eth_balance_float:.10f}", eth_change_str, eth_usd_change_str)
                
                # Only add to balance history if there was an actual change in balance
                # This prevents adding entries for routine balance checks
                if ant_change != 0 or eth_change != 0:
                    # Add to balance history
                    change_record = {
                        'timestamp': now,
                        'ant_balance': ant_balance_float,
                        'eth_balance': eth_balance_float,
                        'ant_usd': ant_usd_value,
                        'eth_usd': eth_usd_value,
                        'ant_change': ant_change,
                        'eth_change': eth_change,
                        'ant_usd_change': ant_usd_change,
                        'eth_usd_change': eth_usd_change
                    }
                    
                    # Ensure balance_history is a deque before using appendleft
                    if not isinstance(self.balance_history, deque):
                        self.logger.info("Converting balance_history from list to deque")
                        self.balance_history = deque(self.balance_history, maxlen=50)
                    
                    self.balance_history.appendleft(change_record)
                    
                    # Update balance history display if it exists
                    self._update_balance_history_display()
                    
                    # Update status label with balance changes
                    status_message = "Balances updated"
                    if ant_change != 0:
                        ant_sign = "+" if ant_change > 0 else ""
                        status_message += f" - ANT: {ant_sign}{ant_change_str}"
                    if eth_change != 0:
                        eth_sign = "+" if eth_change > 0 else ""
                        status_message += f" - ETH: {eth_sign}{eth_change_str}"
                    self.status_label.config(text=status_message)
                    
                    # Set a timer to revert status to "Ready"
                    self.root.after(5000, lambda: self.status_label.config(text="Ready") if not self.is_processing else None)
                
                # Store current balances for next comparison
                self.previous_ant_balance = ant_balance_float
                self.previous_eth_balance = eth_balance_float
        except Exception as error:
            # Capture the error in a local variable and use that in the lambda
            error_msg = str(error)
            self.root.after(0, lambda: show_styled_error(self, "Balance Error", f"Failed to update wallet balances: {error_msg}"))
            self.logger.error(f"Failed to update balances: {error_msg}")

    async def _update_crypto_prices(self):
        """Fetch current cryptocurrency prices from API"""
        try:
            self.logger.info("Fetching crypto prices from API...")
            
            # Store previous prices for comparison
            previous_ant_price = self.ant_price_usd
            previous_eth_price = self.eth_price_usd
            
            # Update both ETH and ANT prices using CoinGecko API
            headers = {
                'User-Agent': 'Mission Ctrl App/1.0',
                'Accept': 'application/json'
            }
            
            try:
                response = requests.get(
                    "https://api.coingecko.com/api/v3/simple/price?ids=ethereum,autonomi&vs_currencies=usd",
                    headers=headers,
                    timeout=10
                )
                
                self.logger.info(f"API response status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Log the response data for debugging
                    self.logger.info(f"API data received: {data}")
                    
                    # Update ETH price if available
                    if 'ethereum' in data and 'usd' in data['ethereum'] and data['ethereum']['usd'] > 0:
                        self.eth_price_usd = data['ethereum']['usd']
                        self.logger.info(f"ETH price updated to ${self.eth_price_usd}")
                    else:
                        self.logger.warning("ETH price not found or invalid in API response")
                    
                    # Update ANT price if available
                    if 'autonomi' in data and 'usd' in data['autonomi'] and data['autonomi']['usd'] > 0:
                        self.ant_price_usd = data['autonomi']['usd']
                        self.logger.info(f"ANT price updated to ${self.ant_price_usd}")
                    else:
                        self.logger.warning("ANT price not found or invalid in API response")
                    
                    # After successful API call, save the updated prices
                    self.save_persistent_data()
                    
                    # Update price labels with appropriate colors
                    self.root.after(0, lambda: self._update_price_display(
                        previous_ant_price, previous_eth_price))
                    
                else:
                    self.logger.warning(f"Failed to fetch crypto prices: HTTP {response.status_code}")
                    if response.status_code == 429:
                        self.logger.warning("Rate limit exceeded. CoinGecko API has strict rate limits.")
                    
                    # Try to parse error response
                    try:
                        error_detail = response.json()
                        self.logger.warning(f"API error details: {error_detail}")
                    except:
                        self.logger.warning(f"Raw response: {response.text[:100]}...")
            
            except requests.exceptions.RequestException as req_err:
                self.logger.error(f"Request exception when fetching prices: {req_err}")
                
            # Always update the last price update time, even on failure
            self.last_price_update = datetime.datetime.now()
            self.logger.info(f"Updated crypto prices - ANT: ${self.ant_price_usd}, ETH: ${self.eth_price_usd}")
            
        except Exception as e:
            self.logger.error(f"Failed to update crypto prices: {str(e)}")
            self.logger.error(f"Exception details: {traceback.format_exc()}")

    def _update_price_display(self, previous_ant_price, previous_eth_price):
        """Update price display with appropriate colors based on price movement"""
        # Log price values for debugging
        self.logger.info(f"Price update - ANT: ${self.ant_price_usd} (was ${previous_ant_price}), ETH: ${self.eth_price_usd} (was ${previous_eth_price})")
        
        if hasattr(self, 'ant_price_label'):
            if self.ant_price_usd <= 0:
                ant_price_text = "Loading..."
                ant_color = gui.CURRENT_COLORS["text_secondary"]
            else:
                if self.ant_price_usd < 1:
                    ant_price_text = f"${self.ant_price_usd:.4f}"
                else:
                    ant_price_text = f"${self.ant_price_usd:.2f}"
                
                # Set ANT color based on price movement
                ant_color = gui.CURRENT_COLORS["text_secondary"]
                if previous_ant_price > 0:
                    if self.ant_price_usd > previous_ant_price:
                        ant_color = gui.CURRENT_COLORS["success"]
                        self.logger.info("ANT price increased - setting green")
                    elif self.ant_price_usd < previous_ant_price:
                        ant_color = gui.CURRENT_COLORS["error"]
                        self.logger.info("ANT price decreased - setting red")
            
            # Update ANT label
            self.ant_price_label.config(text=ant_price_text, foreground=ant_color)
        
        if hasattr(self, 'eth_price_label'):
            # Format ETH price for display
            if self.eth_price_usd <= 0:
                eth_price_text = "Loading..."
                eth_color = gui.CURRENT_COLORS["text_secondary"]
            else:
                eth_price_text = f"${self.eth_price_usd:.2f}"
                
                # Ensure values are numeric for comparison
                try:
                    p_eth = float(previous_eth_price)
                    c_eth = float(self.eth_price_usd)
                    
                    # Set ETH color based on price movement
                    eth_color = gui.CURRENT_COLORS["text_secondary"]
                    
                    # Handle case when previous price is 0
                    if p_eth == 0 and c_eth > 0:
                        eth_color = gui.CURRENT_COLORS["success"]
                        self.logger.info(f"ETH price increased from zero ({c_eth} > 0) - setting green")
                    elif p_eth > 0:
                        if c_eth > p_eth:
                            eth_color = gui.CURRENT_COLORS["success"]
                            self.logger.info(f"ETH price increased ({c_eth} > {p_eth}) - setting green")
                        elif c_eth < p_eth:
                            eth_color = gui.CURRENT_COLORS["error"]
                            self.logger.info(f"ETH price decreased ({c_eth} < {p_eth}) - setting red")
                        else:
                            self.logger.info(f"ETH price unchanged ({c_eth} = {p_eth})")
                except (ValueError, TypeError) as e:
                    self.logger.error(f"Error comparing ETH prices: {e}")

                    eth_color = gui.CURRENT_COLORS["text_secondary"]
            
            self.eth_price_label.config(text=eth_price_text, foreground=eth_color)
            self.logger.info(f"ETH label updated with text: {eth_price_text}, color: {eth_color}")

    def _update_balance_history_display(self):
        """Update the UI display of balance history"""
        if hasattr(self, 'balance_history_frame') and self.balance_history:
            for widget in self.balance_history_frame.winfo_children():
                widget.destroy()
            
            # Add each history entry
            for i, record in enumerate(self.balance_history):
                if i >= 5:  # Only show last 5
                    break
                    
                # Format timestamp
                time_str = record['timestamp'].strftime("%H:%M:%S")
                
                # Format the change entry
                if record['ant_change'] != 0 or record['eth_change'] != 0:
                    change_frame = ttk.Frame(self.balance_history_frame, style="TFrame")
                    change_frame.pack(fill=tk.X, pady=(5, 0))
                    
                    # Time stamp
                    ttk.Label(change_frame, text=time_str, width=10,
                           font=("Inter", 9), foreground=gui.CURRENT_COLORS["text_secondary"]).pack(side=tk.LEFT)
                    
                    # ANT change
                    if record['ant_change'] != 0:
                        sign = "+" if record['ant_change'] > 0 else ""
                        color = gui.CURRENT_COLORS["success"] if record['ant_change'] > 0 else gui.CURRENT_COLORS["error"]
                        
                        # Format very small numbers with fixed precision
                        ant_change_display = f"{record['ant_change']:.12f}" if abs(record['ant_change']) < 0.0001 else f"{record['ant_change']:.8f}"
                        ant_usd_change_display = f"{record['ant_usd_change']:.12f}" if abs(record['ant_usd_change']) < 0.0001 else f"{record['ant_usd_change']:.6f}"
                        
                        ttk.Label(change_frame, 
                               text=f"ANT: {sign}{ant_change_display} (${sign}{ant_usd_change_display})", 
                               font=("Inter", 9, "bold"), 
                               foreground=color).pack(side=tk.LEFT, padx=(5, 15))
                    
                    # ETH change
                    if record['eth_change'] != 0:
                        sign = "+" if record['eth_change'] > 0 else ""
                        color = gui.CURRENT_COLORS["success"] if record['eth_change'] > 0 else gui.CURRENT_COLORS["error"]
                        
                        eth_change_display = f"{record['eth_change']:.12f}" if abs(record['eth_change']) < 0.0001 else f"{record['eth_change']:.8f}"
                        eth_usd_change_display = f"{record['eth_usd_change']:.12f}" if abs(record['eth_usd_change']) < 0.0001 else f"{record['eth_usd_change']:.6f}"
                        
                        ttk.Label(change_frame, 
                               text=f"ETH: {sign}{eth_change_display} (${sign}{eth_usd_change_display})", 
                               font=("Inter", 9, "bold"), 
                               foreground=color).pack(side=tk.LEFT)

    def upload_file(self):
        # File upload logic with public/private options
        from tkinter import filedialog, messagebox, Toplevel, ttk, StringVar
        import gui
        
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

        initial_dir = os.path.expanduser("~")

        if private_selected:
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
            choice_window = Toplevel(self.root)
            choice_window.title("Upload Type")
            choice_window.transient(self.root)
            choice_window.grab_set()
            choice_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
            choice_window.resizable(True, True)

            main_frame = ttk.Frame(choice_window, style="TFrame", padding=20)
            main_frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(main_frame, text="Select upload type:", 
                      font=("Inter", 12, "bold"),
                      foreground=gui.CURRENT_COLORS["text_primary"]).pack(pady=(0, 15))
            
            choice_var = StringVar(value="files")
            
            # Create a custom style for the radio buttons
            style = ttk.Style()
            radio_style = "Dialog.TRadiobutton"
            style.configure(radio_style, 
                           background=gui.CURRENT_COLORS["bg_light"],
                           foreground=gui.CURRENT_COLORS["text_primary"])
            
            # Files radio button
            files_radio = ttk.Radiobutton(main_frame, 
                                        text="Files", 
                                        variable=choice_var, 
                                        value="files",
                                        style=radio_style)
            files_radio.pack(anchor="w", padx=5, pady=5)
            
            # Directory radio button
            if public_selected:
                dir_radio = ttk.Radiobutton(main_frame, 
                                          text="Directory", 
                                          variable=choice_var, 
                                          value="directory",
                                          style=radio_style)
                dir_radio.pack(anchor="w", padx=5, pady=5)

            def on_ok():
                choice_window.destroy()

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
                self._current_operation = 'upload'

                for path in paths_to_upload:
                    self.status_label.config(text=f"Uploading {os.path.basename(path)}")
                    if os.path.isdir(path) and public_selected:
                        asyncio.run_coroutine_threadsafe(public.upload_public_directory(self, path), self.loop)
                    elif public_selected:
                        asyncio.run_coroutine_threadsafe(public.upload_public(self, path), self.loop)
                    elif private_selected:
                        asyncio.run_coroutine_threadsafe(private.upload_private(self, path), self.loop)

                self.is_processing = False
                self.stop_status_animation()
                self.status_label.config(text="Upload(s) scheduled")

            button_frame = ttk.Frame(main_frame, style="TFrame")
            button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(20, 0))
            
            ok_btn = ttk.Button(button_frame, text="OK", 
                       command=on_ok, 
                       style="Accent.TButton",
                       width=15)
            ok_btn.pack(side=tk.RIGHT)
            
            # Apply dark mode if enabled
            if hasattr(self, 'dark_mode_enabled') and self.dark_mode_enabled:
                gui.apply_theme_to_toplevel(choice_window, True)
            
            choice_window.protocol("WM_DELETE_WINDOW", lambda: [choice_window.destroy(), self.status_label.config(text="Ready")])
            return

        self.is_processing = True
        self._current_operation = 'upload'

        for path in paths_to_upload:
            self.status_label.config(text=f"Uploading {os.path.basename(path)}")
            if os.path.isdir(path) and public_selected:
                asyncio.run_coroutine_threadsafe(public.upload_public_directory(self, path), self.loop)
            elif public_selected:
                asyncio.run_coroutine_threadsafe(public.upload_public(self, path), self.loop)
            elif private_selected:
                asyncio.run_coroutine_threadsafe(private.upload_private(self, path), self.loop)

        self.is_processing = False
        self.stop_status_animation()
        self.status_label.config(text="Upload(s) scheduled")

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
        """Async queue processing with success/failure tracking"""
        total_files = len(self.upload_queue)
        successful = 0
        failed = 0
        file_status = []
        
        while self.upload_queue and getattr(self, "is_processing", False):
            upload_type, file_path = self.upload_queue[0]
            filename = os.path.basename(file_path)
            current_index = total_files - len(self.upload_queue) + 1
            
            self.root.after(0, lambda: self.status_label.config(text=f"Uploading file {current_index} of {total_files}: {filename}"))
            
            # Try to upload with error handling
            try:
                if upload_type == "public":
                    result = await public.upload_public(self, file_path, from_queue=True)
                else:
                    result = await private.upload_private(self, file_path, from_queue=True)
                
                successful += 1
                file_status.append((filename, True, "Success"))
                self.logger.info(f"Queue upload successful: {filename}")
            except Exception as e:
                failed += 1
                error_message = str(e)
                file_status.append((filename, False, error_message))
                self.logger.error(f"Queue upload failed for {filename}: {error_message}")
            
            if self.upload_queue:
                self.upload_queue.pop(0)
                self.queue_listbox.delete(0)
                self.root.after(0, lambda: self.queue_label.config(text=f"Queue: {len(self.upload_queue)} files"))
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Processed {current_index} of {total_files} - Success: {successful}, Failed: {failed}"
                ))
        
        # Show final status to user
        self.is_processing = False
        self.stop_status_animation()
        
        # Only show dialog if there were failures
        if failed > 0:
            summary = f"Upload queue completed with {successful} successful and {failed} failed uploads."
            details = "\n".join([f"{name}: {'✓' if status else '✗'} {message if not status else ''}" 
                              for name, status, message in file_status])
            self.root.after(0, lambda: messagebox.showinfo("Upload Queue Results", f"{summary}\n\n{details}"))
        
        self.root.after(0, lambda: self.status_label.config(
            text=f"Queue processing completed - Success: {successful}, Failed: {failed}")
        )

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
        if hasattr(self, 'file_content_frame'):
            for btn in [self.wallet_btn, self.upload_btn, self.download_btn, self.manage_btn]:
                if btn == self.manage_btn:
                    btn.configure(style="ActiveNavButton.TButton")
                else:
                    btn.configure(style="NavButton.TButton")
                    
            # Clear and show the public data
            for widget in self.file_content_frame.winfo_children():
                widget.destroy()
                
            # Show loading message
            ttk.Label(self.file_content_frame, text="Loading public data...", style="Italic.TLabel").pack(anchor="w", pady=10)
            self.root.after(100, lambda: public.display_public_files(self, self.file_content_frame))
        else:
            public.manage_public_files(self)

    def manage_private_files(self):
        if hasattr(self, 'file_content_frame'):
            for btn in [self.wallet_btn, self.upload_btn, self.download_btn, self.manage_btn]:
                if btn == self.manage_btn:
                    btn.configure(style="ActiveNavButton.TButton")
                else:
                    btn.configure(style="NavButton.TButton")
                    
            # Clear and show the private data
            for widget in self.file_content_frame.winfo_children():
                widget.destroy()
                
            # Show loading message
            ttk.Label(self.file_content_frame, text="Loading private data...", style="Italic.TLabel").pack(anchor="w", pady=10)
            self.root.after(100, lambda: private.display_private_files(self, self.file_content_frame))
        else:
            private.manage_private_files(self)

    def retrieve_data(self):
        from get import retrieve_data
        retrieve_data(self)
        
    # Download queue methods
    def add_to_download_queue(self):
        """Add a data address to the download queue"""
        from tkinter import messagebox
        self.status_label.config(text="Adding address to download queue...")
        
        address = self.retrieve_entry.get().strip()
        if not address:
            messagebox.showwarning("Input Error", "Please enter a data address to add to the queue.")
            self.status_label.config(text="Ready")
            return
            
        self.download_queue.append(address)
        self.dl_queue_listbox.insert(tk.END, f"Address: {address[:10]}...")
        self.dl_queue_label.config(text=f"{len(self.download_queue)} files")
        self.status_label.config(text=f"Added address to download queue")
        
    def remove_from_download_queue(self):
        """Remove an item from the download queue"""
        from tkinter import messagebox
        selected = self.dl_queue_listbox.curselection()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select at least one item to remove from the queue.")
            return
        for index in sorted(selected, reverse=True):
            self.download_queue.pop(index)
            self.dl_queue_listbox.delete(index)
        self.dl_queue_label.config(text=f"{len(self.download_queue)} files")
        self.status_label.config(text=f"Removed {len(selected)} items from download queue")
        
    def start_download_queue(self):
        """Start processing the download queue"""
        from tkinter import messagebox
        if not self.download_queue:
            messagebox.showinfo("Queue Empty", "No items in the download queue.")
            return
        if not getattr(self, "is_processing", False):
            if messagebox.askyesno("Confirm Download", f"Start downloading {len(self.download_queue)} items now?"):
                self.is_processing = True
                self._current_operation = 'download'
                self.start_status_animation()
                asyncio.run_coroutine_threadsafe(self.process_download_queue(), self.loop)
                
    async def process_download_queue(self):
        """Process items in the download queue with success/failure tracking"""
        from get import _retrieve
        
        total_items = len(self.download_queue)
        successful = 0
        failed = 0
        item_status = []
        
        while self.download_queue and getattr(self, "is_processing", False):
            address = self.download_queue[0]
            address_display = f"{address[:10]}..."
            current_index = total_items - len(self.download_queue) + 1
            
            self.root.after(0, lambda: self.status_label.config(
                text=f"Downloading item {current_index} of {total_items}: {address_display}")
            )
            
            try:
                # Track if the download was successful
                result = await _retrieve(self, address, from_queue=True, return_status=True)
                if result:
                    successful += 1
                    item_status.append((address_display, True, "Success"))
                    self.logger.info(f"Queue download successful: {address_display}")
                else:
                    failed += 1
                    item_status.append((address_display, False, "Retrieval failed - invalid or inaccessible data"))
                    self.logger.error(f"Queue download failed for {address_display}: retrieval returned no data")
            except Exception as e:
                failed += 1
                error_message = str(e)
                item_status.append((address_display, False, error_message))
                self.logger.error(f"Error processing download item {address_display}: {error_message}")
            
            if self.download_queue:
                self.download_queue.pop(0)
                self.dl_queue_listbox.delete(0)
                self.root.after(0, lambda: self.dl_queue_label.config(text=f"{len(self.download_queue)} files"))
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Processed {current_index} of {total_items} - Success: {successful}, Failed: {failed}"
                ))
        
        # Show final status to user
        self.is_processing = False
        self.stop_status_animation()
        
        # Only show dialog if there were failures
        if failed > 0:
            summary = f"Download queue completed with {successful} successful and {failed} failed downloads."
            details = "\n".join([f"{addr}: {'✓' if status else '✗'} {message if not status else ''}" 
                               for addr, status, message in item_status])
            self.root.after(0, lambda: messagebox.showinfo("Download Queue Results", f"{summary}\n\n{details}"))
        
        self.root.after(0, lambda: self.status_label.config(
            text=f"Queue processing completed - Success: {successful}, Failed: {failed}")
        )

    def show_wallet_options(self):
        wallet_window = tk.Toplevel(self.root)
        wallet_window.title("Wallet Management")
        wallet_window.resizable(True, True)
        wallet_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
        wallet_window.transient(self.root)
        wallet_window.grab_set()
        
        # Main container with padding
        main_frame = ttk.Frame(wallet_window, style="TFrame", padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        ttk.Label(main_frame, text="Wallet Options", 
                font=("Inter", 16, "bold"), 
                foreground=COLORS["accent_primary"]).pack(anchor="w")
        
        ttk.Label(main_frame, text="Manage your wallet settings", 
                font=("Inter", 11),
                foreground=COLORS["text_secondary"]).pack(anchor="w", pady=(5, 20))
        
        # === Wallet Management Section ===
        ttk.Label(main_frame, text="Wallet Management", 
                font=("Inter", 12, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Create New Wallet button
        create_btn = ttk.Button(main_frame, text="Create New Wallet",
                              style="Accent.TButton",
                              command=lambda: wallet.create_wallet(self, wallet_window))
        create_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Import Wallet button
        import_btn = ttk.Button(main_frame, text="Import Wallet (Private Key)",
                              style="Accent.TButton",
                              command=lambda: wallet.import_wallet(self, wallet_window))
        import_btn.pack(fill=tk.X, pady=(0, 20))
        
        # === Wallet Actions Section ===
        ttk.Label(main_frame, text="Wallet Actions", 
                font=("Inter", 12, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Copy Wallet Address button
        def copy_wallet_address():
            if self.wallet:
                self.root.clipboard_clear()
                self.root.clipboard_append(self.wallet.address())
                
                # Create custom top-level dialog that stays on top
                success_dialog = tk.Toplevel(self.root)
                success_dialog.title("Setup Complete")
                success_dialog.resizable(True, True)
                success_dialog.configure(bg=gui.CURRENT_COLORS["bg_light"])
                success_dialog.transient(self.root)
                success_dialog.grab_set()
                
                # Centered container to hold content
                center_frame = ttk.Frame(success_dialog, style="TFrame")
                center_frame.pack(expand=True, fill=tk.BOTH)
                
                # Light bulb icon + message
                ttk.Label(center_frame, text="💡", font=("Inter", 24)).pack(pady=(10, 15))
                ttk.Label(center_frame, text="Wallet address copied to clipboard!", 
                        font=("Inter", 11)).pack(pady=10)
                
                # Separator
                ttk.Separator(center_frame, orient="horizontal").pack(fill=tk.X, pady=15)
                
                # OK button in its own frame at the bottom
                button_frame = ttk.Frame(success_dialog, style="TFrame")
                button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=15)
                
                ok_btn = ttk.Button(button_frame, text="OK", 
                                 command=lambda: [success_dialog.destroy(), wallet_window.destroy()],
                                 style="Accent.TButton",
                                 width=15)
                ok_btn.pack(pady=10)
                
                # Center the dialog on screen
                success_dialog.update_idletasks()
                width = success_dialog.winfo_reqwidth()
                height = success_dialog.winfo_reqheight()
                x = (success_dialog.winfo_screenwidth() // 2) - (width // 2)
                y = (success_dialog.winfo_screenheight() // 2) - (height // 2)
                success_dialog.geometry(f"{width}x{height}+{x}+{y}")
                
                # Override WM protocol to ensure proper destroy behavior
                success_dialog.protocol("WM_DELETE_WINDOW", success_dialog.destroy)
                success_dialog.focus_set()
            else:
                # Use the new styled error function instead of basic messagebox
                from wallet import show_styled_error
                show_styled_error(self, "Error", "No wallet loaded to copy address from.", wallet_window)
                
        copy_btn = ttk.Button(main_frame, text="Copy Wallet Address",
                           style="Secondary.TButton",
                           command=copy_wallet_address)
        copy_btn.pack(fill=tk.X, pady=(0, 10))
        
        # View Private Key button (new)
        view_pk_btn = ttk.Button(main_frame, text="View Private Key (Password Protected)",
                              style="Secondary.TButton",
                              command=lambda: wallet.display_private_key(self, wallet_window))
        view_pk_btn.pack(fill=tk.X, pady=(0, 20))
        
        # === Danger Zone Section ===
        danger_label = ttk.Label(main_frame, text="Danger Zone", 
                              font=("Inter", 11),
                              foreground=COLORS["error"])
        danger_label.pack(anchor="w", pady=(0, 10))
        
        # Delete button with warning styling
        delete_btn = ttk.Button(main_frame, text="Delete Current Wallet",
                             style="Secondary.TButton",
                             command=lambda: wallet.delete_wallet(self, wallet_window))
        delete_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Footer with close button
        footer_frame = ttk.Frame(main_frame, style="TFrame", padding=(0, 20, 0, 0))
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        close_btn = ttk.Button(footer_frame, text="Close",
                            style="Secondary.TButton",
                            command=wallet_window.destroy)
        close_btn.pack(side=tk.RIGHT)

    def view_archive_file(self, addr, name):
        view.view_file(self, addr, name)

    def start_status_update(self):
        """Configure status updates and animations"""
        # Set initial status message only if it hasn't been set already
        if hasattr(self, 'status_label') and not hasattr(self, 'status_initialized'):
            self.status_label.config(text="Checking connection...")
            self.status_initialized = True
        
        # Initialize animation state
        if hasattr(self, 'conn_dot'):
            self.connection_dot_state = 0
            self.connection_animation_running = False
            
        # Schedule regular status updates
        if self.status_update_task:
            self.root.after_cancel(self.status_update_task)
        self.status_update_task = self.root.after(500, self.update_status)

    def update_status(self):
        if self.is_processing:
            self.status_label.config(text=f"{self.status_dots[self.current_dot_idx]} {self._current_operation_message()} {self.status_dots[self.current_dot_idx]}")
            self.current_dot_idx = (self.current_dot_idx + 1) % len(self.status_dots)
        # Only schedule next update if processing or animating
        self.status_update_task = self.root.after(500, self.update_status)

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
        # Load persisted app state
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                self.uploaded_files = [(item["filename"], item["chunk_addr"]) for item in data.get("uploaded_files", [])]
                self.local_archives = [(item["addr"], item["nickname"], item["is_private"]) for item in data.get("local_archives", [])]
                self.upload_queue = [(item["type"], item["path"]) for item in data.get("upload_queue", [])]
                self.download_queue = data.get("download_queue", [])
                self.uploaded_private_files = [(item["filename"], item["access_token"]) for item in data.get("uploaded_private_files", [])]
                self.dark_mode_enabled = data.get("dark_mode_enabled", False)
                
                # Load balance history as a deque if present
                if "balance_history" in data:
                    # Convert string timestamps back to datetime objects
                    history_data = []
                    for record in data["balance_history"]:
                        if isinstance(record, dict) and 'timestamp' in record and isinstance(record['timestamp'], str):
                            try:
                                record_copy = record.copy()
                                record_copy['timestamp'] = datetime.datetime.fromisoformat(record['timestamp'])
                                history_data.append(record_copy)
                            except (ValueError, TypeError):
                                # Skip records with invalid timestamp format
                                continue
                        else:
                            # If timestamp is missing or not a string, skip this record
                            continue
                    self.balance_history = deque(history_data, maxlen=50)
                else:
                    self.balance_history = deque(maxlen=50)
                
                # Load saved crypto prices if available
                if "ant_price_usd" in data and data["ant_price_usd"] > 0:
                    self.ant_price_usd = data["ant_price_usd"]
                if "eth_price_usd" in data and data["eth_price_usd"] > 0:
                    self.eth_price_usd = data["eth_price_usd"]
                    
                self.logger.info("Loaded persistent data from %s", self.data_file)
        except Exception as e:
            self.logger.error("Failed to load persistent data: %s", e)
            self.uploaded_files = []
            self.local_archives = []
            self.upload_queue = []
            self.download_queue = []
            self.uploaded_private_files = []
            self.dark_mode_enabled = False

    def save_persistent_data(self):
        # Save app state to JSON
        try:
            # Convert datetime objects in balance_history to ISO format strings
            serializable_history = []
            for record in self.balance_history:
                # Create a copy of the record
                serialized_record = record.copy()
                # Convert datetime to string in ISO format
                if 'timestamp' in serialized_record and isinstance(serialized_record['timestamp'], datetime.datetime):
                    serialized_record['timestamp'] = serialized_record['timestamp'].isoformat()
                serializable_history.append(serialized_record)
            
            data = {
                "uploaded_files": [{"filename": f, "chunk_addr": a} for f, a in self.uploaded_files],
                "local_archives": [{"addr": a, "nickname": n, "is_private": p} for a, n, p in self.local_archives],
                "upload_queue": [{"type": t, "path": p} for t, p in self.upload_queue],
                "download_queue": self.download_queue,
                "uploaded_private_files": [{"filename": f, "access_token": a} for f, a in self.uploaded_private_files],
                "dark_mode_enabled": self.dark_mode_enabled,  # Save dark mode preference
                "ant_price_usd": self.ant_price_usd,  # Save current ANT price
                "eth_price_usd": self.eth_price_usd,   # Save current ETH price
                "balance_history": serializable_history  # Use the version with string timestamps
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=4)
            self.logger.info("Saved persistent data to %s", self.data_file)
        except Exception as e:
            self.logger.error("Failed to save persistent data: %s", e)

TestApp._view_archive_file = view.view_file

if __name__ == "__main__":
    app = TestApp()
    app.root.mainloop()