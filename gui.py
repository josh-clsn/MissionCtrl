import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import platform
import wallet
import public
import private
from PIL import Image, ImageTk
import io
import base64
import math

# Light Mode color palette
COLORS = {
    "bg_light": "#FFFFFF",         # Pure white background
    "bg_secondary": "#F5F7FA",     # Very light gray for secondary elements
    "bg_input": "#F8F9FB",         # Slightly off-white for input fields
    "text_primary": "#1A1D21",     # Near black for primary text
    "text_secondary": "#5F6368",   # Medium gray for secondary text
    "accent_primary": "#4F46E5",   # Indigo for primary accent
    "accent_secondary": "#7C3AED", # Purple for secondary accent
    "accent_tertiary": "#06B6D4",  # Cyan/teal for tertiary accent
    "success": "#10B981",          # Green for success states
    "warning": "#F59E0B",          # Amber for warnings
    "error": "#EF4444",            # Red for errors
    "border": "#E5E7EB"            # Light gray for borders
}

# Dark mode color palette
DARK_COLORS = {
    "bg_light": "#121212",         # Very dark background
    "bg_secondary": "#1A1A1A",     # Slightly lighter dark for secondary elements
    "bg_input": "#1F1F1F",         # Even slightly lighter for input fields
    "text_primary": "#E0E0E0",     # Light gray for primary text
    "text_secondary": "#A0A0A0",   # Medium gray for secondary text
    "accent_primary": "#6C63FF",   # Lighter indigo for primary accent
    "accent_secondary": "#9d74ff", # Lighter purple for secondary accent
    "accent_tertiary": "#30D5F2",  # Brighter cyan/teal for tertiary accent
    "success": "#1FD997",          # Brighter green for success states
    "warning": "#FFBB33",          # Brighter amber for warnings
    "error": "#FF5252",            # Brighter red for errors
    "border": "#333333"            # Dark gray for borders
}

# Global current color palette, starts with light mode
CURRENT_COLORS = COLORS.copy()

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip_window, text=self.text, background=CURRENT_COLORS["bg_light"], 
                        foreground=CURRENT_COLORS["text_primary"], relief="solid", borderwidth=1, 
                        font=("Inter", 9), padx=8, pady=4)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

def add_context_menu(widget):
    # Right-click context menu for cut/copy/paste
    menu = tk.Menu(widget, tearoff=0, bg=CURRENT_COLORS["bg_light"], fg=CURRENT_COLORS["text_primary"], 
                 activebackground=CURRENT_COLORS["accent_primary"], activeforeground="white")
    menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    widget.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))

def setup_main_gui(app):
    app.root.configure(bg=CURRENT_COLORS["bg_light"])
    app.root.option_add("*Font", "Inter 10")
    
    # Set window to fullscreen/maximized by default
    if platform.system() == "Windows":
        app.root.state('zoomed')
    else:
        app.root.attributes('-zoomed', True)
    
    # Configure the modern UI styles
    style = ttk.Style()
    style.theme_use('clam')
    
    # Configure basic styles
    style.configure(".", font=("Inter", 10), background=CURRENT_COLORS["bg_light"])
    
    # Button styles
    style.configure("TButton", 
                   padding=(12, 8), 
                   font=("Inter", 10),
                   background=CURRENT_COLORS["accent_primary"],
                   foreground="white")
    style.map("TButton", 
             background=[("active", CURRENT_COLORS["accent_secondary"]), 
                         ("disabled", CURRENT_COLORS["bg_light"])],
             foreground=[("disabled", CURRENT_COLORS["text_secondary"])])
    
    # Accent button style
    style.configure("Accent.TButton", 
                   background=CURRENT_COLORS["accent_primary"],
                   foreground="white")
    style.map("Accent.TButton", 
             background=[("active", CURRENT_COLORS["accent_secondary"])])
    
    # Secondary button style
    style.configure("Secondary.TButton", 
                   background=CURRENT_COLORS["bg_light"],
                   foreground=CURRENT_COLORS["text_primary"])
    style.map("Secondary.TButton", 
             background=[("active", CURRENT_COLORS["bg_secondary"]), 
                         ("hover", CURRENT_COLORS["bg_secondary"])],
             foreground=[("active", CURRENT_COLORS["text_primary"])])
    
    # Label styles
    style.configure("TLabel", 
                   background=CURRENT_COLORS["bg_light"], 
                   foreground=CURRENT_COLORS["text_primary"],
                   font=("Inter", 10))
    
    # Title label style
    style.configure("Title.TLabel", 
                   font=("Inter", 14, "bold"))
    
    # Subtitle label style
    style.configure("Subtitle.TLabel", 
                   font=("Inter", 12), 
                   foreground=CURRENT_COLORS["text_secondary"])
    
    # Card frames
    style.configure("Card.TFrame", 
                   background=CURRENT_COLORS["bg_light"],
                   relief="flat")
    
    # Rounded Card frames with shadow effect
    style.configure("RoundedCard.TFrame", 
                  background=CURRENT_COLORS["bg_secondary"],
                  relief="flat",
                  borderwidth=0)
                  
    # Inner frame for rounded cards
    style.configure("CardContent.TFrame", 
                  background=CURRENT_COLORS["bg_secondary"],
                  relief="flat",
                  borderwidth=0)
    
    # Nav Button style
    style.configure("NavButton.TButton", 
                  font=("Inter", 11),
                  padding=(15, 10),
                  background=CURRENT_COLORS["bg_secondary"],
                  foreground=CURRENT_COLORS["text_primary"])
    style.map("NavButton.TButton", 
             background=[("active", CURRENT_COLORS["accent_secondary"])],
             foreground=[("active", "white")])
                   
    # Active NavButton style
    style.configure("ActiveNavButton.TButton", 
                  font=("Inter", 11, "bold"),
                  padding=(15, 10),
                  background=CURRENT_COLORS["accent_primary"],
                  foreground="white")
    
    # Navigation Frame
    style.configure("Nav.TFrame", 
                  background=CURRENT_COLORS["bg_light"],
                  relief="flat")
                  
    # Card Label styles
    style.configure("CardTitle.TLabel", 
                  font=("Inter", 12, "bold"),
                  background=CURRENT_COLORS["bg_secondary"], 
                  foreground=CURRENT_COLORS["accent_primary"])
                  
    style.configure("CardText.TLabel", 
                  background=CURRENT_COLORS["bg_secondary"], 
                  foreground=CURRENT_COLORS["text_primary"])
                  
    style.configure("CardSecondary.TLabel", 
                  background=CURRENT_COLORS["bg_secondary"], 
                  foreground=CURRENT_COLORS["text_secondary"])
                  
    # Bold text label
    style.configure("Bold.TLabel", 
                  font=("Inter", 16, "bold"),
                  background=CURRENT_COLORS["bg_secondary"],
                  foreground=CURRENT_COLORS["text_primary"])
                  
    # Italic message
    style.configure("Italic.TLabel", 
                  font=("Inter", 11, "italic"),
                  background=CURRENT_COLORS["bg_secondary"],
                  foreground=CURRENT_COLORS["text_secondary"])
    
    # Checkbutton style
    style.configure("Card.TCheckbutton", 
                  background=CURRENT_COLORS["bg_secondary"],
                  foreground=CURRENT_COLORS["text_primary"])
    
    # Entry style
    style.configure("TEntry", 
                   fieldbackground=CURRENT_COLORS["bg_input"],
                   background=CURRENT_COLORS["bg_input"],
                   foreground=CURRENT_COLORS["text_primary"],
                   insertcolor=CURRENT_COLORS["text_primary"],
                   bordercolor=CURRENT_COLORS["border"],
                   lightcolor=CURRENT_COLORS["border"],
                   darkcolor=CURRENT_COLORS["border"],
                   selectbackground=CURRENT_COLORS["accent_primary"],
                   selectforeground="white",
                   borderwidth=1)
    style.map("TEntry", 
             fieldbackground=[("readonly", CURRENT_COLORS["bg_input"]), 
                             ("disabled", CURRENT_COLORS["bg_secondary"]),
                             ("active", CURRENT_COLORS["bg_input"])],
             foreground=[("readonly", CURRENT_COLORS["text_primary"]), 
                        ("disabled", CURRENT_COLORS["text_secondary"])],
             selectbackground=[("readonly", CURRENT_COLORS["accent_primary"]),
                              ("disabled", CURRENT_COLORS["accent_primary"])],
             selectforeground=[("readonly", "white"),
                              ("disabled", "white")],
             bordercolor=[("focus", CURRENT_COLORS["accent_primary"])])
    
    # Standard Checkbutton style
    style.configure("TCheckbutton", 
                   background=CURRENT_COLORS["bg_light"],
                   foreground=CURRENT_COLORS["text_primary"])
    style.map("TCheckbutton",
             background=[("active", CURRENT_COLORS["bg_light"])],
             indicatorcolor=[("selected", CURRENT_COLORS["accent_primary"])])
    
    # Notebook style
    style.configure("TNotebook", 
                   background=CURRENT_COLORS["bg_light"],
                   tabmargins=[0, 0, 0, 0])
    style.configure("TNotebook.Tab", 
                   background=CURRENT_COLORS["bg_secondary"],
                   foreground=CURRENT_COLORS["text_primary"],
                   padding=[16, 8],
                   font=("Inter", 10))
    style.map("TNotebook.Tab",
             background=[("selected", CURRENT_COLORS["bg_light"]), 
                        ("active", CURRENT_COLORS["bg_secondary"])],
             foreground=[("selected", CURRENT_COLORS["accent_primary"])])
    
    # Scrollbar style
    style.configure("TScrollbar", 
                   background=CURRENT_COLORS["bg_light"],
                   troughcolor=CURRENT_COLORS["bg_secondary"],
                   bordercolor=CURRENT_COLORS["bg_light"],
                   arrowcolor=CURRENT_COLORS["text_secondary"],
                   width=12)
    
    # Status frame
    style.configure("Status.TFrame", 
                   background=CURRENT_COLORS["bg_light"])
    
    # Create main container with padding
    main_frame = ttk.Frame(app.root, style="TFrame", padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

    # Ensure the root window has no white border
    app.root.configure(highlightthickness=0, bd=0, padx=0, pady=0, borderwidth=0)
    
    # Header with app name and status
    header_frame = ttk.Frame(main_frame, style="TFrame")
    header_frame.pack(fill=tk.X, pady=(0, 20))
    
    # App title
    ttk.Label(header_frame, text="Mission Ctrl", 
             font=("Inter", 20, "bold"),
             foreground=CURRENT_COLORS["accent_primary"]).pack(side=tk.LEFT)
    
    # Connection status on the right
    status_frame = ttk.Frame(header_frame, style="TFrame")
    status_frame.pack(side=tk.RIGHT)
    
    # Animated connection dot
    app.conn_dot = ttk.Label(status_frame, text="•", 
                          foreground=CURRENT_COLORS["success"], 
                          font=("Inter", 14, "bold"))
    app.conn_dot.pack(side=tk.LEFT, padx=(0, 5))
    
    # Network status text
    app.connection_label = ttk.Label(status_frame, text="Network: Connected", 
                                   foreground=CURRENT_COLORS["text_secondary"])
    app.connection_label.pack(side=tk.LEFT)
    
    # Setup the connection dot animation
    app.connection_dot_state = 0
    
    # Start pulse animation function for connection dot
    def animate_connection_dot():
        if hasattr(app, 'connection_animation_running') and app.connection_animation_running:
            app.connection_dot_state = (app.connection_dot_state + 0.1) % (2 * math.pi)
            opacity = int(55 + 200 * abs(math.sin(app.connection_dot_state)))
            color = "#4CAF50"
            
            # Apply opacity by adjusting brightness
            brightness = 0.5 + 0.5 * abs(math.sin(app.connection_dot_state))
            r = int(int(color[1:3], 16) * brightness)
            g = int(int(color[3:5], 16) * brightness)
            b = int(int(color[5:7], 16) * brightness)
            
            # Apply opacity and set new color
            new_color = f"#{r:02x}{g:02x}{b:02x}"
            app.conn_dot.config(foreground=new_color)
        
        # Continue animation loop
        app.root.after(100, animate_connection_dot)
    
    # Start the animation
    app.connection_animation_running = False
    animate_connection_dot()
    
    # Navigation buttons
    nav_frame = ttk.Frame(main_frame, style="Nav.TFrame")
    nav_frame.pack(fill=tk.X, pady=(0, 20))
    
    app.current_view = tk.StringVar(value="wallet")
    
    def show_wallet_view():
        app.current_view.set("wallet")
        update_content_view()
        update_nav_buttons()
        
    def show_upload_view():
        app.current_view.set("upload")
        update_content_view()
        update_nav_buttons()
        
    def show_download_view():
        app.current_view.set("download")
        update_content_view()
        update_nav_buttons()
        
    def show_manage_view():
        app.current_view.set("manage")
        update_content_view()
        update_nav_buttons()
        
        if hasattr(app, 'file_content_frame'):
            # Clear existing content
            for widget in app.file_content_frame.winfo_children():
                widget.destroy()
                
            # Display loading message and load public data
            ttk.Label(app.file_content_frame, text="Loading public data...", style="Italic.TLabel").pack(anchor="w", pady=10)
            app.root.after(100, lambda: public.display_public_files(app, app.file_content_frame))
    
    app.wallet_btn = ttk.Button(nav_frame, text="Wallet", command=show_wallet_view, 
                             style="ActiveNavButton.TButton")
    app.wallet_btn.pack(side=tk.LEFT, padx=(0, 2))
    
    app.upload_btn = ttk.Button(nav_frame, text="Upload", command=show_upload_view, 
                             style="NavButton.TButton")
    app.upload_btn.pack(side=tk.LEFT, padx=2)
    
    app.download_btn = ttk.Button(nav_frame, text="Download", command=show_download_view, 
                               style="NavButton.TButton")
    app.download_btn.pack(side=tk.LEFT, padx=2)
    
    app.manage_btn = ttk.Button(nav_frame, text="Manage Files", command=show_manage_view, 
                             style="NavButton.TButton")
    app.manage_btn.pack(side=tk.LEFT, padx=2)
    
    # Content frames for each view
    content_container = ttk.Frame(main_frame, style="TFrame")
    content_container.pack(fill=tk.BOTH, expand=True)
    
    # WALLET VIEW
    app.wallet_frame = ttk.Frame(content_container, style="TFrame")
    
    # Wallet summary - top row
    wallet_summary_frame = ttk.Frame(app.wallet_frame, style="TFrame")
    wallet_summary_frame.pack(fill=tk.X, pady=(0, 15))
    
    # Wallet address card - completely re-implemented to ensure consistent styling
    address_card = ttk.Frame(wallet_summary_frame, style="RoundedCard.TFrame", padding=15)
    address_card.pack(fill=tk.X, pady=(0, 10))
    
    # Card title with consistent styling
    title_label = ttk.Label(address_card, text="Wallet Address", style="CardTitle.TLabel")
    title_label.pack(anchor="w", pady=(0, 10))
    
    # Create frame for content with matching background
    address_content_frame = ttk.Frame(address_card, style="CardContent.TFrame")
    address_content_frame.pack(fill=tk.BOTH, expand=True)
    
    # Wallet address label with consistent styling
    app.wallet_address_label = ttk.Label(address_content_frame, 
                                     text="Wallet: Not Connected", 
                                     wraplength=500,
                                     style="CardText.TLabel")
    app.wallet_address_label.pack(anchor="w", fill=tk.X, pady=(0, 10))
    
    # Empty spacing frame to ensure consistent height
    spacing_frame = ttk.Frame(address_content_frame, style="CardContent.TFrame", height=20)
    spacing_frame.pack(fill=tk.X)
    
    # Balance cards in a horizontal row
    balance_frame = ttk.Frame(app.wallet_frame, style="TFrame")
    balance_frame.pack(fill=tk.X, pady=(0, 15))
    
    # ANT Balance Card
    ant_card = ttk.Frame(balance_frame, style="RoundedCard.TFrame", padding=15)
    ant_card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
    
    # Title with currency and price
    ant_title_frame = ttk.Frame(ant_card, style="CardContent.TFrame")
    ant_title_frame.pack(anchor="w", fill=tk.X, pady=(0, 5))
    
    ttk.Label(ant_title_frame, text="ANT ", style="CardTitle.TLabel").pack(side=tk.LEFT)
    app.ant_price_label = ttk.Label(ant_title_frame, text="$0.00", style="CardText.TLabel", foreground=CURRENT_COLORS["text_secondary"])
    app.ant_price_label.pack(side=tk.LEFT)
    
    app.ant_balance_label = ttk.Label(ant_card, text="Not Connected", style="Bold.TLabel")
    app.ant_balance_label.pack(anchor="w")
    
    # ETH Balance Card
    eth_card = ttk.Frame(balance_frame, style="RoundedCard.TFrame", padding=15)
    eth_card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
    
    # Title with currency and price
    eth_title_frame = ttk.Frame(eth_card, style="CardContent.TFrame")
    eth_title_frame.pack(anchor="w", fill=tk.X, pady=(0, 5))
    
    ttk.Label(eth_title_frame, text="ETH ", style="CardTitle.TLabel").pack(side=tk.LEFT)
    app.eth_price_label = ttk.Label(eth_title_frame, text="$0.00", style="CardText.TLabel", foreground=CURRENT_COLORS["text_secondary"])
    app.eth_price_label.pack(side=tk.LEFT)
    
    app.eth_balance_label = ttk.Label(eth_card, text="Not Connected", style="Bold.TLabel")
    app.eth_balance_label.pack(anchor="w")
    
    # Wallet actions in a card
    action_card = ttk.Frame(app.wallet_frame, style="RoundedCard.TFrame", padding=15)
    action_card.pack(fill=tk.X, pady=(0, 15))
    
    ttk.Label(action_card, text="Wallet Actions", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))
    
    wallet_actions = ttk.Frame(action_card, style="CardContent.TFrame", padding=(0, 10))
    wallet_actions.pack(fill=tk.X)
    
    # Unlock wallet button - only shown when wallet file exists but not unlocked
    # Will be positioned on the right side with other buttons
    def unlock_wallet():
        def on_wallet_loaded(success):
            # Update UI if wallet was unlocked
            if success:
                app.unlock_button.pack_forget()
        wallet.prompt_wallet_password(app, on_wallet_loaded)
    
    # Create right-side buttons first
    options_btn = ttk.Button(wallet_actions, text="Wallet Options", 
                          command=app.show_wallet_options, style="Accent.TButton")
    options_btn.pack(side=tk.RIGHT)
    
    send_funds_btn = ttk.Button(wallet_actions, text="Send Funds", 
                             command=lambda: wallet.send_funds(app, None), style="Accent.TButton")
    send_funds_btn.pack(side=tk.RIGHT, padx=10)
    
    # Create the unlock button
    # It will be packed by the ctrl.py logic when needed
    app.unlock_button = ttk.Button(wallet_actions, text="Unlock Wallet", 
                               command=unlock_wallet, style="Accent.TButton")
    # Don't pack it - it will be shown after cancel
    
    # History Card
    history_card = ttk.Frame(app.wallet_frame, style="RoundedCard.TFrame", padding=15)
    history_card.pack(fill=tk.BOTH, expand=True)
    
    ttk.Label(history_card, text="Transaction History", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))
    
    app.balance_history_frame = ttk.Frame(history_card, style="CardContent.TFrame")
    app.balance_history_frame.pack(fill=tk.X)
    
    ttk.Label(app.balance_history_frame, text="No recent transactions", style="Italic.TLabel").pack(anchor="w", pady=10)
    
    # UPLOAD VIEW 
    app.upload_frame = ttk.Frame(content_container, style="TFrame")
    
    # Upload Settings Card
    settings_card = ttk.Frame(app.upload_frame, style="RoundedCard.TFrame", padding=10)
    settings_card.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(settings_card, text="Storage Options", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 5))
    
    def toggle_public():
        if app.is_public_var.get():
            app.is_private_var.set(False)
    def toggle_private():
        if app.is_private_var.get():
            app.is_public_var.set(False)
    
    # Create a container for storage options
    option_container = ttk.Frame(settings_card, style="CardContent.TFrame")
    option_container.pack(fill=tk.X, pady=(0, 10))
    
    # Public option
    public_frame = ttk.Frame(option_container, style="CardContent.TFrame", padding=(0, 3))
    public_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    public_checkbox = ttk.Checkbutton(public_frame, text="Public", 
                                    variable=app.is_public_var, 
                                    command=toggle_public,
                                    style="Card.TCheckbutton")
    public_checkbox.pack(side=tk.LEFT)
    
    # Private option
    private_frame = ttk.Frame(option_container, style="CardContent.TFrame", padding=(0, 3))
    private_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    private_checkbox = ttk.Checkbutton(private_frame, text="Private", 
                                     variable=app.is_private_var, 
                                     command=toggle_private,
                                     style="Card.TCheckbutton")
    private_checkbox.pack(side=tk.LEFT)
    
    ttk.Label(private_frame, text="(Encrypted)", 
            style="CardSecondary.TLabel",
            font=("Inter", 9)).pack(side=tk.LEFT, padx=(5, 0))
    
    # Cost Calculation Section
    cost_frame = ttk.Frame(settings_card, style="CardContent.TFrame")
    cost_frame.pack(fill=tk.X, pady=3)
    
    cost_calc_checkbox = ttk.Checkbutton(cost_frame, text="Perform Cost Calculation", 
                                       variable=app.perform_cost_calc_var,
                                       style="Card.TCheckbutton")
    cost_calc_checkbox.pack(side=tk.LEFT)
    
    info_icon = ttk.Label(cost_frame, text="ℹ️", 
                        style="CardSecondary.TLabel",
                        cursor="question_arrow")
    info_icon.pack(side=tk.LEFT, padx=5)
    ToolTip(info_icon, "Cost calculation is not available for queued data.")
    
    # Upload Actions Card
    actions_card = ttk.Frame(app.upload_frame, style="RoundedCard.TFrame", padding=10)
    actions_card.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(actions_card, text="Upload Actions", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 5))
    
    button_frame = ttk.Frame(actions_card, style="CardContent.TFrame")
    button_frame.pack(fill=tk.X)
    
    upload_btn = ttk.Button(button_frame, text="Upload", 
                          command=app.upload_file, style="Accent.TButton")
    upload_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
    
    add_queue_btn = ttk.Button(button_frame, text="Add to Queue", 
                             command=app.add_to_upload_queue, style="Secondary.TButton")
    add_queue_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
    
    # Queue Card
    queue_card = ttk.Frame(app.upload_frame, style="RoundedCard.TFrame", padding=10)
    queue_card.pack(fill=tk.BOTH, expand=True)
    
    ttk.Label(queue_card, text="Upload Queue", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 3))
    
    header_frame = ttk.Frame(queue_card, style="CardContent.TFrame")
    header_frame.pack(fill=tk.X, pady=(0, 5))
    
    app.queue_label = ttk.Label(header_frame, text="0 files", style="CardSecondary.TLabel")
    app.queue_label.pack(side=tk.RIGHT)
    
    queue_list_frame = ttk.Frame(queue_card, style="CardContent.TFrame")
    queue_list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
    
    app.queue_listbox = tk.Listbox(queue_list_frame, height=4, 
                                bg=CURRENT_COLORS["bg_input"], 
                                fg=CURRENT_COLORS["text_primary"],
                                selectbackground=CURRENT_COLORS["accent_primary"],
                                selectforeground="white",
                                font=("Inter", 9),
                                bd=1, relief="solid", highlightthickness=0)
    app.queue_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar = ttk.Scrollbar(queue_list_frame, orient="vertical", 
                          command=app.queue_listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    app.queue_listbox.config(yscrollcommand=scrollbar.set)
    
    queue_actions = ttk.Frame(queue_card, style="CardContent.TFrame")
    queue_actions.pack(fill=tk.X)
    
    remove_btn = ttk.Button(queue_actions, text="Remove Selected", 
                         command=app.remove_from_queue, style="Secondary.TButton")
    remove_btn.pack(side=tk.LEFT)
    
    start_queue_btn = ttk.Button(queue_actions, text="Start Upload Queue", 
                             command=app.start_upload_queue, style="Accent.TButton")
    start_queue_btn.pack(side=tk.RIGHT)
    
    # DOWNLOAD VIEW
    app.download_frame = ttk.Frame(content_container, style="TFrame")
    
    # Download Card
    download_card = ttk.Frame(app.download_frame, style="RoundedCard.TFrame", padding=15)
    download_card.pack(fill=tk.X, pady=(0, 15))
    
    ttk.Label(download_card, text="Download Data", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))
    
    ttk.Label(download_card, text="Enter Data Address", style="CardSecondary.TLabel").pack(anchor="w", pady=(5, 10))
    
    app.retrieve_entry = ttk.Entry(download_card)
    app.retrieve_entry.pack(fill=tk.X, expand=True, pady=(0, 10))
    app.retrieve_entry.bind("<Return>", lambda event: app.retrieve_data())
    add_context_menu(app.retrieve_entry)
    
    button_frame = ttk.Frame(download_card, style="CardContent.TFrame")
    button_frame.pack(fill=tk.X)
    
    get_btn = ttk.Button(button_frame, text="Download Now", 
                     command=app.retrieve_data, style="Accent.TButton")
    get_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
    
    # Add Queue button
    add_to_dl_queue_btn = ttk.Button(button_frame, text="Add to Queue", 
                           command=lambda: app.add_to_download_queue(), style="Secondary.TButton")
    add_to_dl_queue_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
    
    # Download Queue card
    queue_card = ttk.Frame(app.download_frame, style="RoundedCard.TFrame", padding=15)
    queue_card.pack(fill=tk.BOTH, expand=True)
    
    ttk.Label(queue_card, text="Download Queue", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 5))
    
    header_frame = ttk.Frame(queue_card, style="CardContent.TFrame")
    header_frame.pack(fill=tk.X, pady=(0, 10))
    
    app.dl_queue_label = ttk.Label(header_frame, text="0 files", style="CardSecondary.TLabel")
    app.dl_queue_label.pack(side=tk.RIGHT)
    
    queue_list_frame = ttk.Frame(queue_card, style="CardContent.TFrame")
    queue_list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
    
    app.dl_queue_listbox = tk.Listbox(queue_list_frame, height=5, 
                                bg=CURRENT_COLORS["bg_input"], 
                                fg=CURRENT_COLORS["text_primary"],
                                selectbackground=CURRENT_COLORS["accent_primary"],
                                selectforeground="white",
                                font=("Inter", 9),
                                bd=1, relief="solid", highlightthickness=0)
    app.dl_queue_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    dl_scrollbar = ttk.Scrollbar(queue_list_frame, orient="vertical", 
                          command=app.dl_queue_listbox.yview)
    dl_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    app.dl_queue_listbox.config(yscrollcommand=dl_scrollbar.set)
    
    queue_actions = ttk.Frame(queue_card, style="CardContent.TFrame")
    queue_actions.pack(fill=tk.X)
    
    dl_remove_btn = ttk.Button(queue_actions, text="Remove Selected", 
                         command=lambda: app.remove_from_download_queue(), style="Secondary.TButton")
    dl_remove_btn.pack(side=tk.LEFT)
    
    start_dl_queue_btn = ttk.Button(queue_actions, text="Start Download Queue", 
                             command=lambda: app.start_download_queue(), style="Accent.TButton")
    start_dl_queue_btn.pack(side=tk.RIGHT)
    
    # MANAGE FILES VIEW
    app.manage_frame = ttk.Frame(content_container, style="TFrame")
    
    # Manage by type card
    manage_card = ttk.Frame(app.manage_frame, style="RoundedCard.TFrame", padding=15)
    manage_card.pack(fill=tk.X, pady=(0, 15))
    
    ttk.Label(manage_card, text="Manage By Storage Type", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))
    
    # Create a container for the buttons side by side
    buttons_container = ttk.Frame(manage_card, style="CardContent.TFrame")
    buttons_container.pack(fill=tk.X, pady=(5, 10))
    
    # Public data button
    manage_btn = ttk.Button(buttons_container, text="Public Data", 
                         command=lambda: show_public_data(app), style="Accent.TButton")
    manage_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
    
    # Private data button
    store_private_btn = ttk.Button(buttons_container, text="Private Data", 
                               command=lambda: show_private_data(app), style="Accent.TButton")
    store_private_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
    
    # File content card with increased height
    stats_card = ttk.Frame(app.manage_frame, style="RoundedCard.TFrame", padding=15)
    stats_card.pack(fill=tk.BOTH, expand=True)
    
    # Create a frame to hold the file content
    app.file_content_frame = ttk.Frame(stats_card, style="CardContent.TFrame")
    app.file_content_frame.pack(fill=tk.BOTH, expand=True)
    
    # Function to show public data content
    def show_public_data(app):
        # Clear current content
        for widget in app.file_content_frame.winfo_children():
            widget.destroy()
            
        ttk.Label(app.file_content_frame, text="Loading public data...", style="Italic.TLabel").pack(anchor="w", pady=10)
        app.root.after(100, lambda: public.display_public_files(app, app.file_content_frame))
    
    # Function to show private data content
    def show_private_data(app):
        # Clear current content
        for widget in app.file_content_frame.winfo_children():
            widget.destroy()
            
        ttk.Label(app.file_content_frame, text="Loading private data...", style="Italic.TLabel").pack(anchor="w", pady=10)
        app.root.after(100, lambda: private.display_private_files(app, app.file_content_frame))
    
    # Status bar with modern styling
    status_bar = ttk.Frame(main_frame, style="Status.TFrame")
    status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(30, 0))
    
    # Status label with more padding for animations
    app.status_label = ttk.Label(status_bar, text="Initializing...", 
                              foreground=CURRENT_COLORS["text_secondary"],
                              padding=(15, 15))
    app.status_label.pack(side=tk.LEFT)
    
    # Theme toggle button
    app.theme_btn = ttk.Button(status_bar, text="🌙", width=3, 
                            command=lambda: toggle_theme(app), style="Secondary.TButton")
    app.theme_btn.pack(side=tk.RIGHT)
    
    # Initialize dark mode if previously enabled
    app.is_dark_mode = getattr(app, 'dark_mode_enabled', False)
    if app.is_dark_mode:
        CURRENT_COLORS.update(DARK_COLORS)
        app.theme_btn.config(text="☀️")
        app.root.after(100, lambda: apply_theme(app))
    
    # Version label
    ttk.Label(status_bar, text="v2.0.0", 
            foreground=CURRENT_COLORS["text_secondary"],
            padding=(15, 15)).pack(side=tk.RIGHT)
    
    # Function to update navigation buttons
    def update_nav_buttons():
        view = app.current_view.get()
        
        # Reset all buttons to default style
        app.wallet_btn.configure(style="NavButton.TButton")
        app.upload_btn.configure(style="NavButton.TButton")
        app.download_btn.configure(style="NavButton.TButton")
        app.manage_btn.configure(style="NavButton.TButton")
        
        # Highlight active button
        if view == "wallet":
            app.wallet_btn.configure(style="ActiveNavButton.TButton")
        elif view == "upload":
            app.upload_btn.configure(style="ActiveNavButton.TButton")
        elif view == "download":
            app.download_btn.configure(style="ActiveNavButton.TButton")
        elif view == "manage":
            app.manage_btn.configure(style="ActiveNavButton.TButton")
    
    # Function to update content view based on selected view
    def update_content_view():
        # Hide all frames
        app.wallet_frame.pack_forget()
        app.upload_frame.pack_forget()
        app.download_frame.pack_forget()
        app.manage_frame.pack_forget()
        
        # Show selected frame
        view = app.current_view.get()
        if view == "wallet":
            app.wallet_frame.pack(fill=tk.BOTH, expand=True)
        elif view == "upload":
            app.upload_frame.pack(fill=tk.BOTH, expand=True)
        elif view == "download":
            app.download_frame.pack(fill=tk.BOTH, expand=True)
        elif view == "manage":
            app.manage_frame.pack(fill=tk.BOTH, expand=True)
    
    # Show default wallet view
    update_content_view()
    
    app.root.resizable(True, True)

def apply_theme_to_toplevel(toplevel, is_dark=False):
    """Apply theme to a toplevel/dialog window"""
    colors = DARK_COLORS if is_dark else COLORS
    
    toplevel.configure(bg=colors["bg_light"])
    
    # Apply to all child widgets
    for child in toplevel.winfo_children():
        if isinstance(child, tk.Frame):
            child.configure(bg=colors["bg_light"], highlightthickness=0, bd=0)
        elif isinstance(child, tk.Label):
            child.configure(bg=colors["bg_light"], fg=colors["text_primary"])
        elif isinstance(child, tk.Entry):
            child.configure(
                bg=colors["bg_input"],
                fg=colors["text_primary"],
                insertbackground=colors["text_primary"],
                selectbackground=colors["accent_primary"],
                selectforeground="white",
                highlightbackground=colors["border"],
                disabledbackground=colors["bg_secondary"],
                readonlybackground=colors["bg_input"]
            )
        elif isinstance(child, tk.Button):
            if child.cget("text") in ["OK", "Unlock", "Submit", "Confirm"]:
                # Primary action buttons
                child.configure(
                    bg=colors["accent_primary"],
                    fg="white",
                    activebackground=colors["accent_secondary"],
                    activeforeground="white"
                )
            else:
                # Secondary buttons
                child.configure(
                    bg=colors["bg_secondary"],
                    fg=colors["text_primary"],
                    activebackground=colors["bg_light"],
                    activeforeground=colors["text_primary"]
                )
        
        # Recursive call for any child containers
        if hasattr(child, 'winfo_children') and callable(child.winfo_children):
            for grandchild in child.winfo_children():
                if hasattr(grandchild, 'configure'):
                    try:
                        if isinstance(grandchild, tk.Entry):
                            grandchild.configure(
                                bg=colors["bg_input"],
                                fg=colors["text_primary"],
                                insertbackground=colors["text_primary"],
                                disabledbackground=colors["bg_secondary"]
                            )
                        elif isinstance(grandchild, tk.Label):
                            grandchild.configure(bg=colors["bg_light"], fg=colors["text_primary"])
                        elif isinstance(grandchild, tk.Frame):
                            grandchild.configure(bg=colors["bg_light"])
                    except:
                        pass

def toggle_theme(app):
    """Toggle between light and dark mode"""
    global CURRENT_COLORS
    
    # Switch to the other theme
    if CURRENT_COLORS == COLORS:
        CURRENT_COLORS = DARK_COLORS.copy()
        app.theme_btn.config(text="☀️")  # Sun emoji for light mode
        app.is_dark_mode = True
    else:
        CURRENT_COLORS = COLORS.copy()
        app.theme_btn.config(text="🌙")  # Moon emoji for dark mode
        app.is_dark_mode = False
    
    # Apply the new theme
    apply_theme(app)
    
    # Directly update the file content frame if it exists
    if hasattr(app, 'file_content_frame'):
        for widget in app.file_content_frame.winfo_children():
            _apply_theme_to_widget(widget)
    
    # Apply theme to any open toplevel windows
    for window in app.root.winfo_toplevel().winfo_children():
        if isinstance(window, tk.Toplevel):
            apply_theme_to_toplevel(window, app.is_dark_mode)

def apply_theme(app):
    """Apply the current theme to all UI elements"""
    style = ttk.Style()
    
    app.root.configure(bg=CURRENT_COLORS["bg_light"], 
                      highlightthickness=0, 
                      bd=0, 
                      borderwidth=0)
    
    for frame in app.root.winfo_children():
        if isinstance(frame, ttk.Frame) or isinstance(frame, tk.Frame):
            if hasattr(frame, 'configure'):
                try:
                    frame.configure(highlightthickness=0, bd=0, borderwidth=0)
                    if isinstance(frame, tk.Frame):
                        frame.configure(bg=CURRENT_COLORS["bg_light"])
                except:
                    pass
    
    # Update basic styles
    style.configure(".", background=CURRENT_COLORS["bg_light"])
    style.configure("TFrame", background=CURRENT_COLORS["bg_light"])
    style.configure("TLabel", background=CURRENT_COLORS["bg_light"], foreground=CURRENT_COLORS["text_primary"])
    
    # Update button styles
    style.configure("TButton", background=CURRENT_COLORS["accent_primary"], foreground="white")
    style.configure("Accent.TButton", background=CURRENT_COLORS["accent_primary"], foreground="white")
    style.configure("Secondary.TButton", background=CURRENT_COLORS["bg_light"], foreground=CURRENT_COLORS["text_primary"])
    
    # Update NavButton styles
    style.configure("NavButton.TButton", background=CURRENT_COLORS["bg_secondary"], foreground=CURRENT_COLORS["text_primary"])
    style.configure("ActiveNavButton.TButton", background=CURRENT_COLORS["accent_primary"], foreground="white")
    
    # Update the navigation frame background - fixes white area behind tab buttons
    style.configure("Nav.TFrame", background=CURRENT_COLORS["bg_light"], relief="flat")
    
    # Update card styles
    style.configure("RoundedCard.TFrame", background=CURRENT_COLORS["bg_secondary"], borderwidth=0)
    style.configure("CardContent.TFrame", background=CURRENT_COLORS["bg_secondary"], borderwidth=0)
    style.configure("CardTitle.TLabel", background=CURRENT_COLORS["bg_secondary"], foreground=CURRENT_COLORS["accent_primary"])
    style.configure("CardText.TLabel", background=CURRENT_COLORS["bg_secondary"], foreground=CURRENT_COLORS["text_primary"])
    style.configure("CardSecondary.TLabel", background=CURRENT_COLORS["bg_secondary"], foreground=CURRENT_COLORS["text_secondary"])
    
    # Update other specialized styles
    style.configure("Bold.TLabel", background=CURRENT_COLORS["bg_secondary"], foreground=CURRENT_COLORS["text_primary"])
    style.configure("Italic.TLabel", background=CURRENT_COLORS["bg_secondary"], foreground=CURRENT_COLORS["text_secondary"])
    style.configure("Card.TCheckbutton", background=CURRENT_COLORS["bg_secondary"], foreground=CURRENT_COLORS["text_primary"])
    
    # Update entry widgets with more detailed styling
    style.configure("TEntry", 
                   fieldbackground=CURRENT_COLORS["bg_input"],
                   background=CURRENT_COLORS["bg_input"],
                   foreground=CURRENT_COLORS["text_primary"],
                   insertcolor=CURRENT_COLORS["text_primary"],
                   bordercolor=CURRENT_COLORS["border"],
                   lightcolor=CURRENT_COLORS["border"],
                   darkcolor=CURRENT_COLORS["border"],
                   selectbackground=CURRENT_COLORS["accent_primary"],
                   selectforeground="white",
                   borderwidth=1)
    
    # Update entry field state maps
    style.map("TEntry", 
             fieldbackground=[("readonly", CURRENT_COLORS["bg_input"]), 
                             ("disabled", CURRENT_COLORS["bg_secondary"]),
                             ("active", CURRENT_COLORS["bg_input"])],
             foreground=[("readonly", CURRENT_COLORS["text_primary"]), 
                        ("disabled", CURRENT_COLORS["text_secondary"])],
             selectbackground=[("readonly", CURRENT_COLORS["accent_primary"]),
                              ("disabled", CURRENT_COLORS["accent_primary"])],
             selectforeground=[("readonly", "white"),
                              ("disabled", "white")],
             bordercolor=[("focus", CURRENT_COLORS["accent_primary"])])
    
    # LabelFrame styling with border color correction
    style.configure("TLabelframe", 
                   background=CURRENT_COLORS["bg_light"],
                   bordercolor=CURRENT_COLORS["border"],
                   darkcolor=CURRENT_COLORS["border"],
                   lightcolor=CURRENT_COLORS["border"])
    
    style.configure("TLabelframe.Label", 
                   background=CURRENT_COLORS["bg_light"],
                   foreground=CURRENT_COLORS["text_primary"])
    
    # Standard Checkbutton style
    style.configure("TCheckbutton", 
                   background=CURRENT_COLORS["bg_light"],
                   foreground=CURRENT_COLORS["text_primary"])
    style.map("TCheckbutton",
             background=[("active", CURRENT_COLORS["bg_light"])],
             indicatorcolor=[("selected", CURRENT_COLORS["accent_primary"])])
    
    # Notebook style
    style.configure("TNotebook", 
                   background=CURRENT_COLORS["bg_light"],
                   tabmargins=[0, 0, 0, 0])
    style.configure("TNotebook.Tab", 
                   background=CURRENT_COLORS["bg_secondary"],
                   foreground=CURRENT_COLORS["text_primary"],
                   padding=[16, 8],
                   font=("Inter", 10))
    style.map("TNotebook.Tab",
             background=[("selected", CURRENT_COLORS["bg_light"]), 
                        ("active", CURRENT_COLORS["bg_secondary"])],
             foreground=[("selected", CURRENT_COLORS["accent_primary"])])
    
    # Scrollbar style
    style.configure("TScrollbar", 
                   background=CURRENT_COLORS["bg_secondary"],
                   troughcolor=CURRENT_COLORS["bg_light"],
                   bordercolor=CURRENT_COLORS["bg_secondary"],
                   arrowcolor=CURRENT_COLORS["text_primary"],
                   width=12)
    style.map("TScrollbar",
             background=[("active", CURRENT_COLORS["accent_primary"])],
             arrowcolor=[("active", "white")])
    
    # Status frame style - critical for bottom white strip
    style.configure("Status.TFrame", 
                   background=CURRENT_COLORS["bg_light"],
                   borderwidth=0,
                   highlightthickness=0)
    
    # Update ALL tkinter widgets with the appropriate colors
    for widget in app.root.winfo_children():
        _apply_theme_to_widget(widget)
    
    # Update canvas backgrounds
    _update_canvas_backgrounds(app.root)
    
    # Update listbox colors
    if hasattr(app, 'queue_listbox'):
        app.queue_listbox.config(bg=CURRENT_COLORS["bg_input"], 
                             fg=CURRENT_COLORS["text_primary"],
                             selectbackground=CURRENT_COLORS["accent_primary"],
                             selectforeground="white",
                             bd=1, 
                             relief="solid", 
                             highlightthickness=0,
                             highlightbackground=CURRENT_COLORS["border"],
                             highlightcolor=CURRENT_COLORS["accent_primary"])
    
    if hasattr(app, 'dl_queue_listbox'):
        app.dl_queue_listbox.config(bg=CURRENT_COLORS["bg_input"], 
                                fg=CURRENT_COLORS["text_primary"],
                                selectbackground=CURRENT_COLORS["accent_primary"],
                                selectforeground="white",
                                bd=1, 
                                relief="solid", 
                                highlightthickness=0,
                                highlightbackground=CURRENT_COLORS["border"],
                                highlightcolor=CURRENT_COLORS["accent_primary"])
    
    # Save the theme preference
    if hasattr(app, 'save_persistent_data'):
        app.dark_mode_enabled = app.is_dark_mode
        app.save_persistent_data()

def _apply_theme_to_widget(widget):
    """Recursively apply theme to a widget and all its children"""
    try:
        if isinstance(widget, tk.Entry):
            widget.config(bg=CURRENT_COLORS["bg_input"], 
                        fg=CURRENT_COLORS["text_primary"],
                        insertbackground=CURRENT_COLORS["text_primary"], 
                        disabledbackground=CURRENT_COLORS["bg_secondary"],
                        disabledforeground=CURRENT_COLORS["text_secondary"], 
                        readonlybackground=CURRENT_COLORS["bg_input"],
                        selectbackground=CURRENT_COLORS["accent_primary"],
                        selectforeground="white",
                        bd=1, 
                        relief="solid",
                        highlightbackground=CURRENT_COLORS["border"],
                        highlightcolor=CURRENT_COLORS["accent_primary"],
                        highlightthickness=1)
        elif isinstance(widget, ttk.Entry):
            # For ttk.Entry we modify both the widget and the style
            style = ttk.Style()
            entry_style = f"Custom.TEntry.{id(widget)}"
            style.configure(entry_style, 
                          fieldbackground=CURRENT_COLORS["bg_input"],
                          background=CURRENT_COLORS["bg_input"],
                          foreground=CURRENT_COLORS["text_primary"],
                          bordercolor=CURRENT_COLORS["border"],
                          insertcolor=CURRENT_COLORS["text_primary"])
            style.map(entry_style,
                     fieldbackground=[("readonly", CURRENT_COLORS["bg_input"]), 
                                     ("disabled", CURRENT_COLORS["bg_secondary"])],
                     foreground=[("readonly", CURRENT_COLORS["text_primary"]), 
                                ("disabled", CURRENT_COLORS["text_secondary"])])
            widget.configure(style=entry_style)
            
        elif isinstance(widget, tk.Text):
            widget.config(bg=CURRENT_COLORS["bg_input"], 
                        fg=CURRENT_COLORS["text_primary"],
                        insertbackground=CURRENT_COLORS["text_primary"],
                        selectbackground=CURRENT_COLORS["accent_primary"],
                        selectforeground="white",
                        bd=1, 
                        relief="solid",
                        highlightbackground=CURRENT_COLORS["border"],
                        highlightcolor=CURRENT_COLORS["accent_primary"])
        elif isinstance(widget, tk.Listbox):
            widget.config(bg=CURRENT_COLORS["bg_input"], 
                        fg=CURRENT_COLORS["text_primary"],
                        selectbackground=CURRENT_COLORS["accent_primary"], 
                        selectforeground="white",
                        bd=1, 
                        relief="solid",
                        highlightthickness=0,
                        highlightbackground=CURRENT_COLORS["border"],
                        highlightcolor=CURRENT_COLORS["accent_primary"])
        elif isinstance(widget, tk.Canvas):
            widget.config(bg=CURRENT_COLORS["bg_secondary"],
                        bd=0, 
                        highlightthickness=0)
        elif isinstance(widget, tk.Frame):
            # For non-ttk frames which don't use styles
            widget.config(bg=CURRENT_COLORS["bg_secondary"],
                        bd=0, 
                        highlightthickness=0)
                        
        # Handle LabelFrame specifically
        elif isinstance(widget, tk.LabelFrame):
            widget.config(bg=CURRENT_COLORS["bg_secondary"], 
                        fg=CURRENT_COLORS["text_primary"],
                        bd=1, 
                        relief="solid",
                        highlightbackground=CURRENT_COLORS["border"],
                        highlightcolor=CURRENT_COLORS["border"])
        
        # Apply theme to any toplevel windows
        if isinstance(widget, tk.Toplevel):
            # Apply full styling to the toplevel window
            apply_theme_to_toplevel(widget, CURRENT_COLORS == DARK_COLORS)
            
        # Handle specific widget types with highlighting
        if hasattr(widget, 'cget') and widget.winfo_class() in ('Entry', 'Listbox', 'Text'):
            try:
                widget.config(highlightbackground=CURRENT_COLORS["border"],
                            highlightcolor=CURRENT_COLORS["accent_primary"])
            except tk.TclError:
                pass
                
    except tk.TclError:
        # Some widgets may not support all configurations
        pass
    
    # Apply theme to all children
    for child in widget.winfo_children():
        _apply_theme_to_widget(child)

def _update_canvas_backgrounds(widget):
    """Recursively find all canvases and update their backgrounds"""
    if isinstance(widget, tk.Canvas):
        widget.config(bg=CURRENT_COLORS["bg_secondary"], 
                    bd=0, 
                    highlightthickness=0)
        
        # Update any windows embedded in the canvas
        for window_id in widget.find_withtag("window"):
            try:
                # Get the embedded widget from the window item
                embedded_widget = widget.nametowidget(widget.itemcget(window_id, "window"))
                if embedded_widget:
                    _apply_theme_to_widget(embedded_widget)
            except:
                # Skip if any errors occur in finding/applying to embedded widgets
                pass
    
    # Recursively check all children
    for child in widget.winfo_children():
        _update_canvas_backgrounds(child)