# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import platform

def add_context_menu(widget):
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    widget.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))

def setup_main_gui(app):
    style = ttk.Style()
    style.configure("TButton", padding=6, font=("Arial", 10))
    style.map("TButton", background=[("active", "#d3d3d3")])
    style.configure("TLabel", background="#f0f2f5", font=("Arial", 10))
    style.configure("Card.TFrame", background="#ffffff")
    style.configure("Accent.TButton", background="#b0c4de", foreground="black")
    style.map("Accent.TButton", background=[("active", "#a9b7d1")])
    style.configure("Status.TFrame", background="#e9ecef")

    main_frame = ttk.Frame(app.root, padding="15")
    main_frame.pack(fill=tk.BOTH, expand=True)

    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill=tk.BOTH, expand=True)

    # Wallet Tab
    wallet_tab = ttk.Frame(notebook)
    notebook.add(wallet_tab, text="Wallet")
    
    app.connection_label = ttk.Label(wallet_tab, text="Network: Connecting...", foreground="#666666")
    app.connection_label.pack(pady=(0, 15))

    wallet_card = ttk.Frame(wallet_tab, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
    wallet_card.pack(fill=tk.X, pady=(0, 15))
    app.wallet_address_label = ttk.Label(wallet_card, text="Wallet: Not Connected", wraplength=400, foreground="#333333")
    app.wallet_address_label.pack(anchor="w")
    wallet_actions = ttk.Frame(wallet_card)
    wallet_actions.pack(fill=tk.X, pady=(10, 0))
    options_btn = ttk.Button(wallet_actions, text="Wallet Options", command=app.show_wallet_options)
    options_btn.pack(side=tk.RIGHT)
    help_btn = ttk.Button(wallet_actions, text="Help", command=lambda: show_help(app))
    help_btn.pack(side=tk.RIGHT, padx=5)

    balance_card = ttk.Frame(wallet_tab, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
    balance_card.pack(fill=tk.X, pady=(0, 15))
    balances = ttk.Frame(balance_card)
    balances.pack(fill=tk.X)
    app.ant_balance_label = ttk.Label(balances, text="ANT Balance: Not Connected", foreground="#333333")
    app.ant_balance_label.pack(side=tk.LEFT)
    app.eth_balance_label = ttk.Label(balances, text="ETH Balance: Not Connected", foreground="#333333")
    app.eth_balance_label.pack(side=tk.RIGHT)
    refresh_btn = ttk.Button(balance_card, text="Refresh", command=app.update_balances)
    refresh_btn.pack(pady=(10, 0))

    # Upload Tab
    upload_tab = ttk.Frame(notebook)
    notebook.add(upload_tab, text="Upload")
    
    actions_frame = ttk.Frame(upload_tab, padding="10")
    actions_frame.pack(fill=tk.X, pady=(0, 15))
    def toggle_public():
        if app.is_public_var.get():
            app.is_private_var.set(False)
    def toggle_private():
        if app.is_private_var.get():
            app.is_public_var.set(False)
    public_checkbox = ttk.Checkbutton(actions_frame, text="Public", variable=app.is_public_var, command=toggle_public)
    public_checkbox.pack(anchor="w")
    private_checkbox = ttk.Checkbutton(actions_frame, text="Private (encrypted)", variable=app.is_private_var, command=toggle_private)
    private_checkbox.pack(anchor="w")
    upload_btn = ttk.Button(actions_frame, text="Upload", command=app.upload_file, style="Accent.TButton")
    upload_btn.pack(fill=tk.X, pady=(10, 0))

    queue_frame = ttk.Frame(actions_frame)
    queue_frame.pack(fill=tk.X, pady=(5, 0))
    add_queue_btn = ttk.Button(queue_frame, text="Add to Upload Queue", command=app.add_to_upload_queue, style="Accent.TButton")
    add_queue_btn.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
    start_queue_btn = ttk.Button(queue_frame, text="Start Upload Queue", command=app.start_upload_queue, style="Accent.TButton")
    start_queue_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    app.queue_label = ttk.Label(actions_frame, text="Queue: 0 files")
    app.queue_label.pack(anchor="w", pady=(5, 0))
    
    queue_list_frame = ttk.Frame(actions_frame)
    queue_list_frame.pack(fill=tk.BOTH, expand=True)
    app.queue_listbox = tk.Listbox(queue_list_frame, height=5)
    app.queue_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar = ttk.Scrollbar(queue_list_frame, orient="vertical", command=app.queue_listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    app.queue_listbox.config(yscrollcommand=scrollbar.set)
    
    remove_btn = ttk.Button(actions_frame, text="Remove Selected", command=app.remove_from_queue)
    remove_btn.pack(pady=(5, 0))

    # Download Tab
    retrieve_tab = ttk.Frame(notebook)
    notebook.add(retrieve_tab, text="Download")
    
    retrieve_frame = ttk.Frame(retrieve_tab, padding="10")
    retrieve_frame.pack(fill=tk.X)
    ttk.Label(retrieve_frame, text="Download Data", font=("Arial", 11, "bold")).pack(anchor="w")
    retrieve_inner = ttk.Frame(retrieve_frame, relief="solid", borderwidth=1, padding="10", style="Card.TFrame")
    retrieve_inner.pack(fill=tk.X, pady=(5, 0))
    app.retrieve_entry = ttk.Entry(retrieve_inner)
    app.retrieve_entry.pack(fill=tk.X, pady=(0, 10))
    app.retrieve_entry.bind("<Return>", lambda event: app.retrieve_data())
    add_context_menu(app.retrieve_entry)
    get_btn = ttk.Button(retrieve_inner, text="Get", command=app.retrieve_data, style="Accent.TButton")
    get_btn.pack(fill=tk.X)

    # Manage Files Tab
    manage_tab = ttk.Frame(notebook)
    notebook.add(manage_tab, text="Manage Files")
    
    manage_frame = ttk.Frame(manage_tab, padding="10")
    manage_frame.pack(fill=tk.BOTH, expand=True)
    manage_btn = ttk.Button(manage_frame, text="Manage Public Data", command=app.manage_public_files, style="Accent.TButton")
    manage_btn.pack(fill=tk.X, pady=5)
    store_private_btn = ttk.Button(manage_frame, text="Manage Private Data", command=app.manage_private_files, style="Accent.TButton")
    store_private_btn.pack(fill=tk.X, pady=5)

    status_bar = ttk.Frame(main_frame, relief="sunken", borderwidth=1)
    status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    app.status_label = ttk.Label(status_bar, text="Ready", foreground="#666666")
    app.status_label.pack(side=tk.LEFT, padx=5)
    ttk.Label(status_bar, text="v1.0.0", foreground="#666666").pack(side=tk.RIGHT, padx=5)

    # Allow resizing to enable window manager controls
    app.root.resizable(True, True)

def show_help(app):
    help_window = tk.Toplevel(app.root)
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

