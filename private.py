import asyncio
import os
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from autonomi_client import PaymentOption, DataMapChunk
import view
import gui

logger = logging.getLogger("MissionCtrl")

async def upload_private(app, file_path, from_queue=False):
    """
    Upload a file privately (encrypted) to the network
    
    Args:
        app: The application instance
        file_path: The path of the file to upload
        from_queue: Whether this is being called as part of queue processing
        
    Returns:
        True for successful upload, False for failure when from_queue=True
        None otherwise
    """
    success = False
    
    app.status_label.config(
        text=(
            f"Getting quote... for {os.path.basename(file_path)}"
            if app.perform_cost_calc_var.get() and not from_queue
            else f"Uploading file: {os.path.basename(file_path)}"
        )
    )
    app.is_processing = True
    app.start_status_animation()
    try:
        payment_option = PaymentOption.wallet(app.wallet)
        ant_balance = int(await app.wallet.balance())
        if ant_balance <= 0:
            app.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload. Add ANT to your wallet in the Wallet tab."))
            app.is_processing = False
            app.stop_status_animation()
            return False if from_queue else None
        
        with open(file_path, "rb") as f:
            file_data = f.read()
        logger.info("File data type for %s: %s, length: %d", file_path, type(file_data), len(file_data))

        if app.perform_cost_calc_var.get() and not from_queue:
            logger.info("Calculating estimated cost for private file: %s", file_path)
            app._current_operation = 'cost_calc'
            try:
                estimated_cost = await asyncio.wait_for(
                    app.client.data_cost(file_data),
                    timeout=1000
                )
                logger.info("Estimated cost: %s ANT", estimated_cost)
            except asyncio.TimeoutError:
                logger.error("Cost calculation timed out after 1000 seconds")
                app.root.after(0, lambda: messagebox.showerror("Error", "Cost calculation timed out after 400 seconds. Check your network connection."))
                app.is_processing = False
                app.stop_status_animation()
                return False if from_queue else None
            app._current_operation = None
            app.status_label.config(text=f"Quote retrieved: {estimated_cost} ANT for {os.path.basename(file_path)}")
            app.stop_status_animation()

            def show_confirmation():
                nonlocal proceed
                proceed = messagebox.askyesno("Confirm Upload", f"Estimated cost: {estimated_cost} ANT. Proceed?")
                app.root.after(0, continue_upload)

            proceed = False
            app.root.after(0, show_confirmation)
            while not proceed and app.is_processing:
                await asyncio.sleep(0.1)
            if not proceed:
                logger.info("Upload cancelled by user")
                app.is_processing = False
                app.status_label.config(text="Upload cancelled")
                return False if from_queue else None

        logger.info("Upload started for file: %s", file_path)
        app._current_operation = 'upload'
        app.status_label.config(text=f"Uploading file: {os.path.basename(file_path)}")
        app.start_status_animation()
        
        logger.info("Data type passed to data_put: %s", type(file_data))
        price, data_map_chunk = await asyncio.wait_for(
            app.client.data_put(file_data, payment_option),
            timeout=15000
        )
        access_token = data_map_chunk.to_hex()
        file_name = os.path.basename(file_path)
        app.uploaded_private_files.append((file_name, access_token))
        app.save_persistent_data()
        logger.info("Private data uploaded, price: %s ANT, access_token: %s", price, access_token)
        if not from_queue:
            app.root.after(0, lambda: app._show_upload_success(access_token, file_name, True))
        success = True
    except asyncio.TimeoutError:
        logger.error("Upload timed out after 300 seconds")
        if not from_queue:
            app.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 300 seconds. Check your network connection."))
        app.status_label.config(text="Upload timeout")
    except Exception as e:
        import traceback
        logger.error("Upload error: %s\n%s", e, traceback.format_exc())
        if not from_queue:
            app.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}\nDetails: {traceback.format_exc()}"))
        app.status_label.config(text="Upload failed")
    finally:
        if not from_queue:
            app.is_processing = False
            app.stop_status_animation()
    
    return success if from_queue else None

def continue_upload():
    global proceed
    proceed = True

def manage_private_files(app):
    # UI for managing private files
    manage_window = tk.Toplevel(app.root)
    manage_window.title("Manage Private Files")
    manage_window.resizable(True, True)
    manage_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
    manage_window.transient(app.root)

    search_frame = ttk.Frame(manage_window)
    search_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
    search_entry = ttk.Entry(search_frame)
    search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    from gui import add_context_menu, COLORS
    add_context_menu(search_entry)

    def filter_files():
        query = search_entry.get().lower()
        refresh_content(query)

    search_entry.bind("<KeyRelease>", lambda e: filter_files())

    files_frame = ttk.LabelFrame(manage_window, text="Private Files", padding=5)
    files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    files_canvas = tk.Canvas(files_frame, bg=COLORS["bg_light"])
    files_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
    files_inner_frame = ttk.Frame(files_canvas)
    files_canvas.configure(yscrollcommand=files_scrollbar.set)

    files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")

    check_vars = []

    def refresh_content(query=""):
        for widget in files_inner_frame.winfo_children():
            widget.destroy()
        check_vars.clear()

        private_items = [(filename, access_token, "File") for filename, access_token in app.uploaded_private_files]

        for name, access_token, item_type in private_items:
            if query in name.lower() or query in access_token.lower():
                var = tk.BooleanVar(value=False)
                check_vars.append((var, access_token, name))
                frame = ttk.Frame(files_inner_frame)
                frame.pack(anchor="w", padx=5, pady=2)
                chk = ttk.Checkbutton(frame, text=f"{name} ({item_type}) - ")
                chk.pack(side=tk.LEFT)
                addr_entry = ttk.Entry(frame, width=80)
                addr_entry.insert(0, access_token)
                addr_entry.config(state="readonly")
                addr_entry.pack(side=tk.LEFT)
                add_context_menu(addr_entry)

        files_inner_frame.update_idletasks()
        files_canvas.configure(scrollregion=files_canvas.bbox("all"))
        manage_window.after(30000, lambda: refresh_content(query))

    refresh_content()

    def remove_selected():
        selected_items = [(access_token, name) for var, access_token, name in check_vars if var.get()]
        if not selected_items:
            messagebox.showwarning("Selection Error", "Please select at least one item to remove.")
            return
        if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_items)} private items from the list? This won't delete the data from the network."):
            for access_token, name in selected_items:
                if (name, access_token) in app.uploaded_private_files:
                    app.uploaded_private_files.remove((name, access_token))
            app.save_persistent_data()
            refresh_content()

    buttons_frame = ttk.Frame(manage_window)
    buttons_frame.pack(fill=tk.X, pady=10, padx=10)

    ttk.Button(buttons_frame, text="Remove from List", command=remove_selected, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Close", command=manage_window.destroy, style="Accent.TButton").pack(side=tk.RIGHT, padx=5)

def display_private_files(app, parent_frame):
    """Display private files in the provided frame instead of opening a new window"""
    import tkinter as tk
    from tkinter import ttk, messagebox
    from gui import add_context_menu, CURRENT_COLORS
    
    # Create search frame with improved styling
    search_frame = ttk.Frame(parent_frame, style="TFrame", padding=(0, 5, 0, 15))
    search_label = ttk.Label(search_frame, text="Search:", font=("Inter", 11))
    search_label.pack(side=tk.LEFT, padx=(0, 10))
    
    search_entry = ttk.Entry(search_frame, width=40)
    search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    add_context_menu(search_entry)
    
    # Create buttons frame
    buttons_frame = ttk.Frame(parent_frame, style="TFrame", padding=(0, 10))
    
    # Create scrollable frames for files with better styling
    files_frame = ttk.LabelFrame(parent_frame, text="Private Files", padding=10, style="Card.TLabelframe")
    
    # Style the labelframe header
    style = ttk.Style()
    style.configure("Card.TLabelframe.Label", font=("Inter", 12, "bold"), foreground=CURRENT_COLORS["accent_primary"])
    
    files_canvas = tk.Canvas(files_frame, bg=CURRENT_COLORS["bg_secondary"], bd=0, highlightthickness=0)
    files_v_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
    files_inner_frame = ttk.Frame(files_canvas, style="TFrame", padding=5)
    files_canvas.configure(yscrollcommand=files_v_scrollbar.set)
    
    files_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    canvas_window_files = files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")
    
    # Update scrollregion when inner frame size changes
    def on_files_configure(event):
        files_canvas.configure(scrollregion=files_canvas.bbox("all"))
        # Make the inner frame width match the canvas width
        files_canvas.itemconfig(canvas_window_files, width=files_canvas.winfo_width())
    
    files_inner_frame.bind("<Configure>", on_files_configure)
    files_canvas.bind("<Configure>", lambda e: files_canvas.itemconfig(canvas_window_files, width=e.width))
    
    check_vars = []
    
    # --- Pack elements in correct order ---
    search_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(10, 0))
    buttons_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10, padx=10)
    files_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10, expand=True)

    def refresh_content(query=""):
        """Refresh the content of the files list based on search query"""
        for widget in files_inner_frame.winfo_children():
            widget.destroy()
        
        check_vars.clear()
        
        private_items = [(filename, access_token, "File") for filename, access_token in app.uploaded_private_files]
        
        # Display file count heading
        visible_items = [item for item in private_items if query in item[0].lower() or query in item[1].lower()]
        files_frame.configure(text=f"Private Files ({len(visible_items)})")
        
        # Display message when no files found
        if not visible_items:
            empty_msg = ttk.Label(files_inner_frame, 
                                text="No private files found", 
                                font=("Inter", 11, "italic"),
                                foreground=CURRENT_COLORS["text_secondary"])
            empty_msg.pack(pady=20, padx=20)
            return
        
        # Create cards for each file
        for name, access_token, item_type in visible_items:
            if query in name.lower() or query in access_token.lower():
                var = tk.BooleanVar(value=False)
                check_vars.append((var, access_token, name))
                
                # Create a card style frame for each file
                card = ttk.Frame(files_inner_frame, style="FileCard.TFrame", padding=10)
                card.pack(fill=tk.X, pady=5, padx=5)
                
                # Determine file type icon
                icon = "🔒"  # Default for private
                if name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                    icon = "🔒 🖼️"
                elif name.lower().endswith(('.mp4', '.mov', '.avi')):
                    icon = "🔒 🎬"
                elif name.lower().endswith(('.mp3', '.wav', '.ogg')):
                    icon = "🔒 🎵"
                elif name.lower().endswith(('.pdf')):
                    icon = "🔒 📕"
                elif name.lower().endswith(('.zip', '.tar', '.gz')):
                    icon = "🔒 🗜️"
                
                # Header row with checkbox and filename
                header = ttk.Frame(card, style="TFrame")
                header.pack(fill=tk.X, pady=(0, 5))
                
                # Checkbox and file info
                chk = ttk.Checkbutton(header, variable=var, style="TCheckbutton")
                chk.pack(side=tk.LEFT)
                
                filename_label = ttk.Label(header, 
                                        text=f"{icon} {name}", 
                                        font=("Inter", 11, "bold"),
                                        foreground=CURRENT_COLORS["accent_secondary"])
                filename_label.pack(side=tk.LEFT, padx=(5, 0))
                
                # Access token section
                token_frame = ttk.Frame(card, style="TFrame", padding=(20, 5))
                token_frame.pack(fill=tk.X)
                
                token_label = ttk.Label(token_frame, 
                                     text="Access Token:", 
                                     font=("Inter", 10),
                                     foreground=CURRENT_COLORS["text_secondary"])
                token_label.pack(side=tk.LEFT)
                
                # Token with copy button
                token_container = ttk.Frame(token_frame, style="TFrame")
                token_container.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
                
                # Show shortened token for better UI
                shortened_token = f"{access_token[:15]}...{access_token[-8:]}"
                token_display = ttk.Label(token_container, 
                                       text=shortened_token,
                                       font=("Inter Mono", 10),
                                       foreground=CURRENT_COLORS["text_secondary"])
                token_display.pack(side=tk.LEFT)
                
                # Add copy button
                def copy_token(token=access_token):
                    app.root.clipboard_clear()
                    app.root.clipboard_append(token)
                    # Show temporary confirmation
                    token_display.config(text="✓ Copied!", foreground=CURRENT_COLORS["success"])
                    token_display.after(1500, lambda: token_display.config(
                        text=shortened_token, 
                        foreground=CURRENT_COLORS["text_secondary"]
                    ))
                
                copy_btn = ttk.Button(token_container, 
                                    text="Copy", 
                                    style="Small.TButton",
                                    command=lambda token=access_token: copy_token(token),
                                    width=5)
                copy_btn.pack(side=tk.RIGHT, padx=(5, 0))
                
                # Add view button
                view_btn = ttk.Button(token_container, 
                                    text="View", 
                                    style="Small.TButton",
                                    command=lambda name=name, token=access_token: view_private_file(name, token),
                                    width=5)
                view_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Configure card styles
        style = ttk.Style()
        style.configure("FileCard.TFrame", background=CURRENT_COLORS["bg_light"])
        style.configure("Small.TButton", font=("Inter", 9))
        
        files_inner_frame.update_idletasks()
        files_canvas.configure(scrollregion=files_canvas.bbox("all"))
    
    def view_private_file(name, token):
        """View a private file"""
        async def fetch_and_view():
            try:
                app.status_label.config(text=f"Loading private file {name}...")
                # Convert token (hex string) to DataMapChunk and use data_get method
                data_map_chunk = DataMapChunk.from_hex(token)
                data = await app.client.data_get(data_map_chunk)
                app.status_label.config(text="Ready")
                import view
                view.show_data_window(app, data, True, None, True, token)
            except Exception as e:
                import traceback
                logger.error("Error viewing private file: %s\n%s", e, traceback.format_exc())
                app.status_label.config(text="Ready")
                messagebox.showerror("Error", f"Failed to view private file: {e}")
        
        asyncio.run_coroutine_threadsafe(fetch_and_view(), app.loop)
    
    def filter_files():
        """Filter files based on search query"""
        query = search_entry.get().lower()
        refresh_content(query)
    
    search_entry.bind("<KeyRelease>", lambda e: filter_files())
    
    def remove_selected():
        """Remove selected items from the list"""
        selected_items = [(access_token, name) for var, access_token, name in check_vars if var.get()]
        if not selected_items:
            messagebox.showwarning("Selection Error", "Please select at least one item to remove.")
            return
        
        # Create styled confirmation dialog
        dialog, main_frame = gui.create_centered_dialog(
            parent=app.root,
            title="Confirm Removal",
            min_width=400,
            min_height=200,
            padding=20
        )
        
        # Warning icon
        ttk.Label(main_frame, text="⚠️", font=("Inter", 24)).pack(pady=(0, 10))
        
        # Confirmation message
        msg = f"Remove {len(selected_items)} private file(s) from the list?\n\nThis won't delete the data from the network."
        ttk.Label(main_frame, text=msg, font=("Inter", 11), justify="center").pack(pady=10)
        
        # Buttons
        button_frame = ttk.Frame(main_frame, style="TFrame", padding=(0, 20, 0, 0))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        ttk.Button(
            button_frame, 
            text="Cancel", 
            style="Secondary.TButton",
            command=dialog.destroy
        ).pack(side=tk.LEFT)
        
        def confirm_remove():
            for access_token, name in selected_items:
                if (name, access_token) in app.uploaded_private_files:
                    app.uploaded_private_files.remove((name, access_token))
            
            app.save_persistent_data()
            refresh_content()
            dialog.destroy()
        
        ttk.Button(
            button_frame, 
            text="Remove", 
            style="Accent.TButton",
            command=confirm_remove
        ).pack(side=tk.RIGHT)
    
    # Add styled buttons to button frame
    remove_btn = ttk.Button(
        buttons_frame, 
        text="Remove Selected", 
        command=remove_selected, 
        style="Secondary.TButton"
    )
    remove_btn.pack(side=tk.LEFT, padx=5)
    
    # Initialize content
    refresh_content()