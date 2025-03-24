import asyncio
import os
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from autonomi_client import PaymentOption

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
    manage_window.title("Store Private Data Files - Mission Ctrl")
    manage_window.geometry("600x700")
    manage_window.resizable(True, True)
    manage_window.configure(bg="#FFFFFF")

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
    
    # Create a search frame
    search_frame = ttk.Frame(parent_frame)
    search_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
    search_entry = ttk.Entry(search_frame)
    search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    add_context_menu(search_entry)
    
    # Create a frame for files
    files_frame = ttk.LabelFrame(parent_frame, text="Private Files", padding=5)
    files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)
    
    # Create a canvas with scrollbar for the files
    files_canvas = tk.Canvas(files_frame, bg=CURRENT_COLORS["bg_secondary"])
    files_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
    files_inner_frame = ttk.Frame(files_canvas)
    files_canvas.configure(yscrollcommand=files_scrollbar.set)
    
    files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")
    
    check_vars = []
    
    def refresh_content(query=""):
        """Refresh the content of the files list based on search query"""
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
                chk = ttk.Checkbutton(frame, text=f"{name} ({item_type}) - ", variable=var)
                chk.pack(side=tk.LEFT)
                addr_entry = ttk.Entry(frame, width=50)
                addr_entry.insert(0, access_token)
                addr_entry.config(state="readonly")
                addr_entry.pack(side=tk.LEFT)
                add_context_menu(addr_entry)
        
        files_inner_frame.update_idletasks()
        files_canvas.configure(scrollregion=files_canvas.bbox("all"))
    
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
        
        if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_items)} private items from the list? This won't delete the data from the network."):
            for access_token, name in selected_items:
                if (name, access_token) in app.uploaded_private_files:
                    app.uploaded_private_files.remove((name, access_token))
            
            app.save_persistent_data()
            refresh_content()
    
    # Add buttons for actions
    buttons_frame = ttk.Frame(parent_frame)
    buttons_frame.pack(fill=tk.X, pady=10, padx=10)
    
    ttk.Button(buttons_frame, text="Remove from List", command=remove_selected, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    
    # Initialize content
    refresh_content()