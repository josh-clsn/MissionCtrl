import os
import json
import asyncio
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from autonomi_client import PublicArchive, Metadata

logger = logging.getLogger("MissionCtrl")

async def upload_public(app, file_path, from_queue=False):
    """
    Upload a file publicly to the network
    
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
        with open(file_path, "rb") as f:
            file_data = f.read()
        from autonomi_client import PaymentOption
        payment_option = PaymentOption.wallet(app.wallet)
        ant_balance = int(await app.wallet.balance())
        if ant_balance <= 0:
            app.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload. Add ANT to your wallet in the Wallet tab."))
            app.is_processing = False
            app.stop_status_animation()
            return False if from_queue else None
        if app.perform_cost_calc_var.get() and not from_queue:
            logger.info("Calculating estimated cost for file: %s", file_path)
            app._current_operation = 'cost_calc'
            try:
                estimated_cost = await asyncio.wait_for(
                    app.client.data_cost(file_data),
                    timeout=1000
                )
                logger.info("Estimated cost: %s ANT", estimated_cost)
            except asyncio.TimeoutError:
                logger.error("Cost calculation timed out after 1000 seconds")
                app.root.after(0, lambda: messagebox.showerror("Error", "Cost calculation timed out after 1000 seconds. Check your network connection."))
                app.is_processing = False
                app.stop_status_animation()
                return False if from_queue else None
            logger.info("Showing cost confirmation dialog")
            app._current_operation = None 
            app.status_label.config(text=f"Quote retrieved: {estimated_cost} ANT for {os.path.basename(file_path)}")
            app.stop_status_animation() 
            proceed = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: messagebox.askyesno("Confirm Upload", f"Estimated cost: {estimated_cost} ANT. Proceed?")
            )
            if not proceed:
                logger.info("Upload cancelled by user")
                app.is_processing = False
                app.status_label.config(text="Upload cancelled")
                return False if from_queue else None
        logger.info("Upload started for file: %s", file_path)
        app._current_operation = 'upload'
        app.status_label.config(text=f"Uploading file: {os.path.basename(file_path)}")
        app.start_status_animation()
        chunk_price, chunk_addr = await asyncio.wait_for(
            app.client.data_put_public(file_data, payment_option),
            timeout=15000
        )
        logger.info("Chunk uploaded to address: %s for %s ANT", chunk_addr, chunk_price)
        file_name = os.path.basename(file_path)
        app.uploaded_files.append((file_name, chunk_addr))
        if not from_queue:
            app.root.after(0, lambda: app._show_upload_success(chunk_addr, file_name, False))
        success = True
    except asyncio.TimeoutError:
        logger.error("Upload timed out after 15000 seconds")
        if not from_queue:
            app.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 15000 seconds. Check your network connection."))
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

async def upload_public_directory(app, dir_path):
    # Public directory upload with stats and confirmation
    app.status_label.config(text=f"Gathering stats for {os.path.basename(dir_path)}...")
    app.is_processing = True
    app.start_status_animation()
    try:
        from autonomi_client import PaymentOption
        payment_option = PaymentOption.wallet(app.wallet)
        ant_balance = int(await app.wallet.balance())
        if ant_balance <= 0:
            app.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload. Add ANT to your wallet in the Wallet tab."))
            app.is_processing = False
            app.stop_status_animation()
            return
        def get_dir_stats(path):
            total_size = 0
            file_count = 0
            for root, dirs, files in os.walk(path):
                file_count += len(files)
                for file in files:
                    file_path = os.path.join(root, file)
                    total_size += os.path.getsize(file_path)
            return total_size, file_count
        
        def format_size(size_in_bytes):
            KB = 1024
            MB = KB * 1024
            GB = MB * 1024

            if size_in_bytes >= GB:
                return f"{size_in_bytes / GB:.2f} GB", size_in_bytes
            elif size_in_bytes >= MB:
                return f"{size_in_bytes / MB:.2f} MB", size_in_bytes
            else:
                return f"{size_in_bytes} bytes", size_in_bytes

        total_size, file_count = get_dir_stats(dir_path)
        logger.info("Directory stats - Total size: %s bytes, File count: %s", total_size, file_count)

        formatted_size, exact_bytes = format_size(total_size)

        app.stop_status_animation()
        app.status_label.config(text="Waiting for confirmation...")

        confirm_message = (
            f"Directory: {os.path.basename(dir_path)}\n"
            f"Directory stats - Total size: {formatted_size} ({exact_bytes} bytes), File count: {file_count}\n"
            f"Proceed with upload?"
        )
        proceed = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: messagebox.askyesno("Confirm Directory Upload", confirm_message)
        )
        if not proceed:
            logger.info("Directory upload cancelled by user")
            app.is_processing = False
            app.status_label.config(text="Upload cancelled")
            return

        app.status_label.config(
            text=(
                f"Getting quote... for {os.path.basename(dir_path)}"
                if app.perform_cost_calc_var.get()
                else f"Uploading directory: {os.path.basename(dir_path)}"
            )
        )
        app.start_status_animation()

        logger.info("User confirmed directory upload")
        if app.perform_cost_calc_var.get():
            logger.info("Calculating estimated cost for directory: %s", dir_path)
            app._current_operation = 'cost_calc' 
            try:
                estimated_cost = await asyncio.wait_for(
                    app.client.file_cost(dir_path),
                    timeout=15000
                )
                logger.info("Estimated cost: %s ANT", estimated_cost)
            except asyncio.TimeoutError:
                logger.error("Cost calculation timed out after 15000 seconds")
                app.root.after(0, lambda: messagebox.showerror("Error", "Cost calculation timed out after 15000 seconds. Try a smaller directory or check your network."))
                app.is_processing = False
                app.stop_status_animation()
                return
            logger.info("Showing cost confirmation dialog")
            app._current_operation = None 
            app.status_label.config(text=f"Quote retrieved: {estimated_cost} ANT for {os.path.basename(dir_path)}")
            app.stop_status_animation() 
            proceed = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: messagebox.askyesno("Confirm Upload", f"Estimated cost for directory: {estimated_cost} ANT. Proceed?")
            )
            if not proceed:
                logger.info("Upload cancelled by user")
                app.is_processing = False
                app.status_label.config(text="Upload cancelled")
                return
        logger.info("Upload started for directory: %s", dir_path)
        app._current_operation = 'upload' 
        app.status_label.config(text=f"Uploading directory: {os.path.basename(dir_path)}")
        app.start_status_animation() 
        cost, archive_addr = await asyncio.wait_for(
            app.client.dir_and_archive_upload_public(dir_path, app.wallet),
            timeout=15000
        )
        logger.info("Directory uploaded to address: %s for %s ANT", archive_addr, cost)
        dir_name = os.path.basename(dir_path)
        app.local_archives.append((archive_addr, dir_name, False))
        app.root.after(0, lambda: app._show_upload_success(archive_addr, dir_name, False))
    except asyncio.TimeoutError:
        logger.error("Upload timed out after 15000 seconds")
        app.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 15000 seconds. Check your network connection."))
        app.status_label.config(text="Upload timeout")
    except Exception as e:
        import traceback
        logger.error("Upload error: %s\n%s", e, traceback.format_exc())
        app.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}\nDetails: {traceback.format_exc()}"))
        app.status_label.config(text="Upload failed")
    finally:
        app.is_processing = False
        app.stop_status_animation()

def manage_public_files(app):
    # UI for managing public files and archives
    manage_window = tk.Toplevel(app.root)
    manage_window.title("Manage Public Files - Mission Ctrl")
    manage_window.geometry("600x730")
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

    files_frame = ttk.LabelFrame(manage_window, text="Uploaded Files", padding=5)
    files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    files_canvas = tk.Canvas(files_frame, bg=COLORS["bg_light"])
    files_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
    files_inner_frame = ttk.Frame(files_canvas)
    files_canvas.configure(yscrollcommand=files_scrollbar.set)

    files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")

    check_vars = []

    archives_frame = ttk.LabelFrame(manage_window, text="Archives", padding=5)
    archives_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    archives_canvas = tk.Canvas(archives_frame, bg=COLORS["bg_light"])
    archives_scrollbar = ttk.Scrollbar(archives_frame, orient="vertical", command=archives_canvas.yview)
    archives_inner_frame = ttk.Frame(archives_canvas)
    archives_canvas.configure(yscrollcommand=archives_scrollbar.set)

    archives_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    archives_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    archives_canvas.create_window((0, 0), window=archives_inner_frame, anchor="nw")

    archive_vars = []

    def refresh_content(query=""):
        for widget in files_inner_frame.winfo_children():
            widget.destroy()
        for widget in archives_inner_frame.winfo_children():
            widget.destroy()
            
        # Configure grid columns for expansion (column 1 for address)
        files_inner_frame.columnconfigure(1, weight=1)
        archives_inner_frame.columnconfigure(1, weight=1)

        check_vars.clear()
        archive_vars.clear()
        row_index = 0
        for filename, chunk_addr in app.uploaded_files:
            if query in filename.lower() or query in chunk_addr.lower():
                var = tk.BooleanVar(master=app.root, value=False)
                check_vars.append((var, filename, chunk_addr))
                # Use grid layout
                chk = ttk.Checkbutton(files_inner_frame, text=f"{filename} - ", variable=var)
                chk.grid(row=row_index, column=0, sticky="w", padx=(5, 0), pady=2)
                
                addr_entry = ttk.Entry(files_inner_frame, width=80) # Set width to 80
                addr_entry.insert(0, chunk_addr)
                addr_entry.config(state="readonly")
                addr_entry.grid(row=row_index, column=1, sticky="ew", padx=(0, 5), pady=2)
                add_context_menu(addr_entry)
                row_index += 1

        row_index = 0 # Reset row index for archives
        public_archives = [(addr, name) for addr, name, is_private in app.local_archives if not is_private]
        for addr, nickname in public_archives:
            if query in nickname.lower() or query in addr.lower():
                var = tk.BooleanVar(master=app.root, value=False)
                archive_vars.append((var, addr, nickname))
                # Use grid layout
                chk = ttk.Checkbutton(archives_inner_frame, text=f"{nickname} - ", variable=var)
                chk.grid(row=row_index, column=0, sticky="w", padx=(5, 0), pady=2)
                
                addr_entry = ttk.Entry(archives_inner_frame, width=80) # Set width to 80
                addr_entry.insert(0, addr)
                addr_entry.config(state="readonly")
                addr_entry.grid(row=row_index, column=1, sticky="ew", padx=(0, 5), pady=2)
                add_context_menu(addr_entry)
                row_index += 1

        files_inner_frame.update_idletasks()
        files_canvas.configure(scrollregion=files_canvas.bbox("all"))
        archives_inner_frame.update_idletasks()
        archives_canvas.configure(scrollregion=archives_canvas.bbox("all"))

    refresh_content()

    def add_to_archive():
        selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
        if not selected:
            messagebox.showwarning("Selection Error", "Please select at least one file to archive.")
            return

        archive_window = tk.Toplevel(manage_window)
        archive_window.title("Add to Archive - Mission Ctrl")
        archive_window.geometry("400x250")

        ttk.Label(archive_window, text="Nickname for New Archive:").pack(pady=5)
        nickname_entry = ttk.Entry(archive_window)
        nickname_entry.pack(pady=5)
        nickname_entry.insert(0, "My Archive")

        public_archives = [(addr, name) for addr, name, is_private in app.local_archives if not is_private]
        ttk.Label(archive_window, text="Select Archive:").pack(pady=5)
        archive_combo = ttk.Combobox(archive_window, values=[f"{n} - {a}" for a, n in public_archives])
        archive_combo.pack(pady=5)
        archive_combo.set("Create New Archive")

        remove_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(archive_window, text="Remove selected files from Uploaded Files list", variable=remove_var).pack(pady=5)

        async def do_archive():
            nickname = nickname_entry.get().strip()
            if not nickname:
                app.root.after(0, lambda: messagebox.showwarning("Input Error", "Please enter a nickname for the archive."))
                return

            archive_choice = archive_combo.get()
            should_remove = remove_var.get()
            
            archive_window.destroy()
            app.root.after(0, lambda: messagebox.showinfo("Archiving Started", "The archiving process has begun. It can take a while..."))

            selected_files = [(fn, addr, Metadata(size=0)) for fn, addr in selected]
            app.is_processing = True
            app._current_operation = 'archive'
            app.start_status_animation()
            try:
                logger.info("Starting archive creation with nickname: %s", nickname)
                if archive_choice == "Create New Archive":
                    archive = PublicArchive()
                    for filename, chunk_addr, metadata in selected_files:
                        archive.add_file(filename, chunk_addr, metadata)
                    logger.info("Calling archive_put_public for new archive")
                    cost, archive_addr = await asyncio.wait_for(
                        app.client.archive_put_public(archive, app.wallet),
                        timeout=15000
                    )
                    app.local_archives.append((archive_addr, nickname, False))
                    logger.info("New archive created at %s", archive_addr)
                else:
                    archive_addr = archive_choice.split(" - ")[1]
                    logger.info("Fetching existing archive at %s", archive_addr)
                    archive = await app.client.archive_get_public(archive_addr)
                    for filename, chunk_addr, metadata in selected_files:
                        archive.add_file(filename, chunk_addr, metadata)
                    logger.info("Calling archive_put_public for updated archive")
                    cost, new_archive_addr = await asyncio.wait_for(
                        app.client.archive_put_public(archive, app.wallet),
                        timeout=15000
                    )
                    for i, (addr, _, is_private) in enumerate(app.local_archives):
                        if addr == archive_addr and not is_private:
                            app.local_archives[i] = (new_archive_addr, nickname, False)
                            break
                    archive_addr = new_archive_addr
                    logger.info("Updated archive at %s", archive_addr)

                if should_remove:
                    for filename, chunk_addr in selected:
                        app.uploaded_files.remove((filename, chunk_addr))

                app.save_persistent_data()
                with open(app.data_file, 'r') as f:
                    saved_data = json.load(f)
                saved_archives = [(item["addr"], item["nickname"], item["is_private"]) 
                                for item in saved_data.get("local_archives", [])]
                if (archive_addr, nickname, False) not in saved_archives:
                    logger.error("Failed to save archive %s with nickname %s to JSON", archive_addr, nickname)
                    raise Exception("Archive not saved correctly to JSON")

                app.root.after(0, lambda: refresh_content())
                app.root.after(0, lambda: messagebox.showinfo("Success", f"Archive '{nickname}' created successfully at {archive_addr}"))
            except asyncio.TimeoutError:
                logger.error("Archive operation timed out after 1200 seconds")
                app.root.after(0, lambda: messagebox.showerror("Error", "Archive operation timed out. Check your network connection."))
            except Exception as error:
                import traceback
                logger.error("Archiving error: %s\n%s", error, traceback.format_exc())
                error_msg = str(error)
                app.root.after(0, lambda: messagebox.showerror("Error", f"Archiving failed: {error_msg}\nDetails: {traceback.format_exc()}"))
            finally:
                app.is_processing = False
                app.stop_status_animation()

        ttk.Button(archive_window, text="Archive", command=lambda: asyncio.run_coroutine_threadsafe(do_archive(), app.loop)).pack(pady=10)

    def append_to_archive():
        selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
        public_archives = [(addr, name) for addr, name, is_private in app.local_archives if not is_private]
        if not selected:
            messagebox.showwarning("Selection Error", "Please select at least one file to append.")
            return
        if not public_archives:
            messagebox.showwarning("No Archives", "No existing archives to append to. Use 'Add to Archive' to create one.")
            return

        append_window = tk.Toplevel(manage_window)
        append_window.title("Append to Archive - Mission Ctrl")
        append_window.geometry("400x200")

        ttk.Label(append_window, text="Select Archive to Append To:").pack(pady=5)
        archive_combo = ttk.Combobox(append_window, values=[f"{n} - {a}" for a, n in public_archives])
        archive_combo.pack(pady=5)
        if public_archives:
            archive_combo.set(f"{public_archives[0][1]} - {public_archives[0][0]}")

        remove_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(append_window, text="Remove selected files from Uploaded Files list", variable=remove_var).pack(pady=5)

        async def do_append():
            archive_choice = archive_combo.get()
            should_remove = remove_var.get()
            
            if not archive_choice:
                app.root.after(0, lambda: messagebox.showwarning("Input Error", "Please select an archive to append to."))
                return

            append_window.destroy()
            app.root.after(0, lambda: messagebox.showinfo("Appending Started", "The appending process has begun. Please wait..."))

            archive_addr = archive_choice.split(" - ")[1]
            selected_files = [(fn, addr, Metadata(size=0)) for fn, addr in selected]
            app.is_processing = True
            app._current_operation = 'archive'
            app.start_status_animation()
            try:
                logger.info("Appending to archive at %s", archive_addr)
                archive = await app.client.archive_get_public(archive_addr)
                original_nickname = next((n for a, n, p in app.local_archives if a == archive_addr and not p), None)
                for filename, chunk_addr, metadata in selected_files:
                    archive.add_file(filename, chunk_addr, metadata)
                logger.info("Calling archive_put_public for updated archive")
                cost, new_archive_addr = await asyncio.wait_for(
                    app.client.archive_put_public(archive, app.wallet),
                    timeout=15000
                )
                
                for i, (addr, nickname, is_private) in enumerate(app.local_archives):
                    if addr == archive_addr and not is_private:
                        app.local_archives[i] = (new_archive_addr, original_nickname, False)
                        break

                if should_remove:
                    for filename, chunk_addr in selected:
                        app.uploaded_files.remove((filename, chunk_addr))

                app.save_persistent_data()
                with open(app.data_file, 'r') as f:
                    saved_data = json.load(f)
                saved_archives = [(item["addr"], item["nickname"], item["is_private"]) 
                                for item in saved_data.get("local_archives", [])]
                if (new_archive_addr, original_nickname, False) not in saved_archives:
                    logger.error("Failed to save updated archive %s with nickname %s to JSON", new_archive_addr, original_nickname)
                    raise Exception("Updated archive not saved correctly to JSON")

                logger.info("Archive updated at %s", new_archive_addr)
                app.root.after(0, lambda: refresh_content())
                app.root.after(0, lambda: messagebox.showinfo("Success", f"Files appended to archive at {new_archive_addr}"))
            except asyncio.TimeoutError:
                logger.error("Append operation timed out after 1200 seconds")
                app.root.after(0, lambda: messagebox.showerror("Error", "Append operation timed out. Check your network connection."))
            except Exception as error:
                import traceback
                logger.error("Appending error: %s\n%s", error, traceback.format_exc())
                error_msg = str(error)
                app.root.after(0, lambda: messagebox.showerror("Error", f"Appending failed: {error_msg}\nDetails: {traceback.format_exc()}"))
            finally:
                app.is_processing = False
                app.stop_status_animation()

        ttk.Button(append_window, text="Append", command=lambda: asyncio.run_coroutine_threadsafe(do_append(), app.loop)).pack(pady=10)

    def remove_selected():
        selected_files = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
        selected_archives = [(addr, nickname) for var, addr, nickname in archive_vars if var.get()]
        if not selected_files and not selected_archives:
            messagebox.showwarning("Selection Error", "Please select at least one item to remove.")
            return
        if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_files)} files and {len(selected_archives)} archives from the list? This won't delete the data from the network."):
            for filename, chunk_addr in selected_files:
                app.uploaded_files.remove((filename, chunk_addr))
            for addr, nickname in selected_archives:
                for i, (a, n, is_private) in enumerate(app.local_archives):
                    if a == addr and n == nickname and not is_private:
                        app.local_archives.pop(i)
                        break
            app.save_persistent_data()
            refresh_content()

    buttons_frame = ttk.Frame(manage_window)
    buttons_frame.pack(fill=tk.X, pady=10, padx=10)

    ttk.Button(buttons_frame, text="Add to Archive", command=add_to_archive, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Append to Archive", command=append_to_archive, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Remove from List", command=remove_selected, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Close", command=manage_window.destroy, style="Accent.TButton").pack(side=tk.RIGHT, padx=5)

def display_public_files(app, parent_frame):
    """Display public files in the provided frame instead of opening a new window"""
    import tkinter as tk
    from tkinter import ttk, messagebox
    from gui import add_context_menu, CURRENT_COLORS
    
    # --- Layout Order --- 
    # 1. Search bar at the top
    # 2. Buttons at the bottom
    # 3. Lists fill the middle
    
    # Create search frame (Pack later)
    search_frame = ttk.Frame(parent_frame)
    ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
    search_entry = ttk.Entry(search_frame)
    search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    add_context_menu(search_entry)
    
    # Create buttons frame (Pack later)
    buttons_frame = ttk.Frame(parent_frame)
    
    # Create scrollable frames for files and archives (Pack later)
    files_frame = ttk.LabelFrame(parent_frame, text="Uploaded Files", padding=5)
    files_canvas = tk.Canvas(files_frame, bg=CURRENT_COLORS["bg_secondary"], bd=0, highlightthickness=0)
    files_v_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
    files_inner_frame = ttk.Frame(files_canvas)
    files_canvas.configure(yscrollcommand=files_v_scrollbar.set)
    
    files_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    canvas_window_files = files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")
    
    # Update scrollregion when inner frame size changes
    def on_files_configure(event):
        files_canvas.configure(scrollregion=files_canvas.bbox("all"))
        # Adjust canvas window width to prevent horizontal scroll unless needed
        # files_canvas.itemconfig(canvas_window_files, width=event.width)
    files_inner_frame.bind("<Configure>", on_files_configure)
    
    check_vars = []
    
    archives_frame = ttk.LabelFrame(parent_frame, text="Archives", padding=5)
    archives_canvas = tk.Canvas(archives_frame, bg=CURRENT_COLORS["bg_secondary"], bd=0, highlightthickness=0)
    archives_v_scrollbar = ttk.Scrollbar(archives_frame, orient="vertical", command=archives_canvas.yview)
    archives_inner_frame = ttk.Frame(archives_canvas)
    archives_canvas.configure(yscrollcommand=archives_v_scrollbar.set)
    
    archives_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    archives_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    canvas_window_archives = archives_canvas.create_window((0, 0), window=archives_inner_frame, anchor="nw")

    # Update scrollregion when inner frame size changes
    def on_archives_configure(event):
        archives_canvas.configure(scrollregion=archives_canvas.bbox("all"))
        # Adjust canvas window width to prevent horizontal scroll unless needed
        # archives_canvas.itemconfig(canvas_window_archives, width=event.width)
    archives_inner_frame.bind("<Configure>", on_archives_configure)

    archive_vars = []
    
    # --- Pack elements in correct order --- 
    search_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    buttons_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10, padx=10)
    # Pack lists last, filling the middle space from the top down
    files_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=5, expand=True)
    archives_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=5, expand=True)

    def refresh_content(query=""):
        for widget in files_inner_frame.winfo_children():
            widget.destroy()
        for widget in archives_inner_frame.winfo_children():
            widget.destroy()
            
        # Configure grid columns for expansion (column 1 for address)
        files_inner_frame.columnconfigure(1, weight=1)
        archives_inner_frame.columnconfigure(1, weight=1)

        check_vars.clear()
        archive_vars.clear()
        row_index = 0
        for filename, chunk_addr in app.uploaded_files:
            if query in filename.lower() or query in chunk_addr.lower():
                var = tk.BooleanVar(master=app.root, value=False)
                check_vars.append((var, filename, chunk_addr))
                # Use grid layout
                chk = ttk.Checkbutton(files_inner_frame, text=f"{filename} - ", variable=var)
                chk.grid(row=row_index, column=0, sticky="w", padx=(5, 0), pady=2)
                
                addr_entry = ttk.Entry(files_inner_frame, width=80) # Set width to 80
                addr_entry.insert(0, chunk_addr)
                addr_entry.config(state="readonly")
                addr_entry.grid(row=row_index, column=1, sticky="ew", padx=(0, 5), pady=2)
                add_context_menu(addr_entry)
                row_index += 1

        row_index = 0 # Reset row index for archives
        public_archives = [(addr, name) for addr, name, is_private in app.local_archives if not is_private]
        for addr, nickname in public_archives:
            if query in nickname.lower() or query in addr.lower():
                var = tk.BooleanVar(master=app.root, value=False)
                archive_vars.append((var, addr, nickname))
                # Use grid layout
                chk = ttk.Checkbutton(archives_inner_frame, text=f"{nickname} - ", variable=var)
                chk.grid(row=row_index, column=0, sticky="w", padx=(5, 0), pady=2)
                
                addr_entry = ttk.Entry(archives_inner_frame, width=80) # Set width to 80
                addr_entry.insert(0, addr)
                addr_entry.config(state="readonly")
                addr_entry.grid(row=row_index, column=1, sticky="ew", padx=(0, 5), pady=2)
                add_context_menu(addr_entry)
                row_index += 1

        # No need to update scrollregion manually here, the bind does it
        # files_inner_frame.update_idletasks()
        # files_canvas.configure(scrollregion=files_canvas.bbox("all"))
        # archives_inner_frame.update_idletasks()
        # archives_canvas.configure(scrollregion=archives_canvas.bbox("all"))

    def filter_files():
        query = search_entry.get().lower()
        refresh_content(query)

    search_entry.bind("<KeyRelease>", lambda e: filter_files())
    
    def add_to_archive():
        selected = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
        if not selected:
            messagebox.showwarning("Selection Error", "Please select at least one file to archive.")
            return

        archive_window = tk.Toplevel(app.root)
        archive_window.title("Add to Archive - Mission Ctrl")
        archive_window.geometry("400x250")
        archive_window.transient(app.root)
        archive_window.grab_set()

        ttk.Label(archive_window, text="Nickname for New Archive:").pack(pady=5)
        nickname_entry = ttk.Entry(archive_window)
        nickname_entry.pack(pady=5)
        nickname_entry.insert(0, "My Archive")

        public_archives = [(addr, name) for addr, name, is_private in app.local_archives if not is_private]
        ttk.Label(archive_window, text="Select Archive:").pack(pady=5)
        archive_combo = ttk.Combobox(archive_window, values=[f"{n} - {a}" for a, n in public_archives])
        archive_combo.pack(pady=5)
        archive_combo.set("Create New Archive")

        remove_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(archive_window, text="Remove selected files from Uploaded Files list", variable=remove_var).pack(pady=5)

        ttk.Button(archive_window, text="Archive", command=lambda: asyncio.run_coroutine_threadsafe(
            do_archive(nickname_entry.get().strip(), archive_combo.get(), remove_var.get(), selected), app.loop)).pack(pady=10)
    
    async def do_archive(nickname, archive_choice, should_remove, selected):
        if not nickname:
            app.root.after(0, lambda: messagebox.showwarning("Input Error", "Please enter a nickname for the archive."))
            return

        app.root.after(0, lambda: messagebox.showinfo("Archiving Started", "The archiving process has begun. It can take a while..."))

        selected_files = [(fn, addr, Metadata(size=0)) for fn, addr in selected]
        app.is_processing = True
        app._current_operation = 'archive'
        app.start_status_animation()
        try:
            logger.info("Starting archive creation with nickname: %s", nickname)
            if archive_choice == "Create New Archive":
                archive = PublicArchive()
                for filename, chunk_addr, metadata in selected_files:
                    archive.add_file(filename, chunk_addr, metadata)
                logger.info("Calling archive_put_public for new archive")
                cost, archive_addr = await asyncio.wait_for(
                    app.client.archive_put_public(archive, app.wallet),
                    timeout=15000
                )
                app.local_archives.append((archive_addr, nickname, False))
                logger.info("New archive created at %s", archive_addr)
            else:
                archive_addr = archive_choice.split(" - ")[1]
                logger.info("Fetching existing archive at %s", archive_addr)
                archive = await app.client.archive_get_public(archive_addr)
                for filename, chunk_addr, metadata in selected_files:
                    archive.add_file(filename, chunk_addr, metadata)
                logger.info("Calling archive_put_public for updated archive")
                cost, new_archive_addr = await asyncio.wait_for(
                    app.client.archive_put_public(archive, app.wallet),
                    timeout=15000
                )
                for i, (addr, n, is_private) in enumerate(app.local_archives):
                    if addr == archive_addr and not is_private:
                        app.local_archives[i] = (new_archive_addr, nickname, False)
                        break
                archive_addr = new_archive_addr
                logger.info("Updated archive at %s", archive_addr)

            if should_remove:
                for filename, chunk_addr in selected:
                    app.uploaded_files.remove((filename, chunk_addr))

            app.save_persistent_data()
            app.root.after(0, lambda: refresh_content())
            app.root.after(0, lambda: messagebox.showinfo("Success", f"Archive '{nickname}' created successfully at {archive_addr}"))
        except Exception as e:
            import traceback
            logger.error("Archive error: %s\n%s", e, traceback.format_exc())
            app.root.after(0, lambda: messagebox.showerror("Error", f"Archive operation failed: {str(e)}"))
        finally:
            app.is_processing = False
            app.stop_status_animation()
    
    def remove_selected():
        selected_files = [(filename, chunk_addr) for var, filename, chunk_addr in check_vars if var.get()]
        selected_archives = [(addr, nickname) for var, addr, nickname in archive_vars if var.get()]
        if not selected_files and not selected_archives:
            messagebox.showwarning("Selection Error", "Please select at least one item to remove.")
            return
        if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_files)} files and {len(selected_archives)} archives from the list? This won't delete the data from the network."):
            for filename, chunk_addr in selected_files:
                app.uploaded_files.remove((filename, chunk_addr))
            for addr, nickname in selected_archives:
                for i, (a, n, is_private) in enumerate(app.local_archives):
                    if a == addr and n == nickname and not is_private:
                        app.local_archives.pop(i)
                        break
            app.save_persistent_data()
            refresh_content()
    
    # Add buttons to the buttons_frame
    ttk.Button(buttons_frame, text="Add to Archive", command=add_to_archive, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Remove from List", command=remove_selected, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    
    # Initialize content display
    refresh_content()