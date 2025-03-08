import os
import asyncio
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from autonomi_client import Metadata

logger = logging.getLogger("MissionCtrl")

async def upload_private(app, file_path, from_queue=False):
    app.status_label.config(text=f"Getting upload cost quote, please wait... for {os.path.basename(file_path)}" if app.perform_cost_calc_var.get() and not from_queue else f"Uploading file: {os.path.basename(file_path)}")
    app.is_processing = True
    app.start_status_animation()
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        from autonomi_client import PaymentOption
        payment_option = PaymentOption.wallet(app.wallet)
        ant_balance = int(await app.wallet.balance())
        if ant_balance > 0:
            if app.perform_cost_calc_var.get() and not from_queue:
                logger.info("Calculating estimated cost for file: %s", file_path)
                try:
                    estimated_cost = await asyncio.wait_for(
                        app.client.data_cost(file_data),
                        timeout=400
                    )
                    logger.info("Estimated cost: %s ANT", estimated_cost)
                except asyncio.TimeoutError:
                    logger.error("Cost calculation timed out after 400 seconds")
                    app.root.after(0, lambda: messagebox.showerror("Error", "Cost calculation timed out after 400 seconds. Check your network connection."))
                    app.is_processing = False
                    app.stop_status_animation()
                    return
                logger.info("Showing cost confirmation dialog")
                proceed = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: messagebox.askyesno("Confirm Upload", f"Estimated cost: {estimated_cost} ANT. Proceed?")
                )
                if not proceed:
                    logger.info("Upload cancelled by user")
                    app.is_processing = False
                    app.stop_status_animation()
                    app.root.after(0, lambda: app.status_label.config(text="Upload cancelled"))
                    return
            logger.info("Upload started for file: %s", file_path)
            app._current_operation = 'upload'
            app.status_label.config(text=f"Uploading file: {os.path.basename(file_path)}")
            result = await asyncio.wait_for(
                app.client.data_put(file_data, payment_option),
                timeout=15000
            )
            price, data_map_chunk = result
            access_token = data_map_chunk.to_hex()
            file_name = os.path.basename(file_path)
            app.uploaded_private_files.append((file_name, access_token))
            logger.info(f"Private data uploaded, price: {price}, access_token: {access_token}")
            app.root.after(0, lambda: app._show_upload_success(access_token, file_name, True))
        else:
            app.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload. Add ANT to your wallet in the Wallet tab."))
            app.is_processing = False
            app.stop_status_animation()
    except asyncio.TimeoutError:
        logger.error("Upload timed out after 15000 seconds")
        app.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 15000 seconds. Check your network connection."))
        app.status_label.config(text="Upload timeout")
    except Exception as e:
        logger.error("Upload error: %s", e)
        app.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}\nCheck your ANT balance in the Wallet tab."))
        app.status_label.config(text="Upload failed")
    finally:
        if not from_queue:
            app.is_processing = False
            app.stop_status_animation()

async def upload_private_directory(app, dir_path):
    app.status_label.config(text=f"Getting upload cost quote, please wait... for {os.path.basename(dir_path)}" if app.perform_cost_calc_var.get() else f"Uploading directory: {os.path.basename(dir_path)}")
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
        total_size, file_count = get_dir_stats(dir_path)
        logger.info("Directory stats - Total size: %s bytes, File count: %s", total_size, file_count)
        if app.perform_cost_calc_var.get():
            logger.info("Calculating estimated cost for directory: %s", dir_path)
            try:
                estimated_cost = await asyncio.wait_for(
                    app.client.file_cost(dir_path),
                    timeout=300
                )
                logger.info("Estimated cost: %s ANT", estimated_cost)
            except asyncio.TimeoutError:
                logger.error("Cost calculation timed out after 300 seconds")
                app.root.after(0, lambda: messagebox.showerror("Error", "Cost calculation timed out after 300 seconds. Try a smaller directory or check your network."))
                app.is_processing = False
                app.stop_status_animation()
                return
            logger.info("Showing cost confirmation dialog")
            proceed = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: messagebox.askyesno("Confirm Upload", f"Estimated cost: {estimated_cost} ANT. Proceed?")
            )
            if not proceed:
                logger.info("Upload cancelled by user")
                app.is_processing = False
                app.stop_status_animation()
                app.root.after(0, lambda: app.status_label.config(text="Upload cancelled"))
                return
        logger.info("Upload started for directory: %s", dir_path)
        app._current_operation = 'upload'
        app.status_label.config(text=f"Uploading directory: {os.path.basename(dir_path)}")
        archive = await asyncio.wait_for(
            app.client.dir_upload(dir_path, app.wallet),
            timeout=15000
        )
        data_maps = archive.data_maps()
        if data_maps:
            access_token = list(data_maps.values())[0].to_hex()
            dir_name = os.path.basename(dir_path)
            app.local_archives.append((access_token, dir_name, True))
            logger.info("Private directory uploaded, access_token: %s", access_token)
            app.root.after(0, lambda: app._show_upload_success(access_token, dir_name, True))
        else:
            raise Exception("No data maps returned from directory upload")
    except asyncio.TimeoutError:
        logger.error("Upload timed out after 15000 seconds")
        app.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 15000 seconds. Check your network connection."))
        app.status_label.config(text="Upload timeout")
    except Exception as e:
        logger.error("Upload error: %s", e)
        app.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}\nCheck your ANT balance in the Wallet tab."))
        app.status_label.config(text="Upload failed")
    finally:
        app.is_processing = False
        app.stop_status_animation()

def manage_private_files(app):
    manage_window = tk.Toplevel(app.root)
    manage_window.title("Store Private Data Files - Mission Ctrl")
    manage_window.geometry("600x700")
    manage_window.resizable(True, True)

    search_frame = ttk.Frame(manage_window)
    search_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
    search_entry = ttk.Entry(search_frame)
    search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    from gui import add_context_menu
    add_context_menu(search_entry)

    def filter_files():
        query = search_entry.get().lower()
        refresh_content(query)

    search_entry.bind("<KeyRelease>", lambda e: filter_files())

    # Frame for single private files
    files_frame = ttk.LabelFrame(manage_window, text="Private Files", padding=5)
    files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    files_canvas = tk.Canvas(files_frame)
    files_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=files_canvas.yview)
    files_inner_frame = ttk.Frame(files_canvas)
    files_canvas.configure(yscrollcommand=files_scrollbar.set)

    files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    files_canvas.create_window((0, 0), window=files_inner_frame, anchor="nw")

    # Frame for private archives
    archives_frame = ttk.LabelFrame(manage_window, text="Private Archives", padding=5)
    archives_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    archives_canvas = tk.Canvas(archives_frame)
    archives_scrollbar = ttk.Scrollbar(archives_frame, orient="vertical", command=archives_canvas.yview)
    archives_inner_frame = ttk.Frame(archives_canvas)
    archives_canvas.configure(yscrollcommand=archives_scrollbar.set)

    archives_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    archives_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    archives_canvas.create_window((0, 0), window=archives_inner_frame, anchor="nw")

    check_vars = []
    archive_vars = []

    def refresh_content(query=""):
        for widget in files_inner_frame.winfo_children():
            widget.destroy()
        for widget in archives_inner_frame.winfo_children():
            widget.destroy()

        check_vars.clear()
        archive_vars.clear()

        # Single private files
        for filename, access_token in app.uploaded_private_files:
            if query in filename.lower() or query in access_token.lower():
                var = tk.BooleanVar(value=False)
                check_vars.append((var, access_token, filename))
                frame = ttk.Frame(files_inner_frame)
                frame.pack(anchor="w", padx=5, pady=2)
                chk = ttk.Checkbutton(frame, text=f"{filename} - ", variable=var)
                chk.pack(side=tk.LEFT)
                addr_entry = ttk.Entry(frame, width=80)
                addr_entry.insert(0, access_token)
                addr_entry.config(state="readonly")
                addr_entry.pack(side=tk.LEFT)
                from gui import add_context_menu
                add_context_menu(addr_entry)

        # Private archives
        private_archives = [(addr, name) for addr, name, is_private in app.local_archives if is_private]
        for addr, nickname in private_archives:
            if query in nickname.lower() or query in addr.lower():
                var = tk.BooleanVar(value=False)
                archive_vars.append((var, addr, nickname))
                frame = ttk.Frame(archives_inner_frame)
                frame.pack(anchor="w", padx=5, pady=2)
                chk = ttk.Checkbutton(frame, text=f"{nickname} - ", variable=var)
                chk.pack(side=tk.LEFT)
                addr_entry = ttk.Entry(frame, width=80)
                addr_entry.insert(0, addr)
                addr_entry.config(state="readonly")
                addr_entry.pack(side=tk.LEFT)
                from gui import add_context_menu
                add_context_menu(addr_entry)

        files_inner_frame.update_idletasks()
        files_canvas.configure(scrollregion=files_canvas.bbox("all"))
        archives_inner_frame.update_idletasks()
        archives_canvas.configure(scrollregion=archives_canvas.bbox("all"))
        manage_window.after(30000, lambda: refresh_content(query))

    refresh_content()

    buttons_frame = ttk.Frame(manage_window)
    buttons_frame.pack(fill=tk.X, pady=10)

    def remove_selected():
        selected_files = [(access_token, filename) for var, access_token, filename in check_vars if var.get()]
        selected_archives = [(addr, nickname) for var, addr, nickname in archive_vars if var.get()]
        if not selected_files and not selected_archives:
            messagebox.showwarning("Selection Error", "Please select at least one item to remove.")
            return
        if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_files)} private files and {len(selected_archives)} private archives from the list? This won’t delete the data from the network."):
            for access_token, filename in selected_files:
                app.uploaded_private_files.remove((filename, access_token))
            for addr, nickname in selected_archives:
                for i, (a, n, is_private) in enumerate(app.local_archives):
                    if a == addr and n == nickname and is_private:
                        app.local_archives.pop(i)
                        break
            app.save_persistent_data()
            refresh_content()

    ttk.Button(buttons_frame, text="Remove from List", command=remove_selected).pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Close", command=manage_window.destroy).pack(side=tk.LEFT, padx=5)
