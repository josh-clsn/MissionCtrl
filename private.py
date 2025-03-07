# private.py
import os
import asyncio
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from autonomi_client import Metadata

logger = logging.getLogger("MissionCtrl")

async def upload_private(app, file_path, from_queue=False):
    logger.info("Upload Private started for %s", file_path)
    app._current_operation = 'upload'
    app.status_label.config(text=f"Uploading file: {os.path.basename(file_path)}")
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        from autonomi_client import PaymentOption
        payment_option = PaymentOption.wallet(app.wallet)
        ant_balance = int(await app.wallet.balance())
        if ant_balance > 0:
            result = await asyncio.wait_for(
                app.client.data_put(file_data, payment_option),
                timeout=15000
            )
            price, data_map_chunk = result
            access_token = data_map_chunk.to_hex()
            file_name = os.path.basename(file_path)
            app.local_archives.append((access_token, file_name, True))
            logger.info(f"Private data uploaded, price: {price}, access_token: {access_token}")
            app.root.after(0, lambda: app._show_upload_success(access_token, file_name, True))
        else:
            app.root.after(0, lambda: messagebox.showerror("Error", "Insufficient ANT for upload. Add ANT to your wallet in the Wallet tab."))
            app.is_processing = False
            app.stop_status_animation()
    except asyncio.TimeoutError:
        app.root.after(0, lambda: messagebox.showerror("Error", "Upload timed out after 1200 seconds. Check your network connection."))
        app.status_label.config(text="Upload timeout")
    except Exception as e:
        logger.error("Upload error: %s", e)
        app.root.after(0, lambda err=e: messagebox.showerror("Error", f"Upload failed: {err}\nCheck your ANT balance in the Wallet tab."))
        app.status_label.config(text="Upload failed")
    finally:
        if not from_queue:
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

    files_frame = ttk.LabelFrame(manage_window, text="Private Data Files", padding=5)
    files_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    files_canvas = tk.Canvas(files_frame)
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
        private_files = [(addr, name) for addr, name, is_private in app.local_archives if is_private]
        for addr, nickname in private_files:
            if query in nickname.lower() or query in addr.lower():
                var = tk.BooleanVar(value=False)
                check_vars.append((var, addr, nickname))
                frame = ttk.Frame(files_inner_frame)
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
        manage_window.after(30000, lambda: refresh_content(query))

    refresh_content()

    buttons_frame = ttk.Frame(manage_window)
    buttons_frame.pack(fill=tk.X, pady=10)

    def remove_selected():
        selected_files = [(addr, nickname) for var, addr, nickname in check_vars if var.get()]
        if not selected_files:
            messagebox.showwarning("Selection Error", "Please select at least one file to remove.")
            return
        if messagebox.askyesno("Confirm Removal", f"Remove {len(selected_files)} private files from the list? This won’t delete the data from the network."):
            for addr, nickname in selected_files:
                for i, (a, n, is_private) in enumerate(app.local_archives):
                    if a == addr and n == nickname and is_private:
                        app.local_archives.pop(i)
                        break
            manage_window.destroy()

    ttk.Button(buttons_frame, text="Remove from List", command=remove_selected).pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Close", command=manage_window.destroy).pack(side=tk.LEFT, padx=5)

