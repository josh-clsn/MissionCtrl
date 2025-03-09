import os
import io
import mimetypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import logging
import asyncio
import subprocess
from pathlib import Path

logger = logging.getLogger("MissionCtrl")
logger.setLevel(logging.DEBUG)
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_downloads_folder():
    """Get the user's Downloads folder in a cross-platform way."""
    try:
        # On Linux, try using xdg-user-dir to get the Downloads folder
        if os.name != "nt":  # Not Windows
            result = subprocess.run(
                ["xdg-user-dir", "DOWNLOAD"],
                capture_output=True,
                text=True,
                check=True
            )
            downloads_path = result.stdout.strip()
            if downloads_path and os.path.isdir(downloads_path):
                return downloads_path
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass  # Fallback if xdg-user-dir fails or isn't available

    # Fallback: Use ~/Downloads
    return str(Path.home() / "Downloads")

def detect_and_display_content(data, parent_frame, filename="data"):
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None:
        if data.startswith(b'\x89PNG'):
            mime_type = 'image/png'
        elif data.startswith(b'\xff\xd8'):
            mime_type = 'image/jpeg'
        elif data.startswith(b'\x47\x49\x46'):
            mime_type = 'image/gif'
        elif data.startswith(b'BM'):
            mime_type = 'image/bmp'
        elif data.startswith(b'\x00\x00\x01\x00'):
            mime_type = 'image/x-icon'
        elif data.startswith(b'RIFF') and b'WEBP' in data[8:12]:
            mime_type = 'image/webp'
        elif data.startswith(b'\x1a\x45\xdf\xa3') or data.startswith(b'mov') or b'moov' in data[:12]:
            mime_type = 'video/quicktime'
        elif data.startswith(b'\x00\x00\x00\x1cftypmp4') or data.startswith(b'\x00\x00\x00\x18ftyp'):
            mime_type = 'video/mp4'
        elif data.startswith(b'RIFF') and b'AVI ' in data[8:12]:
            mime_type = 'video/avi'
        elif data.startswith(b'\x4f\x67\x67\x53'):
            mime_type = 'video/ogg'
        else:
            try:
                data.decode('utf-8')
                mime_type = 'text/plain'
            except UnicodeDecodeError:
                mime_type = 'application/octet-stream'

    if mime_type.startswith('image/'):
        try:
            img = Image.open(io.BytesIO(data))
            img.thumbnail((600, 600)) 
            photo = ImageTk.PhotoImage(img)
            label = ttk.Label(parent_frame, image=photo)
            label.image = photo
            label.pack(pady=5)
            ttk.Label(parent_frame, text=f"{mime_type.split('/')[1].upper()} Image").pack()
        except Exception as e:
            logger.error("Failed to load image: %s", e)
            ttk.Label(parent_frame, text="Not able to preview the file. Save the file to view it.").pack(pady=5)
    elif mime_type == 'text/plain':
        try:
            text_widget = tk.Text(parent_frame, wrap=tk.WORD, height=10, width=60)
            text_widget.pack(pady=5, fill=tk.BOTH, expand=True)
            text_widget.insert(tk.END, data.decode('utf-8'))
            text_widget.config(state=tk.DISABLED)
            from gui import add_context_menu 
            add_context_menu(text_widget)
            ttk.Label(parent_frame, text="Text Content").pack()
        except Exception as e:
            logger.error("Failed to load text: %s", e)
            ttk.Label(parent_frame, text="Not able to preview the file. Save the file to view it.").pack(pady=5)
    else:
        ttk.Label(parent_frame, text="Not able to preview the file. Save the file to view it.").pack(pady=5)
        ttk.Label(parent_frame, text=f"Detected type: {mime_type} | Size: {len(data)} bytes").pack()

def show_data_window(app, data, is_private, archive=None, is_single_chunk=False, address_input=None):
    view_window = tk.Toplevel(app.root)
    view_window.title("Retrieved Data - Mission Ctrl")
    view_window.geometry("800x600")
    view_window.minsize(800, 600)
    view_window.resizable(True, True)

    main_frame = ttk.Frame(view_window)
    main_frame.pack(fill=tk.BOTH, expand=True)

    canvas = tk.Canvas(main_frame)
    scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
    content_frame = ttk.Frame(canvas)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    canvas.create_window((0, 0), window=content_frame, anchor="nw")
    content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    if is_private and archive:
        ttk.Label(content_frame, text="Retrieved Private Archive:", font=("Arial", 12, "bold")).pack(pady=5)
        file_list = list(archive.files())
        if not file_list:
            ttk.Label(content_frame, text="No files found in archive.").pack()
        else:
            for path, metadata in file_list:
                frame = ttk.Frame(content_frame)
                frame.pack(fill=tk.X, pady=2, padx=5)
                ttk.Label(frame, text=f"- {path} (Size: {metadata.size} bytes)").pack(side=tk.LEFT, padx=5)
    elif is_private:
        ttk.Label(content_frame, text="Retrieved Private Data:", font=("Arial", 12, "bold")).pack(pady=5)
        detect_and_display_content(data, content_frame)
    else:
        if is_single_chunk:
            ttk.Label(content_frame, text="Retrieved Single Public Chunk:", font=("Arial", 12, "bold")).pack(pady=5)
            detect_and_display_content(data, content_frame)
        else:
            ttk.Label(content_frame, text="Retrieved Public Archive:", font=("Arial", 12, "bold")).pack(pady=5)
            file_list = list(archive.files()) if archive else []
            if not file_list:
                ttk.Label(content_frame, text="No files found in archive.").pack()
            else:
                chunk_addresses = list(archive.addresses()) if archive else []
                file_names = [item[0] for item in file_list]
                for name, addr in zip(file_names, chunk_addresses):
                    frame = ttk.Frame(content_frame)
                    frame.pack(fill=tk.X, pady=2, padx=5)
                    ttk.Label(frame, text=f"- {name} (Address: {addr})").pack(side=tk.LEFT, padx=5)
                    loading_label = ttk.Label(frame, text="")
                    loading_label.pack(side=tk.LEFT, padx=5)
                    view_button = ttk.Button(frame, text="View")
                    view_button.config(command=lambda b=view_button, a=addr, n=name, l=loading_label: view_file(app, a, n, b, l))
                    view_button.pack(side=tk.LEFT, padx=5)

    content_frame.update_idletasks()

    button_frame = ttk.Frame(view_window)
    button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

    bottom_loading_label = ttk.Label(button_frame, text="")
    bottom_loading_label.pack(side=tk.LEFT, padx=5)

    button_states = {"save": False, "save_all": False}

    def set_loading_state(button, state, message="", label=None):
        button.config(state=tk.DISABLED if state else tk.NORMAL)
        if label:
            label.config(text=message)
            label.update_idletasks()

    def save_individual():
        if button_states["save"]:
            return
        button_states["save"] = True
        set_loading_state(save_button, True, "Saving...", bottom_loading_label)

        if is_private or is_single_chunk:
            save_path = filedialog.asksaveasfilename(
                parent=view_window,
                initialdir=get_downloads_folder(),  # Changed to Downloads folder
                defaultextension=".bin",
                filetypes=[("All files", "*.*")],
                title="Save Retrieved Data"
            )
            if save_path:
                try:
                    with open(save_path, "wb") as f:
                        f.write(data)
                    messagebox.showinfo("Success", f"Data saved to {save_path}")
                except Exception as ex:
                    logger.error("Failed to save data: %s", ex)
                    messagebox.showerror("Error", f"Failed to save data: {ex}")
        else:
            file_menu = tk.Menu(view_window, tearoff=0)
            file_names = [item[0] for item in archive.files()]
            chunk_addresses = list(archive.addresses())
            for name, addr in zip(file_names, chunk_addresses):
                file_menu.add_command(
                    label=name,
                    command=lambda n=name, a=addr: download_file(n, a)
                )
            file_menu.tk_popup(button_frame.winfo_rootx(), button_frame.winfo_rooty())

        button_states["save"] = False
        set_loading_state(save_button, False, "", bottom_loading_label)

    def download_file(name, addr):
        if button_states["save"]:
            return
        button_states["save"] = True
        set_loading_state(save_button, True, f"Downloading {name}...", bottom_loading_label)

        async def do_download():
            try:
                file_data = await app.client.data_get_public(addr)
                save_path = filedialog.asksaveasfilename(
                    parent=view_window,
                    initialfile=name,
                    initialdir=get_downloads_folder(),  # Changed to Downloads folder
                    defaultextension=".bin",
                    filetypes=[("All files", "*.*")],
                    title=f"Save {name}"
                )
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(file_data)
                    messagebox.showinfo("Success", f"File saved to {save_path}")
            except Exception as ex:
                logger.error("Failed to save file: %s", ex)
                messagebox.showerror("Error", f"Failed to save file: {ex}")
            finally:
                button_states["save"] = False
                set_loading_state(save_button, False, "", bottom_loading_label)
        asyncio.run_coroutine_threadsafe(do_download(), app.loop)

    def save_all():
        if button_states["save_all"]:
            return
        button_states["save_all"] = True
        set_loading_state(save_all_button, True, "Saving all files...", bottom_loading_label)

        save_path = filedialog.askdirectory(
            parent=view_window,
            initialdir=get_downloads_folder(),  # Changed to Downloads folder
            title="Select Directory to Save All Files"
        )
        if save_path:
            async def do_save_all():
                try:
                    if not is_private and archive and not is_single_chunk:
                        await app.client.dir_download_public(address_input, save_path)
                        messagebox.showinfo("Success", f"Directory downloaded to {save_path}")
                    else:
                        file_list = list(archive.files())
                        chunk_addresses = list(archive.addresses())
                        file_names = [item[0] for item in file_list]
                        
                        if len(file_names) != len(chunk_addresses):
                            raise ValueError("Mismatch between file names and chunk addresses")
                        
                        for name, addr in zip(file_names, chunk_addresses):
                            file_data = await app.client.data_get_public(addr)
                            file_path = os.path.join(save_path, name)
                            with open(file_path, "wb") as f:
                                f.write(file_data)
                            logger.info(f"Saved {name} to {file_path}")
                        
                        messagebox.showinfo("Success", f"All {len(file_names)} files saved to {save_path}")
                except Exception as ex:
                    logger.error("Failed to download directory or save files: %s", ex)
                    messagebox.showerror("Error", f"Failed to download directory or save files: {ex}")
                finally:
                    button_states["save_all"] = False
                    set_loading_state(save_all_button, False, "", bottom_loading_label)
            asyncio.run_coroutine_threadsafe(do_save_all(), app.loop)

    save_button = ttk.Button(button_frame, text="Save" if (is_private or is_single_chunk) else "Save File", command=save_individual)
    save_button.pack(side=tk.LEFT, padx=5)
    
    if not is_private and archive and not is_single_chunk:
        save_all_button = ttk.Button(button_frame, text="Save All", command=save_all)
        save_all_button.pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Close", command=lambda: (logger.info("Closing window..."), view_window.destroy())).pack(side=tk.LEFT, padx=5)

    view_window.update_idletasks()

def view_file(app, addr, name, button, loading_label):
    if not hasattr(button, "is_busy"):
        button.is_busy = False
    
    if button.is_busy:
        return
    
    button.is_busy = True
    button.config(state=tk.DISABLED)
    loading_label.config(text=f"Retrieving data {name}...")
    loading_label.update_idletasks()

    async def _view():
        try:
            file_data = await app.client.data_get_public(addr)
            sub_window = tk.Toplevel(app.root)
            sub_window.title(f"View {name}")
            sub_frame = ttk.Frame(sub_window)
            sub_frame.pack(fill=tk.BOTH, expand=True)
            detect_and_display_content(file_data, sub_frame, name)
            ttk.Button(sub_window, text="Close", command=sub_window.destroy).pack(pady=5)
        except Exception as e:
            logger.error("Failed to view %s: %s", name, e)
            messagebox.showerror("Error", f"Failed to view {name}: {e}")
        finally:
            button.is_busy = False
            button.config(state=tk.NORMAL)
            loading_label.config(text="")
            loading_label.update_idletasks()
    
    asyncio.run_coroutine_threadsafe(_view(), app.loop)