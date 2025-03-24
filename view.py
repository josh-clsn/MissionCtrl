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

# Import color scheme from gui.py
from gui import COLORS

def get_downloads_folder():
    """Cross-platform retrieval of Downloads folder."""
    try:
        if os.name != "nt":  # Non-Windows systems
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
        pass  # Fallback if xdg-user-dir fails
    return str(Path.home() / "Downloads")

def detect_and_display_content(data, parent_frame, filename="data"):
    """Detects content type and renders preview in UI."""
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None:
        # Manual MIME detection for common formats
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

    # Content container with border and padding
    content_container = ttk.Frame(parent_frame, style="Card.TFrame", padding=10)
    content_container.pack(fill=tk.BOTH, expand=True, pady=10, padx=5)

    if mime_type.startswith('image/'):
        try:
            img = Image.open(io.BytesIO(data))
            img.thumbnail((600, 600))
            photo = ImageTk.PhotoImage(img)
            
            # Image container
            img_container = ttk.Frame(content_container, style="TFrame")
            img_container.pack(fill=tk.BOTH, expand=True)
            
            # Display image
            label = ttk.Label(img_container, image=photo, background=COLORS["bg_light"])
            label.image = photo
            label.pack(pady=10)
            
            # Image info footer
            info_frame = ttk.Frame(content_container, style="TFrame")
            info_frame.pack(fill=tk.X, pady=(5, 0))
            
            # Add file type badge
            type_badge = ttk.Label(info_frame, text=f"{mime_type.split('/')[1].upper()}", 
                                  background=COLORS["accent_tertiary"], 
                                  foreground="white",
                                  padding=(8, 2))
            type_badge.pack(side=tk.LEFT)
            
            # Add dimensions info
            ttk.Label(info_frame, text=f"Dimensions: {img.width} × {img.height} px", 
                    foreground=COLORS["text_secondary"],
                    padding=(10, 0)).pack(side=tk.RIGHT)
            
        except Exception as e:
            logger.error("Failed to load image: %s", e)
            error_frame = ttk.Frame(content_container, style="TFrame", padding=20)
            error_frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(error_frame, text="⚠️", 
                    font=("Inter", 24), 
                    foreground=COLORS["warning"]).pack(pady=(10, 5))
            ttk.Label(error_frame, text="Unable to preview this image", 
                    font=("Inter", 12, "bold")).pack()
            ttk.Label(error_frame, text="Save the file to view it on your device", 
                    foreground=COLORS["text_secondary"]).pack(pady=(5, 10))
            
    elif mime_type == 'text/plain':
        try:
            # Create text preview with syntax highlighting
            text_frame = ttk.Frame(content_container, style="TFrame")
            text_frame.pack(fill=tk.BOTH, expand=True)
            
            text_widget = tk.Text(text_frame, wrap=tk.WORD, height=15, width=80,
                               font=("Inter Mono", 10),
                               bg=COLORS["bg_secondary"],
                               fg=COLORS["text_primary"],
                               padx=10, pady=10,
                               relief="flat")
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            # Create scrollbar
            scrollbar = ttk.Scrollbar(text_widget, orient="vertical", command=text_widget.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            text_widget.config(yscrollcommand=scrollbar.set)
            
            # Insert text content
            text_widget.insert(tk.END, data.decode('utf-8'))
            text_widget.config(state=tk.DISABLED)
            
            # Add context menu
            from gui import add_context_menu 
            add_context_menu(text_widget)
            
            # Add info footer
            info_frame = ttk.Frame(content_container, style="TFrame")
            info_frame.pack(fill=tk.X, pady=(10, 0))
            
            # Add file type badge
            type_badge = ttk.Label(info_frame, text="TEXT", 
                                background=COLORS["accent_primary"], 
                                foreground="white",
                                padding=(8, 2))
            type_badge.pack(side=tk.LEFT)
            
            # Add file size
            size_text = f"Size: {len(data)} bytes"
            if len(data) > 1024:
                size_text = f"Size: {len(data)/1024:.1f} KB"
            if len(data) > 1024*1024:
                size_text = f"Size: {len(data)/(1024*1024):.1f} MB"
                
            ttk.Label(info_frame, text=size_text, 
                    foreground=COLORS["text_secondary"],
                    padding=(10, 0)).pack(side=tk.RIGHT)
            
        except Exception as e:
            logger.error("Failed to load text: %s", e)
            error_frame = ttk.Frame(content_container, style="TFrame", padding=20)
            error_frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(error_frame, text="⚠️", 
                    font=("Inter", 24), 
                    foreground=COLORS["warning"]).pack(pady=(10, 5))
            ttk.Label(error_frame, text="Unable to preview this text file", 
                    font=("Inter", 12, "bold")).pack()
            ttk.Label(error_frame, text="Save the file to view it on your device", 
                    foreground=COLORS["text_secondary"]).pack(pady=(5, 10))
    else:
        # Generic file preview for unsupported types
        preview_frame = ttk.Frame(content_container, style="TFrame", padding=20)
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        # Show appropriate icon based on MIME type
        icon_text = "📄"
        if mime_type.startswith('video/'):
            icon_text = "🎬"
        elif mime_type.startswith('audio/'):
            icon_text = "🎵"
        elif mime_type.startswith('application/pdf'):
            icon_text = "📕"
        elif mime_type.startswith('application/zip') or mime_type.startswith('application/x-compressed'):
            icon_text = "🗜️"
            
        ttk.Label(preview_frame, text=icon_text, 
                font=("Inter", 48)).pack(pady=(10, 15))
        ttk.Label(preview_frame, text="Preview not available", 
                font=("Inter", 14, "bold")).pack()
        ttk.Label(preview_frame, text="Save the file to view it on your device", 
                foreground=COLORS["text_secondary"]).pack(pady=(5, 10))
        
        # File info
        info_frame = ttk.Frame(preview_frame, style="TFrame", padding=(0, 10, 0, 0))
        info_frame.pack(fill=tk.X)
        
        # Format the file type nicely
        type_text = mime_type.split('/')[-1].upper()
        if type_text == "OCTET-STREAM":
            type_text = "BINARY"
            
        # Add file type badge
        type_badge = ttk.Label(info_frame, text=type_text, 
                            background=COLORS["text_secondary"], 
                            foreground="white",
                            padding=(8, 2))
        type_badge.pack()
        
        # Size info
        size_text = f"Size: {len(data)} bytes"
        if len(data) > 1024:
            size_text = f"Size: {len(data)/1024:.1f} KB"
        if len(data) > 1024*1024:
            size_text = f"Size: {len(data)/(1024*1024):.1f} MB"
            
        ttk.Label(preview_frame, text=size_text, 
                foreground=COLORS["text_secondary"]).pack(pady=(5, 0))

def show_data_window(app, data, is_private, archive=None, is_single_chunk=False, address_input=None):
    """Displays retrieved data or archive contents in a scrollable window."""
    view_window = tk.Toplevel(app.root)
    view_window.title("Retrieved Data - Mission Ctrl")
    view_window.geometry("800x600")
    view_window.minsize(800, 600)
    view_window.resizable(True, True)
    view_window.configure(bg=COLORS["bg_light"])

    main_frame = ttk.Frame(view_window, style="TFrame", padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Add a title header
    header_frame = ttk.Frame(main_frame, style="TFrame")
    header_frame.pack(fill=tk.X, pady=(0, 15))
    
    # Set title based on content type
    title_text = "Retrieved Data"
    if is_private and archive:
        title_text = "Retrieved Private Archive"
    elif is_private:
        title_text = "Retrieved Private Data"
    elif is_single_chunk:
        title_text = "Retrieved Single Public Chunk"
    else:
        title_text = "Retrieved Public Archive"
        
    ttk.Label(header_frame, text=title_text, 
            font=("Inter", 16, "bold"), 
            foreground=COLORS["accent_primary"]).pack(anchor="w")

    content_frame = ttk.Frame(main_frame, style="Card.TFrame", padding="20")
    content_frame.pack(fill=tk.BOTH, expand=True)

    canvas = tk.Canvas(content_frame, bg=COLORS["bg_light"], 
                     bd=0, highlightthickness=0)
    scrollbar = ttk.Scrollbar(content_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas, style="TFrame")
    
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    # Content display based on type
    if is_private and archive:
        file_list = list(archive.files())
        if not file_list:
            ttk.Label(scrollable_frame, text="No files found in archive.", 
                    foreground=COLORS["text_secondary"]).pack(pady=10)
        else:
            for path, metadata in file_list:
                item_frame = ttk.Frame(scrollable_frame, style="TFrame")
                item_frame.pack(fill=tk.X, pady=5, padx=5)
                
                file_icon = "📄 "  # Default file icon
                if path.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                    file_icon = "🖼️ "
                elif path.lower().endswith(('.mp4', '.mov', '.avi')):
                    file_icon = "🎬 "
                elif path.lower().endswith(('.mp3', '.wav', '.ogg')):
                    file_icon = "🎵 "
                elif path.lower().endswith(('.pdf')):
                    file_icon = "📕 "
                elif path.lower().endswith(('.zip', '.tar', '.gz')):
                    file_icon = "🗜️ "
                
                ttk.Label(item_frame, text=f"{file_icon}{path}", 
                        font=("Inter", 11)).pack(side=tk.LEFT, padx=5)
                ttk.Label(item_frame, text=f"{metadata.size} bytes", 
                        foreground=COLORS["text_secondary"]).pack(side=tk.RIGHT, padx=5)
    
    elif is_private:
        detect_and_display_content(data, scrollable_frame)
    
    else:
        if is_single_chunk:
            detect_and_display_content(data, scrollable_frame)
        else:
            file_list = list(archive.files()) if archive else []
            if not file_list:
                ttk.Label(scrollable_frame, text="No files found in archive.", 
                        foreground=COLORS["text_secondary"]).pack(pady=10)
            else:
                chunk_addresses = list(archive.addresses()) if archive else []
                file_names = [item[0] for item in file_list]
                
                for name, addr in zip(file_names, chunk_addresses):
                    item_frame = ttk.Frame(scrollable_frame, style="TFrame", padding=5)
                    item_frame.pack(fill=tk.X, pady=3)
                    
                    file_icon = "📄 "  # Default file icon
                    if name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                        file_icon = "🖼️ "
                    elif name.lower().endswith(('.mp4', '.mov', '.avi')):
                        file_icon = "🎬 "
                    elif name.lower().endswith(('.mp3', '.wav', '.ogg')):
                        file_icon = "🎵 "
                    elif name.lower().endswith(('.pdf')):
                        file_icon = "📕 "
                    elif name.lower().endswith(('.zip', '.tar', '.gz')):
                        file_icon = "🗜️ "
                    
                    info_frame = ttk.Frame(item_frame, style="TFrame")
                    info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
                    
                    ttk.Label(info_frame, text=f"{file_icon}{name}", 
                            font=("Inter", 11)).pack(anchor="w")
                    ttk.Label(info_frame, text=f"Address: {addr}", 
                            foreground=COLORS["text_secondary"], 
                            font=("Inter", 9)).pack(anchor="w")
                    
                    action_frame = ttk.Frame(item_frame, style="TFrame")
                    action_frame.pack(side=tk.RIGHT)
                    
                    loading_label = ttk.Label(action_frame, text="")
                    loading_label.pack(side=tk.LEFT, padx=5)
                    
                    view_button = ttk.Button(action_frame, text="View", style="Secondary.TButton", width=8)
                    view_button.config(command=lambda b=view_button, a=addr, n=name, l=loading_label: 
                                     view_file(app, a, n, b, l))
                    view_button.pack(side=tk.LEFT, padx=5)

    content_frame.update_idletasks()

    # Button frame at bottom
    button_frame = ttk.Frame(main_frame, style="TFrame", padding=(0, 15, 0, 0))
    button_frame.pack(side=tk.BOTTOM, fill=tk.X)

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
                initialdir=get_downloads_folder(),
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
                    import traceback
                    logger.error("Failed to save file: %s\n%s", ex, traceback.format_exc())
                    messagebox.showerror("Error", f"Failed to save file: {ex}\nDetails: {traceback.format_exc()}")
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
                    initialdir=get_downloads_folder(),
                    defaultextension=".bin",
                    filetypes=[("All files", "*.*")],
                    title=f"Save {name}"
                )
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(file_data)
                    messagebox.showinfo("Success", f"File saved to {save_path}")
            except Exception as ex:
                import traceback
                logger.error("Failed to save file: %s\n%s", ex, traceback.format_exc())
                messagebox.showerror("Error", f"Failed to save file: {ex}\nDetails: {traceback.format_exc()}")
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
            initialdir=get_downloads_folder(),
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
                    import traceback
                    logger.error("Failed to download directory or save files: %s\n%s", ex, traceback.format_exc())
                    messagebox.showerror("Error", f"Failed to download directory or save files: {ex}\nDetails: {traceback.format_exc()}")
                finally:
                    button_states["save_all"] = False
                    set_loading_state(save_all_button, False, "", bottom_loading_label)
            asyncio.run_coroutine_threadsafe(do_save_all(), app.loop)

    # Footer with action buttons
    action_buttons = ttk.Frame(button_frame, style="TFrame")
    action_buttons.pack(side=tk.RIGHT)
    
    # Only show Save All button if there's an archive
    if archive or is_single_chunk or (is_private and data):
        save_all_button = ttk.Button(action_buttons, text="Save All", 
                                command=save_all, style="Accent.TButton")
        save_all_button.pack(side=tk.RIGHT, padx=(10, 0))
    
    save_button = ttk.Button(action_buttons, text="Save", 
                        command=save_individual, style="Accent.TButton")
    save_button.pack(side=tk.RIGHT)
    
    close_button = ttk.Button(action_buttons, text="Close", 
                         command=view_window.destroy, style="Secondary.TButton")
    close_button.pack(side=tk.RIGHT, padx=(0, 10))

    view_window.update_idletasks()

def view_file(app, addr, name, button, loading_label):
    """Async retrieval and display of a single public file."""
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
            import traceback
            logger.error("Failed to view %s: %s\n%s", name, e, traceback.format_exc())
            messagebox.showerror("Error", f"Failed to view {name}: {e}\nDetails: {traceback.format_exc()}")
        finally:
            button.is_busy = False
            button.config(state=tk.NORMAL)
            loading_label.config(text="")
            loading_label.update_idletasks()
    
    asyncio.run_coroutine_threadsafe(_view(), app.loop)