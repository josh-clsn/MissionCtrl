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
import platform
import base64
import math
import magic
import gui
import pygame
import threading
import tempfile

logger = logging.getLogger("MissionCtrl")

# Define common audio file extensions
AUDIO_EXTENSIONS = (".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac")
# Define common video file extensions
VIDEO_EXTENSIONS = (".mp4", ".mov", ".avi", ".mkv", ".webm", ".flv")

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

def detect_and_display_content(app, data, parent_frame, filename="data"):
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
            # Create text preview with full height and width
            text_container = ttk.Frame(content_container, style="TFrame")
            text_container.pack(fill=tk.BOTH, expand=True)
            
            # File info header
            info_frame = ttk.Frame(text_container, style="TFrame")
            info_frame.pack(fill=tk.X, pady=(0, 5))
            
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
            
            # Create the text widget that takes the full container size
            text_frame = ttk.Frame(text_container, style="TFrame")
            text_frame.pack(fill=tk.BOTH, expand=True)
            
            text_widget = tk.Text(text_frame, wrap=tk.WORD,
                               font=("Inter Mono", 11),
                               bg=COLORS["bg_secondary"],
                               fg=COLORS["text_primary"],
                               padx=15, pady=15,
                               relief="flat")
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            # Create scrollbar
            scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            text_widget.config(yscrollcommand=scrollbar.set)
            
            # Insert text content
            text_widget.insert(tk.END, data.decode('utf-8'))
            text_widget.config(state=tk.DISABLED)
            
            # Add context menu
            from gui import add_context_menu 
            add_context_menu(text_widget)
            
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
        is_playable_video = False
        is_playable_audio = False
        if mime_type.startswith('video/'):
            icon_text = "🎬"
            is_playable_video = True
        elif mime_type.startswith('audio/'):
            icon_text = "🎵"
            is_playable_audio = True
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

        # Add Play button for audio/video if detected
        if is_playable_audio or is_playable_video:
            play_button_frame = ttk.Frame(preview_frame, style="TFrame")
            play_button_frame.pack(pady=(15, 0))

            if is_playable_audio:
                play_cmd = lambda: open_audio_player(app, data, filename)
            else: # is_playable_video
                play_cmd = lambda: open_external_video_player(app, data, filename)

            play_button = ttk.Button(play_button_frame, text="Play", 
                                   command=play_cmd, 
                                   style="Accent.TButton", width=12)
            play_button.pack()

def show_data_window(app, data, is_private, archive=None, is_single_chunk=False, address_input=None):
    """Displays retrieved data or archive contents in a scrollable window."""
    view_window = tk.Toplevel(app.root)
    view_window.title("Retrieved Data - Mission Ctrl")
    view_window.resizable(True, True)
    view_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
    view_window.geometry("1300x900")

    # Apply theme if dark mode is enabled
    if hasattr(app, 'is_dark_mode') and app.is_dark_mode:
        gui.apply_theme_to_toplevel(view_window, True)
    
    # Set window to remain on top until user interaction
    view_window.attributes("-topmost", True)
    view_window.grab_set()
    
    # Remove topmost after a short delay (allows user to see and interact with window)
    def remove_topmost():
        view_window.attributes("-topmost", False)
        # Keep window focused
        view_window.focus_force()
    
    # Schedule removal of topmost after 1.5 seconds
    view_window.after(1500, remove_topmost)

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
            foreground=gui.CURRENT_COLORS["accent_primary"]).pack(anchor="w")

    # For single chunks and private data, use the improved direct viewing
    if is_private or is_single_chunk:
        content_frame = ttk.Frame(main_frame, style="Card.TFrame")
        content_frame.pack(fill=tk.BOTH, expand=True)
        detect_and_display_content(app, data, content_frame)
    else:
        # For archives, use the original scrollable approach
        content_frame = ttk.Frame(main_frame, style="Card.TFrame", padding="20")
        content_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(content_frame, bg=gui.CURRENT_COLORS["bg_light"],
                         bd=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(content_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style="TFrame")
        
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        # Content display for archives
        file_list = list(archive.files()) if archive else []
        if not file_list:
            ttk.Label(scrollable_frame, text="No files found in archive.", 
                    foreground=gui.CURRENT_COLORS["text_secondary"]).pack(pady=10)
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
                        foreground=gui.CURRENT_COLORS["text_secondary"],
                        font=("Inter", 9)).pack(anchor="w")
                
                action_frame = ttk.Frame(item_frame, style="TFrame")
                action_frame.pack(side=tk.RIGHT)
                
                loading_label = ttk.Label(action_frame, text="")
                loading_label.pack(side=tk.LEFT, padx=5)

                # Check file type for action button
                is_audio = name.lower().endswith(AUDIO_EXTENSIONS)
                is_video = name.lower().endswith(VIDEO_EXTENSIONS)

                if is_audio:
                    button_text = "Play"
                    command_func = play_audio
                elif is_video:
                    button_text = "Play"
                    command_func = play_video
                else:
                    button_text = "View"
                    command_func = view_file

                action_button = ttk.Button(action_frame, text=button_text, style="Secondary.TButton", width=8)
                # Assign the command using a lambda that captures the current loop variables correctly
                action_button.config(command=lambda cmd=command_func, b=action_button, a=addr, n=name, l=loading_label:
                                     cmd(app, a, n, b, l))
                action_button.pack(side=tk.LEFT, padx=5)

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

    # Update UI before showing window
    view_window.update_idletasks()
    
    # Final focus - this is sufficient since we're using the delayed topmost removal pattern
    view_window.focus_force()

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
            sub_window.geometry("900x700")  # Set a larger initial window size

            # Apply theme if dark mode is enabled
            if hasattr(app, 'is_dark_mode') and app.is_dark_mode:
                gui.apply_theme_to_toplevel(sub_window, True)
            
            # Set window to remain on top until user interaction
            sub_window.attributes("-topmost", True)
            sub_window.focus_force()
            sub_window.grab_set()
            
            # Remove topmost after a short delay
            def remove_topmost():
                sub_window.attributes("-topmost", False)
                # Keep window focused
                sub_window.focus_force()
            
            # Schedule removal of topmost after 1.5 seconds
            sub_window.after(1500, remove_topmost)
            
            main_frame = ttk.Frame(sub_window, padding=10)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Add a header with filename
            header_frame = ttk.Frame(main_frame)
            header_frame.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(header_frame, text=name, 
                    font=("Inter", 14, "bold"),
                    foreground=gui.CURRENT_COLORS["accent_primary"]).pack(anchor="w")
            
            # Content frame to hold the file display
            content_frame = ttk.Frame(main_frame)
            content_frame.pack(fill=tk.BOTH, expand=True)
            
            # Use the detect_and_display_content function to render the file
            detect_and_display_content(app, file_data, content_frame, name)
            
            # Footer with close button
            footer_frame = ttk.Frame(main_frame, padding=(0, 10, 0, 0))
            footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
            
            ttk.Button(footer_frame, text="Close", 
                     command=sub_window.destroy,
                     style="Secondary.TButton").pack(side=tk.RIGHT)
            
            # Add save button
            save_btn = ttk.Button(footer_frame, text="Save", 
                               command=lambda: save_viewed_file(file_data, name, sub_window),
                               style="Accent.TButton")
            save_btn.pack(side=tk.RIGHT, padx=(0, 10))
            
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

def save_viewed_file(data, filename, parent_window):
    """Save a file that's being viewed."""
    save_path = filedialog.asksaveasfilename(
        parent=parent_window,
        initialfile=filename,
        initialdir=get_downloads_folder(),
        defaultextension=".*",
        filetypes=[("All files", "*.*")],
        title=f"Save {filename}"
    )
    if save_path:
        try:
            with open(save_path, "wb") as f:
                f.write(data)
            messagebox.showinfo("Success", f"File saved to {save_path}", parent=parent_window)
        except Exception as ex:
            import traceback
            logger.error("Failed to save file: %s\n%s", ex, traceback.format_exc())
            messagebox.showerror("Error", f"Failed to save file: {ex}\nDetails: {traceback.format_exc()}", parent=parent_window)

def play_audio(app, address, filename, button, loading_label):
    """Initiates fetching audio data and opening the player."""
    logger.info(f"Play button clicked for: {filename} ({address})")
    
    # Disable button and show loading indicator
    if button:
        button.config(state=tk.DISABLED)
    loading_label.config(text="Loading...")
    loading_label.update_idletasks()

    # Run the async fetch in the background
    asyncio.run_coroutine_threadsafe(
        _do_play_audio(app, address, filename, button, loading_label),
        app.loop
    )

async def _do_play_audio(app, address, filename, button, loading_label):
    """Fetches audio data and calls the function to open the player window."""
    audio_data = None
    try:
        logger.info(f"Fetching audio data for {filename} from {address}")
        # Fetch the audio data (assuming public for now)
        # TODO: Add handling for private data if needed
        audio_data = await app.client.data_get_public(address)
        logger.info(f"Successfully fetched {len(audio_data)} bytes for {filename}")
        
        # Call the player window function in the main thread
        app.root.after(0, open_audio_player, app, audio_data, filename)
        
    except Exception as e:
        import traceback
        logger.error(f"Failed to fetch or play audio {filename}: {e}\n{traceback.format_exc()}")
        app.root.after(0, messagebox.showerror, "Error", f"Failed to load audio: {e}")
    finally:
        # Re-enable button and clear loading indicator in the main thread
        def reset_ui():
            if button:
                button.config(state=tk.NORMAL)
            loading_label.config(text="")
        app.root.after(0, reset_ui)

def open_audio_player(app, audio_data, filename):
    """Creates and manages the audio player window using Tkinter and Pygame."""
    
    player_window = tk.Toplevel(app.root)
    player_window.title(f"Play - {filename}")
    player_window.resizable(True, True)
    player_window.configure(bg=gui.CURRENT_COLORS["bg_light"])
    player_window.transient(app.root)
    player_window.grab_set()
    
    if hasattr(app, 'is_dark_mode') and app.is_dark_mode:
        gui.apply_theme_to_toplevel(player_window, True)
        
    # Ensure window is brought to the front and stays there temporarily
    player_window.lift()
    player_window.focus_force()
    player_window.attributes("-topmost", True)
    
    # Remove topmost after a short delay
    def remove_topmost():
        player_window.attributes("-topmost", False)
        # Keep window focused
        player_window.focus_force()
    
    # Schedule removal of topmost after 1.5 seconds
    player_window.after(1500, remove_topmost)
        
    playback_thread = None
    paused = False

    try:
        # Initialize pygame mixer in a separate thread to avoid blocking
        pygame.mixer.init()
        
        # Load audio from memory
        audio_stream = io.BytesIO(audio_data)
        pygame.mixer.music.load(audio_stream)
        logger.info(f"Audio loaded into pygame mixer for {filename}")

    except Exception as e:
        logger.error(f"Pygame error loading audio {filename}: {e}")
        messagebox.showerror("Playback Error", f"Could not load audio for playback: {e}", parent=player_window)
        player_window.destroy()
        return
        
    # --- Player Controls ---
    control_frame = ttk.Frame(player_window, style="TFrame", padding=20)
    control_frame.pack(fill=tk.BOTH, expand=True)

    status_label = ttk.Label(control_frame, text="Ready", anchor="center")
    status_label.pack(fill=tk.X, pady=(0, 10))
    
    button_frame = ttk.Frame(control_frame, style="TFrame")
    button_frame.pack()

    def run_playback():
        """Runs pygame mixer functions in a dedicated thread."""
        try:
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy() or paused:
                pygame.time.Clock().tick(10) # Keep thread alive while playing/paused
            # Playback finished naturally
            player_window.after(0, lambda: status_label.config(text="Finished"))
            player_window.after(0, lambda: play_pause_button.config(state=tk.DISABLED))
        except Exception as e:
            logger.error(f"Error during playback thread: {e}")
            player_window.after(0, lambda: status_label.config(text=f"Error: {e}"))
        finally:
            logger.info("Playback thread finished.")
            
    def play_music():
        nonlocal playback_thread
        if not pygame.mixer.music.get_busy() and not playback_thread:
            status_label.config(text="Playing...")
            # Start playback in a new thread
            playback_thread = threading.Thread(target=run_playback, daemon=True)
            playback_thread.start()
            play_pause_button.config(text="Pause")
            stop_button.config(state=tk.NORMAL)
            play_pause_button.config(state=tk.NORMAL)
        elif paused:
            pause_unpause_music() # If paused, treat play as unpause

    def pause_unpause_music():
        nonlocal paused
        if paused:
            pygame.mixer.music.unpause()
            paused = False
            status_label.config(text="Playing...")
            play_pause_button.config(text="Pause")
        else:
            pygame.mixer.music.pause()
            paused = True
            status_label.config(text="Paused")
            play_pause_button.config(text="Play")
            
    def stop_music():
        nonlocal playback_thread, paused
        logger.info("Stopping music")
        pygame.mixer.music.stop()
        pygame.mixer.music.unload()
        paused = False 
        playback_thread = None
        status_label.config(text="Stopped")
        play_pause_button.config(text="Play", state=tk.DISABLED)
        stop_button.config(state=tk.DISABLED)


    play_pause_button = ttk.Button(button_frame, text="Play", command=play_music, width=10)
    play_pause_button.pack(side=tk.LEFT, padx=5)
    
    stop_button = ttk.Button(button_frame, text="Stop", command=stop_music, state=tk.DISABLED, width=10)
    stop_button.pack(side=tk.LEFT, padx=5)

    def on_close():
        logger.info("Closing player window")
        stop_music() 
        try:
            # Important: Quit mixer only when completely done
            # If other players might exist, this needs more careful management
            pygame.mixer.quit()
            logger.info("Pygame mixer quit.")
        except Exception as e:
             logger.warning(f"Error quitting pygame mixer: {e}")
        player_window.destroy()

    player_window.protocol("WM_DELETE_WINDOW", on_close)
    
    # Start playing immediately
    play_music()

# --- Video Playback Implementation ---
def play_video(app, address, filename, button, loading_label):
    """Initiates fetching video data and opening it externally."""
    logger.info(f"Video play button clicked for: {filename} ({address})")

    # Disable button and show loading indicator
    if button:
        button.config(state=tk.DISABLED)
    loading_label.config(text="Loading...")
    loading_label.update_idletasks()

    # Run the async fetch in the background
    asyncio.run_coroutine_threadsafe(
        _do_play_video(app, address, filename, button, loading_label),
        app.loop
    )

async def _do_play_video(app, address, filename, button, loading_label):
    """Fetches video data and calls the function to open it externally."""
    video_data = None
    try:
        logger.info(f"Fetching video data for {filename} from {address}")
        # Fetch the video data (assuming public for now)
        # TODO: Add handling for private data if needed
        video_data = await app.client.data_get_public(address)
        logger.info(f"Successfully fetched {len(video_data)} bytes for {filename}")

        # Call the external player function in the main thread
        app.root.after(0, open_external_video_player, app, video_data, filename)

    except Exception as e:
        import traceback
        logger.error(f"Failed to fetch or play video {filename}: {e}\n{traceback.format_exc()}")
        app.root.after(0, messagebox.showerror, "Error", f"Failed to load video: {e}")
    finally:
        # Re-enable button and clear loading indicator in the main thread
        def reset_ui():
            if button:
                button.config(state=tk.NORMAL)
            loading_label.config(text="")
        app.root.after(0, reset_ui)

def open_external_video_player(app, video_data, filename):
    """Saves video data to a temporary file and opens it with the default system player."""
    try:
        # Create a temporary file with the correct extension
        _, ext = os.path.splitext(filename)
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as temp_file:
            temp_file.write(video_data)
            temp_file_path = temp_file.name
        logger.info(f"Video data saved to temporary file: {temp_file_path}")

        # Open the temporary file with the default system application
        if platform.system() == "Windows":
            os.startfile(temp_file_path)
        elif platform.system() == "Darwin": # macOS
            subprocess.run(["open", temp_file_path], check=True)
        else: # Linux and other Unix-like systems
            subprocess.run(["xdg-open", temp_file_path], check=True)
        logger.info(f"Launched default player for: {temp_file_path}")

        # Optional: Clean up the temp file after a delay or when the app closes.
        # For simplicity, we're leaving it; the OS usually cleans temp dirs.

    except Exception as e:
        import traceback
        logger.error(f"Failed to open video in external player: {e}\n{traceback.format_exc()}")
        messagebox.showerror("Error", f"Could not open video player: {e}")