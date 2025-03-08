# get.py
import asyncio
import json
import os
import io
import mimetypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from autonomi_client import DataMapChunk
import view

logger = logging.getLogger("MissionCtrl")

def retrieve_data(app):
    logger.info("Retrieve Data button clicked")
    app.status_label.config(text="Preparing retrieval...")
    address_input = app.retrieve_entry.get().strip()
    if not address_input or address_input == "Enter a data address (e.g., 0x123...)":
        messagebox.showwarning("Input Error", "Please enter a valid data address. It should be a long string of letters and numbers (e.g., 0x123...).")
        app.status_label.config(text="Ready")
        return

    app.is_processing = True
    app._current_operation = 'download'
    app.start_status_animation()
    
    async def _retrieve():
        try:
            data = None
            is_private = False
            archive = None
            is_single_chunk = False

            try:
                data_map_chunk = DataMapChunk.from_hex(address_input)
                data = await app.client.data_get(data_map_chunk)
                is_private = True
                logger.info("Successfully retrieved private data")
            except Exception as private_error:
                logger.info("Not a private data map: %s", private_error)
                try:
                    archive = await app.client.archive_get_public(address_input)
                    chunk_addr = list(archive.addresses())[0]
                    data = await app.client.data_get_public(chunk_addr)
                    is_private = False
                    logger.info("Successfully retrieved public archive")
                except Exception as archive_error:
                    logger.info("Not a public archive: %s", archive_error)
                    try:
                        data = await app.client.data_get_public(address_input)
                        is_private = False
                        is_single_chunk = True
                        logger.info("Successfully retrieved single public chunk")
                    except Exception as chunk_error:
                        logger.error("Retrieval failed for all types: %s", chunk_error)
                        app.root.after(0, lambda: messagebox.showerror(
                            "Retrieval Failed",
                            "We couldn’t find your data. Make sure the address is correct and matches a private data map, public archive, or public chunk. Try copying it again."
                        ))
                        app.is_processing = False
                        app.stop_status_animation()
                        return

            app.root.after(0, lambda: view.show_data_window(app, data, is_private, archive, is_single_chunk))
        except Exception as e:
            logger.error("Retrieval failed: %s", e)
            app.root.after(0, lambda: messagebox.showerror("Error", f"Retrieval failed: {e}\nCheck your network connection or the address."))
        finally:
            app.is_processing = False
            app.stop_status_animation()

    asyncio.run_coroutine_threadsafe(_retrieve(), app.loop)

