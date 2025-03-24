import asyncio
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from autonomi_client import DataMapChunk
import view

logger = logging.getLogger("MissionCtrl")

async def _retrieve(app, address_input, from_queue=False, return_status=False):
    """
    Retrieve data from the network
    
    Args:
        app: The application instance
        address_input: The address to retrieve data from
        from_queue: Whether this is being called as part of queue processing
        return_status: Whether to return a status indicating success/failure
        
    Returns:
        If return_status is True, returns True for success, False for failure
        Otherwise returns None
    """
    success = False
    
    try:
        data = None
        is_private = False
        is_single_chunk = False
        archive = None

        try:
            data_map_chunk = DataMapChunk.from_hex(address_input)
            data = await app.client.data_get(data_map_chunk)
            is_private = True
            logger.info("Successfully retrieved private data")
        except Exception as private_error:
            logger.info("Not a private data map: %s", private_error)
            try:
                archive = await app.client.archive_get_public(address_input)
                logger.info("Successfully retrieved public archive")
            except Exception as archive_error:
                logger.info("Not a public archive: %s", archive_error)
                try:
                    data = await app.client.data_get_public(address_input)
                    is_single_chunk = True
                    logger.info("Successfully retrieved single public chunk")
                except Exception as chunk_error:
                    logger.error("Retrieval failed for all types: %s", chunk_error)
                    if not from_queue:
                        app.root.after(0, lambda: messagebox.showerror(
                            "Retrieval Failed",
                            f"Couldn't retrieve data from {address_input[:10]}...\nEnsure the address is correct and matches a private or public data chunk or archive."
                        ))
                    return False if return_status else None

        # Show data window and mark as successful
        app.root.after(0, lambda: view.show_data_window(app, data, is_private, archive, is_single_chunk, address_input))
        success = True
    except Exception as e:
        logger.error("Fatal error in _retrieve: %s", e)
        if not from_queue:
            app.root.after(0, lambda err=e: messagebox.showerror("Error", f"Retrieval error: {err}"))
    finally:
        # Only reset processing state if this wasn't called as part of queue processing
        if not from_queue:
            app.is_processing = False
            app.stop_status_animation()
    
    return success if return_status else None

def retrieve_data(app, from_queue=False):
    logger.info("Retrieve Data button clicked")
    app.status_label.config(text="Preparing retrieval...")
    address_input = app.retrieve_entry.get().strip()
    if not address_input or address_input == "Enter a data address (e.g., 0x123...)":
        messagebox.showwarning("Input Error", "Please enter a valid data address (e.g., 0x123...).")
        app.status_label.config(text="Ready")
        return

    app.is_processing = True
    app._current_operation = 'download'
    
    # Only start the animation if not part of queue processing
    if not from_queue:
        app.start_status_animation()
        
    asyncio.run_coroutine_threadsafe(_retrieve(app, address_input, from_queue), app.loop)