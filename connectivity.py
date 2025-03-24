import asyncio
import logging
from autonomi_client import Client

logger = logging.getLogger("MissionCtrl")

# Shared connection status
connected = False
is_checking = False
last_quote = None

async def check_connection_with_quote(app, first_check=False):
    """Test connectivity by requesting a small quote"""
    global connected, is_checking, last_quote
    
    if is_checking:
        return connected
    
    is_checking = True
    
    # Only update UI for first check or periodic checks (not during operations)
    if first_check or not app.is_processing:
        if first_check:
            app.connection_label.config(text="Network: Testing connection")
            if hasattr(app, 'conn_dot'):
                app.conn_dot.config(foreground="#FFA500")
    
    try:
        # Use a very small 3-byte test data
        test_data = b'ABC'
        
        # Request quote with a short timeout
        try:
            estimated_cost = await asyncio.wait_for(
                app.client.data_cost(test_data),
                timeout=120
            )
            
            # Store last successful quote
            last_quote = estimated_cost
            
            # Update connection status
            connected = True
            
            # Update UI if this was first check or a periodic check
            if first_check or not app.is_processing:
                app.connection_label.config(text="Network: Connected to Autonomi")
                if hasattr(app, 'conn_dot'):
                    app.conn_dot.config(foreground="#4CAF50")  # Green for connected
                    # Enable pulse animation
                    if not hasattr(app, 'connection_animation_running') or not app.connection_animation_running:
                        app.connection_animation_running = True
                # Update status label with successful connection
                if hasattr(app, 'status_label'):
                    app.status_label.config(text="Ready")
                
            logger.info(f"Connection test successful, quote received: {estimated_cost} ANT")
            return True
            
        except asyncio.TimeoutError:
            logger.warning("Connection test timed out")
            connected = False
            if first_check or not app.is_processing:
                app.connection_label.config(text="Network: Disconnected")
                if hasattr(app, 'conn_dot'):
                    app.conn_dot.config(foreground="#F44336")
                    app.connection_animation_running = False
                if hasattr(app, 'status_label'):
                    app.status_label.config(text="Connection error: Network timeout - Please check your internet connection")
            return False
            
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in connection test: {error_msg}")
        connected = False
        
        user_msg = "Connection error"
        if "Not enough node quotes" in error_msg:
            user_msg += ": Network has insufficient nodes available"
        elif "timeout" in error_msg.lower():
            user_msg += ": Network timeout"
        elif "connection refused" in error_msg.lower():
            user_msg += ": Network connection refused"
        else:
            # Truncate long error messages
            if len(error_msg) > 80:
                error_msg = error_msg[:77] + "..."
            user_msg += f": {error_msg}"
        
        if first_check or not app.is_processing:
            app.connection_label.config(text="Network: Disconnected")
            if hasattr(app, 'conn_dot'):
                app.conn_dot.config(foreground="#F44336")
                app.connection_animation_running = False
            if hasattr(app, 'status_label'):
                app.status_label.config(text=user_msg)
        return False
    finally:
        is_checking = False

def schedule_connection_check(app, first_check=False):
    """Schedule a connection check without blocking"""
    asyncio.run_coroutine_threadsafe(check_connection_with_quote(app, first_check), app.loop)
    
    # Schedule next check in 5 minutes if not first check
    if not first_check:
        app.root.after(300000, lambda: schedule_connection_check(app))  # 5 minutes
    
def get_last_quote():
    """Return the last successful quote received"""
    return last_quote

def is_connected():
    """Return current connection status"""
    return connected 