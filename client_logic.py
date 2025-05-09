# --- client_logic.py ---
# (Based on your client_connect.py, modified for GUI integration)

import asyncio
import socket
import msgpack
import random
import sys
import time
from collections.abc import Callable # For type hinting
from html import escape 

# --- Configuration ---
SERVER_HOST = "csc4026z.link"
SERVER_PORT = 51825
PING_INTERVAL = 25

# --- Protocol Message Types ---
# (Keep all your constants: CONNECT, PING, ERROR, OK, etc.)
CONNECT = 1
PING = 3
CHANNEL_CREATE = 4
CHANNEL_LIST = 5
CHANNEL_INFO = 6
CHANNEL_JOIN = 7
CHANNEL_LEAVE = 8
CHANNEL_MESSAGE = 9
WHOIS = 10
WHOAMI = 11
USER_MESSAGE = 12
SET_USERNAME = 13
USER_LIST = 14
DISCONNECT = 23
ERROR = 20
OK = 21
CONNECT_RESPONSE = 22
PING_RESPONSE = 24
CHANNEL_CREATE_RESPONSE = 25
CHANNEL_LIST_RESPONSE = 26
CHANNEL_INFO_RESPONSE = 27
CHANNEL_JOIN_RESPONSE = 28
CHANNEL_LEFT_RESPONSE = 29
CHANNEL_MESSAGE_RESPONSE = 30
WHOIS_RESPONSE = 31
WHOAMI_RESPONSE = 32
USER_MESSAGE_RESPONSE = 33
SET_USERNAME_RESPONSE = 34
USER_LIST_RESPONSE = 35
SERVER_MESSAGE = 36
SERVER_SHUTDOWN = 37

# --- asyncio UDP Client Protocol (Modified for Signals) ---

class ChatClientProtocol(asyncio.DatagramProtocol):
    # Accepts a 'signals' object (from PyQt) instead of on_con_lost
    def __init__(self, loop, signals: object, shutdown_event: asyncio.Event):
        self.loop = loop
        self.signals = signals # Store the signals object from the GUI
        self.shutdown_event = shutdown_event
        self.transport = None
        self.server_address = (SERVER_HOST, SERVER_PORT)
        self.session_id = None
        self.username = None
        # self.ping_task = None # Ping task is managed externally now
        self.connected_event = asyncio.Event()
        print("ChatClientProtocol Initialized (for GUI)")

    def connection_made(self, transport):
        self.transport = transport
        # Emit signal to update GUI status
        self.signals.status_updated.emit(f"Socket created, connecting to {self.server_address}...")
        self.send_connect()

    def send_connect(self):
        connect_request = {
            'request_type': CONNECT,
            'request_handle': random.randint(0, 2**32 - 1)
        }
        # Emit signal for logging/display in GUI
        self.signals.message_received.emit(f"Sending CONNECT: {connect_request}", "info")
        try:
            bytes_to_send = msgpack.packb(connect_request)
            self.transport.sendto(bytes_to_send)
        except Exception as e:
            self.signals.message_received.emit(f"Error packing/sending CONNECT: {e}", "error")
            self.shutdown_event.set()

    def send_message(self, data_dict):
        if not self.transport or self.transport.is_closing():
            # Emit error to GUI
            self.signals.message_received.emit("Error: Transport not available or closing.", "error")
            return

        if self.session_id is not None and data_dict.get('request_type') != CONNECT:
            data_dict['session'] = self.session_id
        elif data_dict.get('request_type') != CONNECT:
             # Emit warning to GUI
             self.signals.message_received.emit("Warning: Cannot send message requiring session_id before connection is established.", "error")
             return

        if 'request_handle' not in data_dict:
             data_dict['request_handle'] = random.randint(0, 2**32 - 1)

        # Optionally emit sent message to GUI (can be verbose)
        # self.signals.message_received.emit(f"Sending: {data_dict}", "info")
        print(f"Sending (logic): {data_dict}") # Keep console print for debugging logic if needed

        try:
            bytes_to_send = msgpack.packb(data_dict)
            self.transport.sendto(bytes_to_send)
        except Exception as e:
            # Emit error to GUI
            self.signals.message_received.emit(f"Error packing/sending message: {data_dict} - {e}", "error")
            if isinstance(e, msgpack.exceptions.PackException):
                 self.shutdown_event.set()

    def datagram_received(self, data, addr):
        """Decodes messages and emits signals to the GUI."""
        try:
            decoded_message = msgpack.unpackb(data, raw=False)
            # Optionally log raw received data to console for debugging
            # print(f"\nDecoded (logic): {decoded_message}")

            response_type = decoded_message.get('response_type')
            response_handle = decoded_message.get('response_handle')
            msg_text = ""
            msg_tag = "info" # Default tag

            # --- Handle different message types by emitting signals ---

            if response_type == CONNECT_RESPONSE:
                self.session_id = decoded_message.get('session')
                self.username = decoded_message.get('username')
                # Emit specific connection state signal for GUI
                self.signals.connection_state_changed.emit("connected", {
                    "username": self.username,
                    "session": self.session_id,
                    "message": decoded_message.get('message')
                })
                self.connected_event.set() # Allow ping task to start

            elif response_type == PING_RESPONSE:
                pass # No GUI update needed for successful ping response

            elif response_type == OK:
                 msg_text = f"OK (Request Handle: {response_handle})"
                 msg_tag = "info"

            elif response_type == ERROR:
                # Let the GUI slot format the "ERROR:" prefix
                msg_text = f"{decoded_message.get('error')} (Handle: {response_handle})"
                msg_tag = "error"

            elif response_type == CHANNEL_LIST_RESPONSE:
                channels = decoded_message.get('channels', [])
                next_page = decoded_message.get('next_page', False)
                msg_text = "--- Channel List ---\n"
                if channels: msg_text += "\n".join([f"- {ch}" for ch in channels])
                else: msg_text += "(No channels found)"
                if next_page: msg_text += "\n(More channels available... use /channels <offset>)"
                msg_text += "\n--------------------"
                msg_tag = "info"

            elif response_type == USER_LIST_RESPONSE:
                users = decoded_message.get('users', [])
                next_page = decoded_message.get('next_page', False)
                msg_text = "--- User List ---\n"
                if users: msg_text += "\n".join([f"- {user}" for user in users])
                else: msg_text += "(No users found)"
                if next_page: msg_text += "\n(More users available... use /users <offset>)"
                msg_text += "\n-----------------"
                msg_tag = "info"

            elif response_type == CHANNEL_MESSAGE_RESPONSE:
                channel = decoded_message.get('channel')
                sender = decoded_message.get('username')
                if sender == self.username:
                    msg_text = f"[You] /say {channel} {decoded_message.get('message')}"
                    msg_tag = "own_message"
                else:
                    msg_text = f"[User] <{sender}> {decoded_message.get('message')}"
                    msg_tag = "channel"


            elif response_type == USER_MESSAGE_RESPONSE:
                 sender = decoded_message.get('from_username')
                 msg_text = f"[DM] <{sender}> {decoded_message.get('message')}"
                 msg_tag = "dm"

            elif response_type == SERVER_MESSAGE:
                msg_text = f"[Server] {decoded_message.get('message')}"
                msg_tag = "server"


            elif response_type == SERVER_SHUTDOWN:
                 # Emit specific state change signal
                 self.signals.connection_state_changed.emit("shutdown", {})
                 self.shutdown_event.set() # Also trigger internal shutdown

            elif response_type == CHANNEL_JOIN_RESPONSE:
                user = decoded_message.get('username')
                channel = decoded_message.get('channel')
                desc = decoded_message.get('description')
                if response_handle: # Our request
                    msg_text = f"Successfully joined channel '{channel}'"
                    if desc: msg_text += f"\n  Description: {desc}"
                else: # Someone else joined
                    msg_text = f"User '{user}' joined channel '{channel}'"
                msg_tag = "info"

            elif response_type == CHANNEL_LEFT_RESPONSE:
                user = decoded_message.get('username')
                channel = decoded_message.get('channel')
                if response_handle: # Our request
                    msg_text = f"Successfully left channel '{channel}'"
                else: # Someone else left
                    msg_text = f"User '{user}' left channel '{channel}'"
                msg_tag = "info"

            elif response_type == CHANNEL_CREATE_RESPONSE:
                 channel = decoded_message.get('channel')
                 desc = decoded_message.get('description')
                 msg_text = f"Successfully created channel '{channel}'"
                 if desc: msg_text += f"\n  Description: {desc}"
                 msg_tag = "info"

            elif response_type == CHANNEL_INFO_RESPONSE:
                 channel = decoded_message.get('channel')
                 desc = decoded_message.get('description')
                 members = decoded_message.get('members', [])
                 msg_text = f"--- Channel Info: {channel} ---\n"
                 msg_text += f"  Description: {desc if desc else '(None)'}\n"
                 msg_text += f"  Members ({len(members)}):\n"
                 if members: msg_text += "\n".join([f"    - {member}" for member in members])
                 else: msg_text += "    (No members)"
                 msg_text += "\n-----------------------------"
                 msg_tag = "info"

            elif response_type == WHOIS_RESPONSE:
                 uname = decoded_message.get('username')
                 status = decoded_message.get('status')
                 channels = decoded_message.get('channels', [])
                 transport_type = decoded_message.get('transport')
                 pub_key = decoded_message.get('wireguard_public_key')
                 msg_text = f"--- User Info: {uname} ---\n"
                 msg_text += f"  Status: {status}\n"
                 msg_text += f"  Transport: {transport_type}\n"
                 if pub_key: msg_text += f"  WG Public Key: {pub_key}\n"
                 msg_text += f"  Channels ({len(channels)}):\n"
                 if channels: msg_text += "\n".join([f"    - {ch}" for ch in channels])
                 else: msg_text += "    (Not in any channels)"
                 msg_text += "\n-------------------------"
                 msg_tag = "info"

            elif response_type == WHOAMI_RESPONSE:
                 self.username = decoded_message.get('username') # Update local state
                 msg_text = f"Your current username is: {self.username}"
                 msg_tag = "info"
                 # Emit signals to update GUI title/status
                 self.signals.title_updated.emit(f"PyQt5 Async Chat - {self.username}@{SERVER_HOST}")
                 self.signals.status_updated.emit(f"Connected as {self.username}")

            elif response_type == SET_USERNAME_RESPONSE:
                 old_name = decoded_message.get('old_username')
                 new_name = decoded_message.get('new_username')
                 if response_handle: # Our request succeeded
                     msg_text = f"Username successfully changed from '{old_name}' to '{new_name}'"
                     self.username = new_name # Update local state
                     # Emit signals to update GUI title/status
                     self.signals.title_updated.emit(f"PyQt5 Async Chat - {self.username}@{SERVER_HOST}")
                     self.signals.status_updated.emit(f"Connected as {self.username}")
                 else: # Someone else changed their name
                     msg_text = f"User '{old_name}' changed their name to '{new_name}'"
                 msg_tag = "info"

            else:
                # Catch-all for unexpected message types
                msg_text = f"Received unhandled message type: {response_type}\nData: {decoded_message}"
                msg_tag = "error"

            # --- Emit the final signal to the GUI ---
            if msg_text:
                self.signals.message_received.emit(msg_text, msg_tag)

        except msgpack.exceptions.UnpackException as e:
            self.signals.message_received.emit(f"Failed to decode server message: {e} - Data: {data.hex()}", "error")
        except Exception as e:
            self.signals.message_received.emit(f"Error processing received datagram: {e}", "error")

        # NOTE: Removed console prompt redisplay logic


    def error_received(self, exc):
        """Called when a send or receive operation raises an OSError."""
        # Emit error to GUI
        self.signals.message_received.emit(f"Socket error received: {exc}", "error")
        # Consider triggering shutdown on certain errors
        # self.shutdown_event.set()

    def connection_lost(self, exc):
        """Called when the connection is lost or closed."""
        print("Connection lost (logic).") # Keep console log for debugging
        # Emit signal to GUI, only if not already shutting down via server msg
        if not self.shutdown_event.is_set():
            self.signals.connection_state_changed.emit("disconnected", {})
        self.shutdown_event.set() # Ensure shutdown is signalled


# --- Background Tasks ---

async def send_pings(protocol: ChatClientProtocol):
    """Periodically sends PING messages. Assumes protocol has 'signals'."""
    while not protocol.shutdown_event.is_set():
        try:
            # Wait until the initial CONNECT response has been processed
            # Use wait_for to handle potential connection delays/failures
            await asyncio.wait_for(protocol.connected_event.wait(), timeout=PING_INTERVAL + 10)

            if protocol.session_id: # Only send PING if we have a session
                ping_request = {'request_type': PING}
                protocol.send_message(ping_request)

            await asyncio.sleep(PING_INTERVAL)

        except asyncio.TimeoutError:
            # If we time out waiting for the connection, signal error and stop
            if not protocol.connected_event.is_set():
                 protocol.signals.message_received.emit("Connection timeout - No CONNECT_RESPONSE received.", "error")
                 protocol.shutdown_event.set()
                 break
            # If already connected, timeout just means loop continues after sleep interval
        except asyncio.CancelledError:
            print("Ping task cancelled.")
            break
        except Exception as e:
            # Emit error to GUI
            protocol.signals.message_received.emit(f"Error in PING task: {e}", "error")
            # Avoid busy-looping on error, wait before retrying
            await asyncio.sleep(PING_INTERVAL)


# --- Command Parsing Function (extracted from handle_user_input) ---

def parse_and_send_command(message: str, protocol: ChatClientProtocol):
    """
    Parses user input string and sends the appropriate message via the protocol.
    Emits feedback/errors via protocol.signals.
    """
    if not protocol or not protocol.transport or protocol.transport.is_closing():
         protocol.signals.message_received.emit("Cannot send: Not connected.", "error")
         return

    # Emit the user's own input back to the GUI for display
    # protocol.signals.message_received.emit(message, "own_message")
    protocol.signals.message_received.emit(f"[You] {escape(message)}", "own_message")


    request = None
    usage_error = None

    # --- Command Parsing Logic (from your original handle_user_input) ---
    if message.lower() == "/quit":
        protocol.signals.message_received.emit("Quit command received. Shutting down.", "info")
        protocol.shutdown_event.set() # Signal shutdown
        return # Don't send /quit to server

    elif message.lower().startswith("/channels"):
         parts = message.split()
         request = {'request_type': CHANNEL_LIST}
         if len(parts) == 2:
             try: request['offset'] = int(parts[1])
             except ValueError: usage_error = "Usage: /channels [optional_offset_number]"
         elif len(parts) > 2: usage_error = "Usage: /channels [optional_offset_number]"

    elif message.startswith("/create "):
         parts = message.split(" ", 2)
         if len(parts) >= 2:
             request = {'request_type': CHANNEL_CREATE, 'channel': parts[1]}
             if len(parts) == 3: request['description'] = parts[2]
         else: usage_error = "Usage: /create <channel_name> [optional description]"

    elif message.startswith("/info channel "):
         parts = message.split(" ", 2)
         if len(parts) == 3: request = {'request_type': CHANNEL_INFO, 'channel': parts[2]}
         else: usage_error = "Usage: /info channel <channel_name>"

    elif message.startswith("/join "):
         parts = message.split(" ", 1)
         if len(parts) == 2: request = {'request_type': CHANNEL_JOIN, 'channel': parts[1]}
         else: usage_error = "Usage: /join <channel_name>"

    elif message.startswith("/leave "):
         parts = message.split(" ", 1)
         if len(parts) == 2: request = {'request_type': CHANNEL_LEAVE, 'channel': parts[1]}
         else: usage_error = "Usage: /leave <channel_name>"

    elif message.startswith("/say"):
         parts = message.split(" ", 2)
         if len(parts) == 3:
            request = {'request_type': CHANNEL_MESSAGE, 'channel': parts[1], 'message': parts[2]}
         elif len(parts) == 2:
            usage_error = "Missing message. Usage: /say <channel_name> <message>"
         else:
            usage_error = "Usage: /say <channel_name> <message>"

    elif message.lower().startswith("/users"):
         parts = message.split()
         request = {'request_type': USER_LIST}
         if len(parts) == 2:
             try: request['offset'] = int(parts[1])
             except ValueError: usage_error = "Usage: /users [optional_offset_number]"
         elif len(parts) > 2: usage_error = "Usage: /users [optional_offset_number]"

    elif message.startswith("/whois "):
         parts = message.split(" ", 1)
         if len(parts) == 2: request = {'request_type': WHOIS, 'username': parts[1]}
         else: usage_error = "Usage: /whois <username>"

    elif message.lower() == "/whoami":
         request = {'request_type': WHOAMI}

    elif message.startswith("/dm "):
         parts = message.split(" ", 2)
         if len(parts) == 3: request = {'request_type': USER_MESSAGE, 'to_username': parts[1], 'message': parts[2]}
         else: usage_error = "Usage: /dm <username> <message>"

    elif message.startswith("/setuser "):
         parts = message.split(" ", 1)
         if len(parts) == 2: request = {'request_type': SET_USERNAME, 'username': parts[1]}
         else: usage_error = "Usage: /setuser <new_username>"
    
    elif message.lower() == "/help":
        help_text = (
            "--- Available Commands ---\n"
            "/users                       List all users\n"
            "/channels                    List available channels\n"
            "/join <channel>             Join a channel\n"
            "/say <channel> <message>    Send a message to a channel\n"
            "/dm <user> <message>        Send a private message\n"
            "/whoami                     Show your current username\n"
            "/whois <username>           Get info about a user\n"
            "/setuser <new_username>     Change your username\n"
            "/quit                       Exit the chat\n"
            "/help                       Show this help message\n"
            "---------------------------"
        )
        help_html = help_text.replace("\n", "<br>")
        protocol.signals.message_received.emit(help_html, "info_html")
        return


    # --- Unknown Command or Default Behavior ---
    else:
        if message.startswith("/"):
            usage_error = f"Unknown command: {message}"
        else:
            # Default behavior: Require explicit /say command
            usage_error = "Cannot send message directly. Use /say <channel> <message> or a known command."

    # --- Handle results ---
    if usage_error:
        # Emit usage error back to GUI
        protocol.signals.message_received.emit(usage_error, "error")
    elif request:
        # Send the valid request
        protocol.send_message(request)


# NOTE: Removed handle_user_input, main(), and if __name__ == "__main__"
# This file is now intended to be imported as a module.