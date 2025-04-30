import asyncio
import socket
import msgpack
import random
import sys
import time

# --- Configuration ---
SERVER_HOST = "csc4026z.link"
SERVER_PORT = 51825  # Cleartext port
PING_INTERVAL = 25  # Seconds

# --- Protocol Message Types (from PDF) ---
# Requests (Client -> Server)
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

# Responses (Server -> Client)
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

# --- asyncio UDP Client Protocol ---

class ChatClientProtocol(asyncio.DatagramProtocol):
    # How its been implemented: This class uses asyncio.DatagramProtocol
    # to handle UDP communication asynchronously. It manages state like
    # session_id, transport, and handles incoming/outgoing messages.
    def __init__(self, loop, on_con_lost, shutdown_event):
        self.loop = loop
        self.on_con_lost = on_con_lost # Future to signal connection loss/shutdown
        self.shutdown_event = shutdown_event # Event to signal shutdown requested
        self.transport = None
        # Store server address tuple for potential reference, though not used in sendto with remote_addr
        self.server_address = (SERVER_HOST, SERVER_PORT)
        # *** Store the Session ID ***
        # How its been implemented: Initialized to None, set in datagram_received
        # upon successful CONNECT_RESPONSE.
        self.session_id = None
        self.username = None
        self.ping_task = None
        self.input_task = None
        # How its been implemented: Used to signal background tasks (ping, input)
        # that the initial connection handshake is complete.
        self.connected_event = asyncio.Event()

    def connection_made(self, transport):
        """Called when the UDP socket is ready."""
        self.transport = transport
        # Note: transport.get_extra_info('peername') would give the remote_addr if needed
        print(f"Socket created, default destination set to {self.server_address}...")
        # Send the initial CONNECT message
        self.send_connect()

    def send_connect(self):
        """Sends the initial CONNECT request."""
        connect_request = {
            'request_type': CONNECT,
            'request_handle': random.randint(0, 2**32 - 1)
        }
        print(f"Sending CONNECT request: {connect_request}")
        try:
            bytes_to_send = msgpack.packb(connect_request)
            # *** FIX ***
            # How its been implemented: Since remote_addr was used in create_datagram_endpoint,
            # we call sendto with only the data. The transport knows the destination.
            self.transport.sendto(bytes_to_send)
        except Exception as e:
            # This error handling remains the same
            print(f"Error packing/sending CONNECT message: {e}")
            self.shutdown_event.set() # Signal shutdown on critical error

    def send_message(self, data_dict):
        """Packs and sends a message dictionary to the server."""
        if not self.transport or self.transport.is_closing():
            print("Error: Transport not available or closing.")
            return

        # *** Use the Session ID ***
        # How its been implemented: Checks if session_id exists and the message
        # isn't CONNECT, then adds the stored session_id to the dictionary.
        if self.session_id is not None and data_dict.get('request_type') != CONNECT:
            data_dict['session'] = self.session_id
        elif data_dict.get('request_type') != CONNECT:
             print("Warning: Cannot send message requiring session_id before connection is established.")
             return # Don't send messages needing session before we have one

        # Always add a request handle (server might ignore it for some types)
        if 'request_handle' not in data_dict:
             data_dict['request_handle'] = random.randint(0, 2**32 - 1)

        print(f"Sending: {data_dict}")
        try:
            bytes_to_send = msgpack.packb(data_dict)
            # *** FIX ***
            # How its been implemented: Same reason as send_connect - transport is "connected".
            # Send data to the default remote_addr set during endpoint creation.
            self.transport.sendto(bytes_to_send)
        except Exception as e:
            # This error handling remains the same
            print(f"Error packing/sending message: {data_dict} - {e}")
            if isinstance(e, msgpack.exceptions.PackException):
                 self.shutdown_event.set()


    def datagram_received(self, data, addr):
        """Called when a datagram is received from the server."""
        # *** Implement Response/Message Handling ***
        # How its been implemented: This method is the central point for handling
        # all incoming messages. It decodes MessagePack and uses an if/elif
        # structure based on 'response_type' to take appropriate action.
        # print(f"\nReceived raw data from {addr}: {data.hex()}") # Show raw hex (optional debug)
        try:
            decoded_message = msgpack.unpackb(data, raw=False)
            print(f"\nDecoded: {decoded_message}") # Print decoded message

            response_type = decoded_message.get('response_type')
            response_handle = decoded_message.get('response_handle') # May be None

            # --- Handle different message types ---

            if response_type == CONNECT_RESPONSE:
                # *** Store the Session ID (Implementation Detail) ***
                self.session_id = decoded_message.get('session')
                self.username = decoded_message.get('username')
                print("\n--------------------------------------------------")
                print(f"Successfully connected!")
                print(f"  Session ID: {self.session_id}") # Log stored ID
                print(f"  Assigned Username: {self.username}")
                print(f"  Message: {decoded_message.get('message')}")
                print("--------------------------------------------------")
                print("Type commands starting with '/' or messages to send.")
                print("e.g., /users, /channels, /say <channel> <message>, /quit")
                # Signal that connection is complete and start background tasks
                self.connected_event.set() # Allow ping/input tasks to proceed

            elif response_type == PING_RESPONSE:
                # print(f"Received PONG (handle: {response_handle})") # Optional debug
                pass # PING successful

            elif response_type == OK:
                 print(f"Received OK (handle: {response_handle})")
                 # Indicates success for requests like SET_USERNAME, CHANNEL_CREATE etc.

            elif response_type == ERROR:
                print(f"!!! SERVER ERROR: {decoded_message.get('error')} (handle: {response_handle})")

            elif response_type == CHANNEL_LIST_RESPONSE:
                # Handles paginated channel list response
                channels = decoded_message.get('channels', [])
                next_page = decoded_message.get('next_page', False)
                print("--- Channel List ---")
                if channels:
                    for channel in channels:
                        print(f"- {channel}")
                else:
                    print("(No channels found)")
                if next_page:
                    print("(More channels available...)") # Indication for user
                print("--------------------")

            elif response_type == USER_LIST_RESPONSE:
                # Handles paginated user list response
                users = decoded_message.get('users', [])
                next_page = decoded_message.get('next_page', False)
                print("--- User List ---")
                if users:
                    for user in users:
                        print(f"- {user}")
                else:
                    print("(No users found)")
                if next_page:
                    print("(More users available...)") # Indication for user
                print("-----------------")

            elif response_type == CHANNEL_MESSAGE_RESPONSE:
                # Handles messages sent by others in channels we are in (unsolicited)
                print(f"\n[{decoded_message.get('channel')}] <{decoded_message.get('username')}> {decoded_message.get('message')}")

            elif response_type == USER_MESSAGE_RESPONSE:
                 # Handles direct messages sent by others (unsolicited)
                 print(f"\n<DM from {decoded_message.get('from_username')}> {decoded_message.get('message')}")

            elif response_type == SERVER_MESSAGE:
                 # Handles broadcast messages from the server admin (unsolicited)
                 print(f"\n*** SERVER BROADCAST: {decoded_message.get('message')} ***")

            elif response_type == SERVER_SHUTDOWN:
                 # Handles server shutdown notification (unsolicited)
                 print("\n!!! Server is shutting down !!!")
                 self.shutdown_event.set() # Trigger client shutdown

            elif response_type == CHANNEL_JOIN_RESPONSE:
                # Handles notifications about users joining channels (can be solicited or unsolicited)
                user = decoded_message.get('username')
                channel = decoded_message.get('channel')
                desc = decoded_message.get('description') # Also included
                if response_handle: # It was our request that succeeded
                    print(f"Successfully joined channel '{channel}'")
                    if desc: print(f"  Description: {desc}")
                else: # Someone else joined a channel we are in
                    print(f"User '{user}' joined channel '{channel}'")

            elif response_type == CHANNEL_LEFT_RESPONSE:
                # Handles notifications about users leaving channels (can be solicited or unsolicited)
                user = decoded_message.get('username')
                channel = decoded_message.get('channel')
                if response_handle: # It was our request that succeeded
                    print(f"Successfully left channel '{channel}'")
                else: # Someone else left a channel we are in
                    print(f"User '{user}' left channel '{channel}'")

            elif response_type == CHANNEL_CREATE_RESPONSE:
                 # Response to our /create request
                 channel = decoded_message.get('channel')
                 desc = decoded_message.get('description')
                 print(f"Successfully created channel '{channel}'")
                 if desc: print(f"  Description: {desc}")

            elif response_type == CHANNEL_INFO_RESPONSE:
                 # Response to our /info channel request
                 channel = decoded_message.get('channel')
                 desc = decoded_message.get('description')
                 members = decoded_message.get('members', [])
                 print(f"--- Channel Info: {channel} ---")
                 print(f"  Description: {desc if desc else '(None)'}")
                 print(f"  Members ({len(members)}):")
                 if members:
                     for member in members: print(f"    - {member}")
                 else:
                     print("    (No members - should not happen if you are in it!)")
                 print("-----------------------------")

            elif response_type == WHOIS_RESPONSE:
                 # Response to our /whois request
                 uname = decoded_message.get('username')
                 status = decoded_message.get('status')
                 channels = decoded_message.get('channels', [])
                 transport_type = decoded_message.get('transport')
                 pub_key = decoded_message.get('wireguard_public_key')
                 print(f"--- User Info: {uname} ---")
                 print(f"  Status: {status}")
                 print(f"  Transport: {transport_type}")
                 if pub_key: print(f"  WG Public Key: {pub_key}")
                 print(f"  Channels ({len(channels)}):")
                 if channels:
                     for ch in channels: print(f"    - {ch}")
                 else:
                     print("    (Not in any channels)")
                 print("-------------------------")

            elif response_type == WHOAMI_RESPONSE:
                 # Response to our /whoami request
                 print(f"Your current username is: {decoded_message.get('username')}")
                 # Update local state if needed, though server is source of truth
                 self.username = decoded_message.get('username')

            elif response_type == SET_USERNAME_RESPONSE:
                 # Response to our /setuser request (can also be unsolicited if someone else changes)
                 old_name = decoded_message.get('old_username')
                 new_name = decoded_message.get('new_username')
                 if response_handle: # Our request succeeded
                     print(f"Username successfully changed from '{old_name}' to '{new_name}'")
                     self.username = new_name # Update local state
                 else: # Someone else changed their name
                     print(f"User '{old_name}' changed their name to '{new_name}'")

            else:
                # Catch-all for unexpected message types
                print(f"Received unhandled message type: {response_type}")

        except msgpack.exceptions.UnpackException as e:
            print(f"Failed to decode server message: {e} - Data: {data.hex()}")
        except Exception as e:
            print(f"Error processing received datagram: {e}")

        # Ensure prompt is redisplayed after handling a message, unless shutting down
        if not self.shutdown_event.is_set():
            print("> ", end='', flush=True)


    def error_received(self, exc):
        """Called when a send or receive operation raises an OSError."""
        print(f"Socket error received: {exc}")
        # Consider triggering shutdown on certain errors
        # self.shutdown_event.set()

    def connection_lost(self, exc):
        """Called when the connection is lost or closed."""
        print("Socket closed.")
        # Signal that the connection is lost
        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)
        self.shutdown_event.set() # Ensure shutdown is signalled


# --- Background Tasks ---

async def send_pings(protocol):
    """Periodically sends PING messages to keep the connection alive."""
    # *** Implement PING ***
    # How its been implemented: Runs as a separate asyncio task. Waits for
    # the connection to be established (connected_event), then periodically
    # calls protocol.send_message with a PING request type.
    # print("Starting PING task...") # Optional debug
    while not protocol.shutdown_event.is_set():
        try:
            # Wait until the initial CONNECT response has been processed
            await asyncio.wait_for(protocol.connected_event.wait(), timeout=None)

            if protocol.session_id: # Only send PING if we have a session
                ping_request = {
                    'request_type': PING
                    # request_handle and session_id are added by send_message
                }
                protocol.send_message(ping_request)
            # else:
                # print("PING: Not connected yet, skipping PING.") # Optional debug

            # Wait for the specified interval before sending the next PING
            await asyncio.sleep(PING_INTERVAL)
        except asyncio.CancelledError:
            # print("PING task cancelled.") # Optional debug
            break # Exit loop if task is cancelled
        except Exception as e:
            print(f"Error in PING task: {e}")
            # Avoid busy-looping on error, wait before retrying
            await asyncio.sleep(PING_INTERVAL)


async def handle_user_input(protocol):
    """Handles user input from the console."""
    # *** Implement User Input Handling ***
    # How its been implemented: Runs as a separate asyncio task. Uses
    # loop.run_in_executor to avoid blocking the event loop with stdin.
    # Parses simple commands and calls protocol.send_message accordingly.
    # print("Starting user input handler...") # Optional debug
    loop = asyncio.get_running_loop()

    while not protocol.shutdown_event.is_set():
        try:
            # Wait until connected before prompting for input
            await asyncio.wait_for(protocol.connected_event.wait(), timeout=None)

            # Run blocking input() in a separate thread via executor
            # Display prompt before blocking call
            print("> ", end='', flush=True)
            message = await loop.run_in_executor(
                None, sys.stdin.readline)
            message = message.strip() # Remove newline and surrounding whitespace

            if protocol.shutdown_event.is_set(): # Check again after blocking call
                break

            if not message:
                continue # Ignore empty input

            # --- Command Parsing ---
            if message.lower() == "/quit":
                print("Quit command received. Shutting down.")
                protocol.shutdown_event.set()
                break # Exit input loop

            # *** Implement Other Message Types (Examples) ***
            # How its been implemented: Simple command parsing checks for known
            # commands, constructs the appropriate request dictionary, and
            # calls protocol.send_message.

            # --- Channel Commands ---
            elif message.lower().startswith("/channels"):
                 # Handles /channels [offset]
                 parts = message.split()
                 request = {'request_type': CHANNEL_LIST}
                 if len(parts) == 2:
                     try:
                         offset = int(parts[1])
                         request['offset'] = offset
                     except ValueError:
                         print("Usage: /channels [optional_offset_number]")
                         continue # Skip sending if offset is invalid
                 elif len(parts) > 2:
                     print("Usage: /channels [optional_offset_number]")
                     continue
                 protocol.send_message(request)

            elif message.startswith("/create "):
                 # Handles /create <channel> [description]
                 parts = message.split(" ", 2)
                 if len(parts) >= 2:
                     channel = parts[1]
                     description = parts[2] if len(parts) == 3 else None
                     request = {'request_type': CHANNEL_CREATE, 'channel': channel}
                     if description:
                         request['description'] = description
                     protocol.send_message(request)
                 else:
                     print("Usage: /create <channel_name> [optional description]")

            elif message.startswith("/info channel "):
                 # Handles /info channel <channel>
                 parts = message.split(" ", 2)
                 if len(parts) == 3:
                     channel = parts[2]
                     request = {'request_type': CHANNEL_INFO, 'channel': channel}
                     protocol.send_message(request)
                 else:
                     print("Usage: /info channel <channel_name>")

            elif message.startswith("/join "):
                 # Handles /join <channel>
                 parts = message.split(" ", 1)
                 if len(parts) == 2:
                     channel = parts[1]
                     request = {'request_type': CHANNEL_JOIN, 'channel': channel}
                     protocol.send_message(request)
                 else:
                     print("Usage: /join <channel_name>")

            elif message.startswith("/leave "):
                 # Handles /leave <channel>
                 parts = message.split(" ", 1)
                 if len(parts) == 2:
                     channel = parts[1]
                     request = {'request_type': CHANNEL_LEAVE, 'channel': channel}
                     protocol.send_message(request)
                 else:
                     print("Usage: /leave <channel_name>")

            elif message.startswith("/say "):
                 # Handles /say <channel> <message>
                 parts = message.split(" ", 2)
                 if len(parts) == 3:
                     channel, chat_message = parts[1], parts[2]
                     request = {
                         'request_type': CHANNEL_MESSAGE,
                         'channel': channel,
                         'message': chat_message
                     }
                     protocol.send_message(request)
                 else:
                     print("Usage: /say <channel_name> <message>")

            # --- User Commands ---
            elif message.lower().startswith("/users"):
                 # Handles /users [offset]
                 parts = message.split()
                 request = {'request_type': USER_LIST}
                 if len(parts) == 2:
                     try:
                         offset = int(parts[1])
                         request['offset'] = offset
                     except ValueError:
                         print("Usage: /users [optional_offset_number]")
                         continue # Skip sending if offset is invalid
                 elif len(parts) > 2:
                     print("Usage: /users [optional_offset_number]")
                     continue
                 protocol.send_message(request)

            elif message.startswith("/whois "):
                 # Handles /whois <username>
                 parts = message.split(" ", 1)
                 if len(parts) == 2:
                     username_to_query = parts[1]
                     request = {'request_type': WHOIS, 'username': username_to_query}
                     protocol.send_message(request)
                 else:
                     print("Usage: /whois <username>")

            elif message.lower() == "/whoami":
                 # Handles /whoami
                 request = {'request_type': WHOAMI}
                 protocol.send_message(request)

            elif message.startswith("/dm "):
                 # Handles /dm <username> <message>
                 parts = message.split(" ", 2)
                 if len(parts) == 3:
                     to_username, dm_message = parts[1], parts[2]
                     request = {
                         'request_type': USER_MESSAGE,
                         'to_username': to_username,
                         'message': dm_message
                     }
                     protocol.send_message(request)
                 else:
                     print("Usage: /dm <username> <message>")

            elif message.startswith("/setuser "):
                 # Handles /setuser <username>
                 parts = message.split(" ", 1)
                 if len(parts) == 2:
                     new_username = parts[1]
                     request = {'request_type': SET_USERNAME, 'username': new_username}
                     protocol.send_message(request)
                 else:
                     print("Usage: /setuser <new_username>")

            # --- Unknown Command ---
            else:
                # Handle unknown commands or potentially default behavior
                if message.startswith("/"):
                    print(f"Unknown command: {message}")
                else:
                    # Default behavior could be sending to a 'current' channel if implemented
                    print("Cannot send message directly. Use /say <channel> <message>")
                    print("Or use a known command like /users, /channels, /quit")


        except asyncio.CancelledError:
            # print("Input task cancelled.") # Optional debug
            break
        except Exception as e:
            print(f"Error reading user input: {e}")
            # If stdin closes (e.g., piped input ends), shut down
            if isinstance(e, EOFError):
                 print("Input stream closed.")
                 protocol.shutdown_event.set()
                 break


# --- Main Execution ---

async def main():
    # *** Implement asyncio ***
    # How its been implemented: The main function sets up the asyncio event loop,
    # creates the datagram endpoint, starts the background tasks (ping, input),
    # and manages the main lifecycle, waiting for a shutdown signal.
    loop = asyncio.get_running_loop()
    # Future to signal when connection_lost is called
    on_con_lost = loop.create_future()
    # Event to coordinate shutdown across tasks
    shutdown_event = asyncio.Event()

    print(f"Attempting to connect to UDP {SERVER_HOST}:{SERVER_PORT}")

    try:
        # Create the UDP endpoint and the protocol instance
        # Using remote_addr connects the socket for default send destination
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ChatClientProtocol(loop, on_con_lost, shutdown_event),
            remote_addr=(SERVER_HOST, SERVER_PORT))

    except OSError as e:
        print(f"Error creating socket/endpoint: {e}")
        print("Check network connection and server address/port.")
        return # Exit if endpoint creation fails
    except Exception as e:
        print(f"Unexpected error during endpoint creation: {e}")
        return

    # Start background tasks for PING and user input
    # These tasks run concurrently with the main loop
    ping_task = asyncio.create_task(send_pings(protocol))
    input_task = asyncio.create_task(handle_user_input(protocol))

    try:
        # Wait until shutdown is signalled (by user /quit, server shutdown, error)
        await shutdown_event.wait()
        print("Shutdown signal received, cleaning up...")

    finally:
        # --- Cleanup ---
        print("Cancelling background tasks...")
        # Cancel tasks gracefully
        if ping_task and not ping_task.done():
            ping_task.cancel()
        if input_task and not input_task.done():
            input_task.cancel()
        # Allow tasks a moment to process cancellation
        # Use await asyncio.gather to wait for tasks to finish cancelling
        tasks = [t for t in [ping_task, input_task] if t and not t.done()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


        # Send DISCONNECT message if we successfully connected and transport exists
        if protocol.session_id and protocol.transport and not protocol.transport.is_closing():
             print("Sending DISCONNECT message...")
             disconnect_msg = {'request_type': DISCONNECT}
             # Manually add session here as send_message might have issues during shutdown
             disconnect_msg['session'] = protocol.session_id
             try:
                 # *** FIX ***
                 # Use sendto() without address argument as transport is connected
                 protocol.transport.sendto(msgpack.packb(disconnect_msg))
                 # Give it a tiny moment to potentially send before closing
                 await asyncio.sleep(0.01)
             except Exception as e:
                 print(f"Error sending disconnect message: {e}")


        print("Closing transport...")
        if transport and not transport.is_closing():
            transport.close()

        # Optionally wait for the connection_lost future if robust cleanup needed
        # try:
        #     await asyncio.wait_for(on_con_lost, timeout=1.0)
        # except asyncio.TimeoutError:
        #     print("Timeout waiting for connection_lost.")

        print("Client finished.")


if __name__ == "__main__":
    try:
        # Run the main asynchronous function
        asyncio.run(main())
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nCaught KeyboardInterrupt, exiting.")
    except Exception as e:
        # Catch any unexpected errors during setup or shutdown
        print(f"\nUnhandled error in main execution: {e}")