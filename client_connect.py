import asyncio
import socket
import msgpack
import random
import sys
import time
import nacl.public
from nacl.bindings import crypto_scalarmult
from hashlib import blake2s
import hashlib
import struct
import base64
from cryptography.hazmat.primitives.hashes import BLAKE2s
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
SERVER_HOST = "csc4026z.link"
SERVER_PORT = 51825  # Cleartext port
SERVER_SECURE_PORT = 51820
PING_INTERVAL = 25  # Seconds

# Wireguard constants
SERVER_STATIC_PUBLIC_KEY = b'f,^\xc0Cb\xf3\x937\xbf\x11\x14"\xed\x13\x0b\x9f\xe7\xaf;\x94\xb0p\x13\xe1\x94\xdd\x85\xcf\x01\x0bC'

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

# --- Wireguard Cryptographic Functions ---
def DH_Generate():
    """Generate a new Curve25519 key pair for DH operations"""
    private_key = nacl.public.PrivateKey.generate()
    return private_key.encode(), private_key.public_key.encode()

def DH(private_key, public_key):
    """Perform Diffie-Hellman key exchange"""
    return nacl.bindings.crypto_scalarmult(n=private_key, p=public_key)

def Hash(data):
    """BLAKE2s hash function as specified by Wireguard"""
    return hashlib.blake2s(data, digest_size=32).digest()

def MixHash(*args):
    """Hash the concatenation of multiple inputs"""
    concatenated = b''.join(args)
    return Hash(concatenated)

def Mac(key, input_data):
    """Compute a MAC using BLAKE2s with key"""
    return hashlib.blake2s(input_data, key=key, digest_size=16).digest()

def Hmac(key, input_data):
    """Compute an HMAC using BLAKE2s"""
    h = HMAC(key, hashes.BLAKE2s(32))
    h.update(input_data)
    return h.finalize()

def Kdf1(key, input_data):
    """Derive one output key from input key and data"""
    return Hmac(key, input_data + b'\x01')

def Kdf2(key, input_data):
    """Derive two output keys from input key and data"""
    t0 = Hmac(key, input_data + b'\x01')
    t1 = Hmac(key, t0 + input_data + b'\x02')
    return t0, t1

def Kdf3(key, input_data):
    """Derive three output keys from input key and data"""
    t0 = Hmac(key, input_data + b'\x01')
    t1 = Hmac(key, t0 + input_data + b'\x02')
    t2 = Hmac(key, t1 + input_data + b'\x03')
    return t0, t1, t2

def AEAD_encrypt(key, counter, plaintext, authtext):
    """
    Encrypt using ChaCha20Poly1305 AEAD
    counter must be 12 bytes (96 bits)
    """
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(counter, plaintext, authtext)

def AEAD_decrypt(key, counter, ciphertext, authtext):
    """
    Decrypt using ChaCha20Poly1305 AEAD
    counter must be 12 bytes (96 bits)
    """
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(counter, ciphertext, authtext)

def Timestamp(t=None):
    """
    Create a timestamp value as defined in the Wireguard spec
    If t is None, use current time
    """
    if t is None:
        t = time.time()
    seconds = int(t)
    nano = int((t - seconds) * 1_000_000_000)
    
    # TAI64N format: 0x400000000000000000000000 + seconds, then nano
    tai = 0x400000000000000 + seconds
    
    # Pack as 12 bytes: 8 for TAI64 time, 4 for nanoseconds
    return struct.pack('>QI', tai, nano)

# --- Wireguard Handshake Functions ---
def create_initiation_message(client_static_private, client_static_public, server_static_public):
    """
    Create a Wireguard initiation message
    Returns the message and the state needed for handling the response
    """
    debug_print("Creating Wireguard initiation message")
    debug_print(f"Client static public key: {client_static_public.hex()}")
    debug_print(f"Server static public key: {server_static_public.hex()}")
    
    # Initial hash and chain key derivation
    construction = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    chain_key = Hash(construction)
    debug_print(f"Initial chain_key: {chain_key.hex()}")
    
    identifier = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
    hash_value = MixHash(chain_key, identifier)
    debug_print(f"After identifier, hash_value: {hash_value.hex()}")
    
    # Mix in responder's public key (server)
    hash_value = MixHash(hash_value, server_static_public)
    debug_print(f"After mixing server public key, hash_value: {hash_value.hex()}")
    
    # Generate ephemeral key
    client_ephemeral_private, client_ephemeral_public = DH_Generate()
    debug_print(f"Generated ephemeral public key: {client_ephemeral_public.hex()}")
    
    # Update chain key with ephemeral key
    chain_key = Kdf1(chain_key, client_ephemeral_public)
    debug_print(f"After Kdf1 with ephemeral key, chain_key: {chain_key.hex()}")
    
    # Update hash with ephemeral key
    hash_value = MixHash(hash_value, client_ephemeral_public)
    debug_print(f"After mixing ephemeral key, hash_value: {hash_value.hex()}")
    
    # DH and key derivation for static key
    shared_secret1 = DH(client_ephemeral_private, server_static_public)
    debug_print(f"Shared secret 1: {shared_secret1.hex()}")
    
    chain_key, key1 = Kdf2(chain_key, shared_secret1)
    debug_print(f"After Kdf2 with shared_secret1, chain_key: {chain_key.hex()}")
    debug_print(f"key1: {key1.hex()}")
    
    # Encrypt static public key
    counter1 = b"\x00" * 12
    msg_static = AEAD_encrypt(key1, counter1, client_static_public, hash_value)
    debug_print(f"Encrypted static public key: {msg_static.hex()}")
    
    # Update hash with encrypted static key
    hash_value = MixHash(hash_value, msg_static)
    debug_print(f"After mixing encrypted static key, hash_value: {hash_value.hex()}")
    
    # DH and key derivation for timestamp
    shared_secret2 = DH(client_static_private, server_static_public)
    chain_key, key2 = Kdf2(chain_key, shared_secret2)
    debug_print(f"After Kdf2 with shared_secret2, chain_key: {chain_key.hex()}")
    debug_print(f"key2: {key2.hex()}")
    
    # Encrypt timestamp
    counter2 = b"\x00" * 12
    timestamp = Timestamp()
    msg_timestamp = AEAD_encrypt(key2, counter2, timestamp, hash_value)
    debug_print(f"Encrypted timestamp: {msg_timestamp.hex()}")
    
    # Final hash update
    hash_value = MixHash(hash_value, msg_timestamp)
    debug_print(f"After mixing encrypted timestamp, hash_value: {hash_value.hex()}")
    
    # Create sender index (random 32-bit value)
    sender_index = struct.pack("<I", random.randint(0, 2**32 - 1))
    
    # Assemble the message (excluding MACs)
    msg_type = b"\x01"  # Type 1 for initiation
    reserved = b"\x00" * 3
    
    msg = msg_type + reserved + sender_index + client_ephemeral_public + msg_static + msg_timestamp
    
    # Calculate MAC1 - mac1 = MAC(Hash("mac1----" || S_R_pub), msg)
    mac1_key = Hash(b"mac1----" + server_static_public)
    mac1 = Mac(mac1_key, msg)
    
    # Add mac1 and empty mac2
    mac2 = b"\x00" * 16
    msg += mac1 + mac2
    
    # Add detailed debugging of the final message structure
    debug_print("Final message structure:")
    debug_print(f"- Message type: {msg_type.hex()}")
    debug_print(f"- Reserved: {reserved.hex()}")
    debug_print(f"- Sender index: {sender_index.hex()}")
    debug_print(f"- Client ephemeral public: {client_ephemeral_public.hex()}")
    debug_print(f"- Encrypted static key: {msg_static.hex()}")
    debug_print(f"- Encrypted timestamp: {msg_timestamp.hex()}")
    debug_print(f"- MAC1: {mac1.hex()}")
    debug_print(f"- MAC2: {mac2.hex()}")
    
    # Return message and state for response handling
    handshake_state = {
        "chain_key": chain_key,
        "hash": hash_value,
        "client_ephemeral_private": client_ephemeral_private,
        "client_static_private": client_static_private,
        "sender_index": sender_index
    }
    
    return msg, handshake_state

def process_handshake_response(response_msg, handshake_state):
    """
    Process a Wireguard handshake response message
    Returns the session keys for transport encryption/decryption
    """
    debug_print("Processing handshake response")
    hex_dump(response_msg, "Response message")
    
    # Unpack the response message
    if len(response_msg) < 60:  # Minimum size check
        raise ValueError(f"Response message too short: {len(response_msg)} bytes")
    
    msg_type = response_msg[0:1]
    if msg_type != b"\x02":  # Type 2 for response
        raise ValueError(f"Unexpected message type: {msg_type.hex()}")
    
    # Skip reserved bytes
    receiver_index = response_msg[4:8]  # Should match our sender_index
    sender_index = response_msg[8:12]   # Server's sender index
    
    debug_print(f"Message type: {msg_type.hex()}")
    debug_print(f"Receiver index: {receiver_index.hex()}")
    debug_print(f"Sender index: {sender_index.hex()}")
    
    # Extract ephemeral key and encrypted empty message
    server_ephemeral_public = response_msg[12:44]
    msg_empty = response_msg[44:60]
    
    debug_print(f"Server ephemeral public key: {server_ephemeral_public.hex()}")
    debug_print(f"Encrypted empty message: {msg_empty.hex()}")
    
    # Continue the handshake
    chain_key = handshake_state["chain_key"]
    hash_value = handshake_state["hash"]
    
    # Update chain key with server's ephemeral key
    chain_key = Kdf1(chain_key, server_ephemeral_public)
    
    # Update hash with server's ephemeral key
    hash_value = MixHash(hash_value, server_ephemeral_public)
    
    # DH: client ephemeral private + server ephemeral public
    shared_secret1 = DH(handshake_state["client_ephemeral_private"], server_ephemeral_public)
    chain_key = Kdf1(chain_key, shared_secret1)
    
    # DH: client static private + server ephemeral public
    shared_secret2 = DH(handshake_state["client_static_private"], server_ephemeral_public)
    chain_key = Kdf1(chain_key, shared_secret2)
    
    # Derive key for empty message
    chain_key, tmp, key3 = Kdf3(chain_key, b"")
    hash_value = MixHash(hash_value, tmp)
    
    # Decrypt empty message
    counter = b"\x00" * 12
    try:
        empty = AEAD_decrypt(key3, counter, msg_empty, hash_value)
        if empty != b"":
            raise ValueError("Decrypted empty message is not empty")
    except Exception as e:
        raise ValueError(f"Failed to decrypt empty message: {e}")
    
    # Update hash with decrypted empty message
    hash_value = MixHash(hash_value, empty)
    
    # Derive transport keys
    sending_key, receiving_key = Kdf2(chain_key, b"")
    
    # Return transport session state
    session = {
        "sender_index": handshake_state["sender_index"],
        "receiver_index": sender_index,
        "sending_key": sending_key,
        "receiving_key": receiving_key,
        "send_counter": 0,
        "recv_counter": 0
    }
    
    return session

# --- Wireguard Transport Functions ---
def encrypt_transport_message(data, session):
    """Encrypt a transport data message"""
    # Prepare the datagram
    msg_type = b"\x04"  # Type 4 for transport data
    receiver_index = session["receiver_index"]
    counter = struct.pack("<Q", session["send_counter"])
    
    # Encrypt the data
    key = session["sending_key"]
    counter_nonce = b"\x00" * 4 + counter  # 12-byte nonce
    encrypted_data = AEAD_encrypt(key, counter_nonce, data, b"")
    
    # Assemble the message
    msg = msg_type + receiver_index + counter + encrypted_data
    
    # Increment counter
    session["send_counter"] += 1
    
    return msg

def decrypt_transport_message(msg, session):
    """Decrypt a transport data message"""
    # Verify message type
    if msg[0:1] != b"\x04":
        raise ValueError(f"Unexpected message type: {msg[0:1]}")
    
    # Extract receiver index and counter
    receiver_index = msg[1:5]
    counter_bytes = msg[5:13]
    encrypted_data = msg[13:]
    
    # Verify receiver index matches our sender index
    if receiver_index != session["sender_index"]:
        raise ValueError("Receiver index in message doesn't match our sender index")
    
    # Convert counter to integer
    counter = struct.unpack("<Q", counter_bytes)[0]
    
    # Check for replay
    if counter < session["recv_counter"]:
        raise ValueError(f"Replayed message: counter {counter} < {session['recv_counter']}")
    
    # Decrypt the data
    key = session["receiving_key"]
    counter_nonce = b"\x00" * 4 + counter_bytes  # 12-byte nonce
    decrypted_data = AEAD_decrypt(key, counter_nonce, encrypted_data, b"")
    
    # Update counter if valid
    session["recv_counter"] = counter + 1
    
    return decrypted_data

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

class SecureChatClientProtocol(asyncio.DatagramProtocol):
    """Secure chat client using Wireguard encryption"""
    def __init__(self, loop, on_con_lost, shutdown_event, client_private_key):
        self.loop = loop
        self.on_con_lost = on_con_lost
        self.shutdown_event = shutdown_event
        self.transport = None
        self.server_address = (SERVER_HOST, SERVER_SECURE_PORT)
        
        # Session state
        self.session_id = None
        self.username = None
        self.ping_task = None
        self.input_task = None
        self.connected_event = asyncio.Event()
        
        # Wireguard state
        self.handshake_state = None
        self.session = None
        self.client_private_key = client_private_key
        self.client_public_key = nacl.public.PrivateKey(client_private_key).public_key.encode()
        self.server_public_key = SERVER_STATIC_PUBLIC_KEY
    
    def connection_made(self, transport):
        """Called when the UDP socket is ready."""
        self.transport = transport
        print(f"Socket created, default destination set to {self.server_address}...")
        
        print("Scheduling Wireguard handshake initiation...")
        # Store the task so we can track it
        self.handshake_task = asyncio.create_task(self.initiate_secure_handshake())
        
        # Optional: add callback to track task completion
        self.handshake_task.add_done_callback(
            lambda t: print(f"Handshake task completed with result: {t.exception() or 'Success'}")
        )
    
    async def initiate_secure_handshake(self):
        """Start the Wireguard handshake process with validation and retry"""
        max_attempts = 3
        
        for attempt in range(1, max_attempts + 1):
            try:
                print(f"Initiating secure connection (attempt {attempt}/{max_attempts})...")
                
                # Create and send initiation message
                initiation_msg, self.handshake_state = create_initiation_message(
                    self.client_private_key,
                    self.client_public_key,
                    self.server_public_key
                )
                
                # Validate the message length
                expected_length = 148  # Type(1) + Reserved(3) + SenderIndex(4) + EphemeralKey(32) + 
                                      # EncryptedStatic(48) + EncryptedTimestamp(28) + MAC1(16) + MAC2(16)
                if len(initiation_msg) != expected_length:
                    print(f"WARNING: Initiation message length is {len(initiation_msg)}, expected {expected_length} bytes")
                    hex_dump(initiation_msg, "Invalid initiation message")
                
                debug_initiation_message(initiation_msg)
                self.transport.sendto(initiation_msg)
                print(f"Sent Wireguard initiation message ({len(initiation_msg)} bytes), waiting for response...")
                
                # Wait for response before continuing or retrying
                await asyncio.sleep(2)
                
                if self.session:
                    print("Handshake completed during wait period!")
                    return
                    
            except Exception as e:
                print(f"Error initiating secure handshake: {e}")
                import traceback
                traceback.print_exc()
                
            print(f"Attempt {attempt} completed without successful handshake")
            
        print(f"Failed to establish secure connection after {max_attempts} attempts")
        print("Possible issues:")
        print("1. Server is not responding to Wireguard handshake")
        print("2. Your private key is not registered with the server")
        print("3. Network issues preventing UDP communication")
        print("Try using --cleartext mode to verify server connectivity")
        
        self.shutdown_event.set()
    
    def datagram_received(self, data, addr):
        """Called when a datagram is received from the server."""
        try:
            debug_print(f"Received {len(data)} bytes from {addr}")
            hex_dump(data, "Received data")
            
            # If we have an active session, decrypt the message
            if self.session:
                # For transport data messages
                if data[0] == 4:  # Type 4 for transport data
                    debug_print("Processing transport data message")
                    try:
                        decrypted_data = decrypt_transport_message(data, self.session)
                        decoded_message = msgpack.unpackb(decrypted_data, raw=False)
                        self.handle_chat_message(decoded_message)
                    except Exception as e:
                        print(f"Error decrypting transport message: {e}")
                        import traceback
                        traceback.print_exc()
                    return
                else:
                    print(f"Unexpected message type {data[0]} with established session")
                    return
            
            # If we're in handshake phase
            if not self.session and self.handshake_state:
                if len(data) >= 1:
                    msg_type = data[0]
                    debug_print(f"Message type: {msg_type} (expected response: 2)")
                    
                    if msg_type == 2:  # Type 2 for handshake response
                        print("Received Wireguard handshake response")
                        try:
                            self.session = process_handshake_response(data, self.handshake_state)
                            print("Secure session established successfully!")
                            self.send_connect()
                            return
                        except Exception as e:
                            print(f"Error processing handshake response: {e}")
                            import traceback
                            traceback.print_exc()
                            return
                    else:
                        print(f"Unexpected message type during handshake: {msg_type}")
                else:
                    print("Received empty or too short message during handshake")
        
            print(f"Received unexpected message (session: {bool(self.session)}, handshake_state: {bool(self.handshake_state)})")
            
        except Exception as e:
            print(f"Error processing received datagram: {e}")
            import traceback
            traceback.print_exc()
            
        # Ensure prompt is redisplayed after handling a message
        if not self.shutdown_event.is_set():
            print("> ", end='', flush=True)
    
    def send_connect(self):
        """Sends the initial CONNECT request over the secure channel."""
        connect_request = {
            'request_type': CONNECT,
            'request_handle': random.randint(0, 2**32 - 1)
        }
        print(f"Sending CONNECT request: {connect_request}")
        try:
            bytes_to_send = msgpack.packb(connect_request)
            self.send_message_secure(bytes_to_send)
        except Exception as e:
            print(f"Error packing/sending CONNECT message: {e}")
            self.shutdown_event.set()
    
    def send_message_secure(self, data):
        """Encrypts and sends data through the secure channel"""
        if not self.session:
            print("Cannot send secure message - no session established")
            return
        
        encrypted_msg = encrypt_transport_message(data, self.session)
        self.transport.sendto(encrypted_msg)
    
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
    
    def handle_chat_message(self, decoded_message):
        """Process a chat protocol message (after decryption)"""
        print(f"\nDecoded: {decoded_message}")

        response_type = decoded_message.get('response_type')
        response_handle = decoded_message.get('response_handle')
        
        # The same handling logic as in the original ChatClientProtocol.datagram_received
        # Copy all the different response type handlers here
        
        if response_type == CONNECT_RESPONSE:
            self.session_id = decoded_message.get('session')
            self.username = decoded_message.get('username')
            print("\n--------------------------------------------------")
            print(f"Successfully connected!")
            print(f"  Session ID: {self.session_id}")
            print(f"  Assigned Username: {self.username}")
            print(f"  Message: {decoded_message.get('message')}")
            print("--------------------------------------------------")
            print("Type commands starting with '/' or messages to send.")
            self.connected_event.set()
            
        # Add the other message type handlers from the original code
        # ...
    
    def error_received(self, exc): 
        """Called when a send or receive operation raises an OSError."""
        print(f"Socket error received: {exc}")
    
    def connection_lost(self, exc):
        """Called when the connection is lost or closed."""
        print("Socket closed.")
        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)
        self.shutdown_event.set()

    async def test_server_connectivity(self):
        """Send a test packet to verify server is reachable"""
        try:
            print(f"Testing connectivity to {self.server_address}...")
            # Send a simple test packet - this is not a valid Wireguard packet
            # but will help determine if UDP packets are reaching the server
            test_packet = b"\x00" * 8
            self.transport.sendto(test_packet)
            
            # Wait briefly to see if we get any response
            # No valid response is expected, but an ICMP error might 
            # indicate network problems
            await asyncio.sleep(1)
            print("Test packet sent (no response expected)")
            
        except Exception as e:
            print(f"Error during connectivity test: {e}")

# --- Debugging Functions ---

DEBUG_MODE = True  # Set to control debug verbosity

def debug_print(*args, **kwargs):
    """Conditionally print debug information"""
    if DEBUG_MODE:
        print("[DEBUG]", *args, **kwargs)

def hex_dump(data, prefix=""):
    """Print a hex dump of binary data"""
    if not DEBUG_MODE:
        return
        
    print(f"{prefix} [{len(data)} bytes]:")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  {i:04x}: {hex_str.ljust(47)} | {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}")


def debug_initiation_message(msg):
    if len(msg) != 148:
        print(f"WARNING: Initiation message length is {len(msg)}, expected 148 bytes")
        
    print(f"Message type: {msg[0]} (should be 1)")
    print(f"Sender index: {int.from_bytes(msg[4:8], 'little')}")
    print(f"Ephemeral public key: {msg[8:40].hex()[:16]}...")
    print(f"Encrypted static key length: {len(msg[40:88])}")
    print(f"Encrypted timestamp length: {len(msg[88:116])}")
    print(f"MAC1: {msg[116:132].hex()[:16]}...")
    print(f"MAC2: {msg[132:148] == b'\\x00' * 16}")


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

async def main(use_secure=True, debug=False):
    """Main function with secure mode support"""
    global DEBUG_MODE
    DEBUG_MODE = debug
    
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()
    shutdown_event = asyncio.Event()
    
    if use_secure:
        try:
            client_private_key = base64.b64decode(b"loWkKlPp0ghY78cZoO83klkrVlp45Yqm+MoYgWMQXxA=")
            
            print(f"Attempting to connect to UDP {SERVER_HOST}:{SERVER_SECURE_PORT} (ENCRYPTED)")
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SecureChatClientProtocol(
                    loop, on_con_lost, shutdown_event, client_private_key
                ),
                remote_addr=(SERVER_HOST, SERVER_SECURE_PORT)
            )
        except Exception as e:
            print(f"Error setting up secure connection: {e}")
            print("Falling back to cleartext connection...")
            use_secure = False
    
    if not use_secure:
        print(f"Attempting to connect to UDP {SERVER_HOST}:{SERVER_PORT} (CLEARTEXT)")
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ChatClientProtocol(loop, on_con_lost, shutdown_event),
            remote_addr=(SERVER_HOST, SERVER_PORT)
        )
    
    # Start background tasks
    ping_task = asyncio.create_task(send_pings(protocol))
    input_task = asyncio.create_task(handle_user_input(protocol))
    
    try:
        await shutdown_event.wait()
        print("Shutdown signal received, cleaning up...")
    finally:
        # Cleanup as in original code
        print("Cancelling background tasks...")
        if ping_task and not ping_task.done():
            ping_task.cancel()
        if input_task and not input_task.done():
            input_task.cancel()
            
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
        secure_mode = "--cleartext" not in sys.argv
        debug_mode = "--debug" in sys.argv
        asyncio.run(main(use_secure=secure_mode, debug=debug_mode))
    except KeyboardInterrupt:
        print("\nCaught KeyboardInterrupt, exiting.")
    except Exception as e:
        print(f"\nUnhandled error in main execution: {e}")