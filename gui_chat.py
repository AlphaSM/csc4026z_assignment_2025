# --- gui_chat.py ---
import asyncio
import sys
import msgpack # Need this for DISCONNECT cleanup
import re
from html import escape
from PyQt5.QtWidgets import QCheckBox, QTextBrowser
from datetime import datetime
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import QLabel, QSplitter, QListWidget, QListWidgetItem
# from PyQt5.QtWidgets import QSplitter, QListWidget



# --- PyQt5 Imports ---
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QWidget, QStatusBar, QMessageBox
)
from PyQt5.QtCore import pyqtSignal, pyqtSlot, Qt, QObject

# --- Asyncio Integration ---
import asyncqt

# --- Import from your MODIFIED client logic file ---
try:
    # Import the necessary components from client_logic.py
    from client_logic import (
        ChatClientProtocol,
        send_pings,
        parse_and_send_command,
        SERVER_HOST,
        SERVER_PORT,
        DISCONNECT, # Needed for cleanup
        # Import other constants if needed directly, but usually not required
    )
    print("Successfully imported from client_logic.py")
except ImportError as e:
    print(f"Error importing from client_logic.py: {e}")
    print("Make sure client_logic.py is in the same directory and does not contain syntax errors.")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred during import: {e}")
    sys.exit(1)


# --- PyQt5 GUI Classes ---

class WindowSignals(QObject):
    """Defines the signals available for communication between network logic and GUI."""
    message_received = pyqtSignal(str, str) # message_text, tag
    status_updated = pyqtSignal(str)        # status_text
    connection_state_changed = pyqtSignal(str, dict) # state ("connected", etc.), data
    title_updated = pyqtSignal(str)         # title_text
    user_list_updated = pyqtSignal(list)  # NEW signal to handle /users list update



class ChatWindow(QMainWindow):
    """The main chat application window."""
    def __init__(self, loop, shutdown_event):
        super().__init__()
        self.loop = loop
        self.shutdown_event = shutdown_event
        self.signals = WindowSignals() # Instantiate the signals container

        # Placeholder for the function that actually sends commands
        self.send_command_func = None

        self.init_ui()
        self.connect_signals()

        # Initial message in the GUI
        self.signals.message_received.emit("GUI Initialized. Attempting connection...", "info")

    def init_ui(self):
        self.setWindowTitle(f"PyQt5 Async Chat - Connecting...")
        self.setGeometry(100, 100, 700, 500)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        splitter = QSplitter(self)
        splitter.setOrientation(Qt.Horizontal)

        # === Left Panel (Chat) ===
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)

        self.text_area = QTextBrowser(self)
        self.text_area.setReadOnly(True)
        self.text_area.setOpenExternalLinks(True)
        self.text_area.setHtml("<p><i>Welcome! Please wait...</i></p>")
        self.text_area.document().setDefaultStyleSheet("""
            .error { color: red; font-weight: bold; }
            .info { color: blue; }
            .server { color: purple; font-weight: bold; }
            .channel { color: darkgreen; }
            .dm { color: #FF8C00; }
            .own_message { color: gray; font-style: italic; }
            .timestamp { color: #555; font-size: smaller; }
        """)

        chat_layout.addWidget(self.text_area)

        input_layout = QHBoxLayout()
        self.input_entry = QLineEdit(self)
        self.input_entry.setPlaceholderText("Enter message or command (e.g., /users, /say channel msg)")
        self.send_button = QPushButton("Send", self)
        input_layout.addWidget(self.input_entry)
        input_layout.addWidget(self.send_button)
        chat_layout.addLayout(input_layout)

        self.auto_scroll_checkbox = QCheckBox("Auto-scroll", self)
        self.auto_scroll_checkbox.setChecked(True)
        chat_layout.addWidget(self.auto_scroll_checkbox)

        chat_widget.setLayout(chat_layout)
        splitter.addWidget(chat_widget)

        # === Right Panel (User List) ===
        self.user_list_widget = QListWidget()
        self.user_list_widget.setMaximumWidth(200)
        splitter.addWidget(self.user_list_widget)

        # === Main Layout ===
        layout = QVBoxLayout(central_widget)
        layout.addWidget(splitter)

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.signals.status_updated.emit("Initializing...")

        self.input_entry.setFocus()
        self.input_entry.setEnabled(False)
        self.send_button.setEnabled(False)



    def connect_signals(self):
        # Connect internal GUI actions
        self.send_button.clicked.connect(self.on_send_input)
        self.input_entry.returnPressed.connect(self.on_send_input)

        # Connect signals emitted by the protocol (via WindowSignals) to GUI slots
        self.signals.message_received.connect(self.update_text_area)
        self.signals.status_updated.connect(self.update_status_bar)
        self.signals.connection_state_changed.connect(self.handle_connection_state)
        self.signals.title_updated.connect(self.setWindowTitle)
        self.user_list_widget.itemDoubleClicked.connect(self.on_user_double_clicked)
        self.signals.user_list_updated.connect(self.update_user_list)



    # --- Slots for updating the GUI ---

    @pyqtSlot(str, str)
    def update_text_area(self, message, tag):
        if tag == "info_html":
            # Message is already HTML-formatted, so skip escaping
            formatted_message = f"<span class='info'>{message}</span>"
        else:
            escaped_message = escape(message)
            escaped_message = re.sub(r'(https?://\S+)', r'<a href="\1">\1</a>', escaped_message)
            formatted_message = f"<span class='{tag}'>{escaped_message}</span>"

        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"<span class='timestamp'>[{timestamp}]</span> {formatted_message}"

        self.text_area.append(formatted_message)

        if self.auto_scroll_checkbox.isChecked():
            self.text_area.verticalScrollBar().setValue(self.text_area.verticalScrollBar().maximum())

    @pyqtSlot(str)
    def update_status_bar(self, status_text):
        self.status_bar.showMessage(status_text)

    @pyqtSlot(list)
    def update_user_list(self, users):
        self.user_list_widget.clear()
        self.user_list_widget.addItems(users)


    @pyqtSlot(str, dict)
    def handle_connection_state(self, state, data):
        """Updates GUI based on connection status signals."""
        if state == "connected":
            username = data.get('username', '???')
            session = data.get('session', '???')
            self.signals.status_updated.emit(f"Connected as {username}")
            self.signals.title_updated.emit(f"PyQt5 Async Chat - {username}@{SERVER_HOST}")
            # Use update_text_area to add messages
            self.update_text_area(f"Successfully connected! Session: {session}", "info")
            self.update_text_area("Type commands like /users, /channels, /join <ch>, /say <ch> <msg>, /dm <user> <msg>, /quit", "info")
            self.input_entry.setEnabled(True)
            self.send_button.setEnabled(True)
            self.input_entry.setFocus()
        elif state == "disconnected":
            self.signals.status_updated.emit("Disconnected")
            self.update_text_area("Connection lost or closed.", "error")
            self.input_entry.setEnabled(False)
            self.send_button.setEnabled(False)
        elif state == "shutdown":
            self.signals.status_updated.emit("Server Shutdown")
            self.update_text_area("Server initiated shutdown.", "server")
            self.input_entry.setEnabled(False)
            self.send_button.setEnabled(False)

    # --- GUI Action Handlers ---

    @pyqtSlot()
    def on_send_input(self):
        """Called when Send button clicked or Enter pressed in input."""
        message = self.input_entry.text().strip()
        if message and self.send_command_func:
            self.input_entry.clear()
            # Call the function responsible for parsing/sending (defined in main_async)
            self.send_command_func(message)
        elif not self.send_command_func:
             self.update_text_area("Error: Send function not ready.", "error")

    @pyqtSlot('QListWidgetItem*')
    def on_user_double_clicked(self, item):
        username = item.text()
        self.input_entry.setText(f"/dm {username} ")
        self.input_entry.setFocus()


    def closeEvent(self, event):
        """Handle window close event (clicking the X)."""
        if not self.shutdown_event.is_set():
            reply = QMessageBox.question(self, 'Confirm Exit',
                                         "Are you sure you want to quit?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.update_text_area("Shutdown requested by user.", "info")
                self.shutdown_event.set() # Signal asyncio tasks to stop
                event.accept() # Allow window to close
            else:
                event.ignore() # Prevent window from closing
        else:
            event.accept() # Allow closing if already shutting down


# --- Asyncio Helper ---
async def watch_shutdown(shutdown_event: asyncio.Event, app: QApplication):
    """Waits for the shutdown event and then quits the Qt application."""
    await shutdown_event.wait()
    print("Shutdown event detected by watcher, quitting application.")
    # Use invokeMethod for thread safety if needed, but app.quit() often works
    # from PyQt5.QtCore import QMetaObject, Qt
    # QMetaObject.invokeMethod(app, "quit", Qt.QueuedConnection)
    app.quit()


# --- Main Async Setup Function ---
async def main_async(app: QApplication, window: ChatWindow, shutdown_event: asyncio.Event):
    """Sets up asyncio tasks and the network connection."""
    loop = asyncio.get_running_loop()
    protocol_instance = None
    transport = None

    # Define the actual function that interacts with the protocol
    # This function will be called by the GUI's on_send_input
    def _send_command_to_protocol(command_text):
        nonlocal protocol_instance
        if protocol_instance:
            # Call the parser/sender function imported from client_logic.py
            parse_and_send_command(command_text, protocol_instance)
        else:
            # Use the GUI's signal to display the error if protocol isn't ready
            window.signals.message_received.emit("Error: Protocol not available to send command.", "error")

    # Assign this internal function to the window instance
    window.send_command_func = _send_command_to_protocol

    # --- Network Setup ---
    try:
        print(f"Attempting UDP connection to {SERVER_HOST}:{SERVER_PORT}")
        # Create the endpoint using the imported protocol class from client_logic
        # Crucially, pass the window's signals object to the protocol constructor
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ChatClientProtocol(loop, window.signals, shutdown_event),
            remote_addr=(SERVER_HOST, SERVER_PORT))

        protocol_instance = protocol # Store for use in callback and cleanup
        print("Datagram endpoint created successfully.")

    except OSError as e:
        window.signals.message_received.emit(f"Network Connection Error: {e}", "error")
        window.signals.status_updated.emit("Connection Failed")
        shutdown_event.set() # Trigger shutdown if connection fails immediately
    except Exception as e:
        window.signals.message_received.emit(f"Unexpected error during connection setup: {e}", "error")
        window.signals.status_updated.emit("Error")
        shutdown_event.set()

    # --- Start Background Tasks ---
    ping_task = None
    if protocol_instance:
        # Start pinger using the imported function from client_logic
        ping_task = asyncio.create_task(send_pings(protocol_instance))
        print("Ping task created.")
    else:
        print("Skipping ping task creation due to connection failure.")

    # Task to watch for the shutdown signal and quit the app
    shutdown_watcher_task = asyncio.create_task(watch_shutdown(shutdown_event, app))
    print("Shutdown watcher task created.")

    # --- Wait for shutdown signal ---
    print("Asyncio setup complete. Waiting for shutdown signal...")
    await shutdown_event.wait() # The application runs until this event is set

    # --- Cleanup Logic ---
    print("Shutdown signalled. Initiating asyncio cleanup...")
    tasks_to_cancel = [ping_task, shutdown_watcher_task]
    active_tasks = [t for t in tasks_to_cancel if t and not t.done()]
    if active_tasks:
        print(f"Cancelling {len(active_tasks)} background tasks...")
        for task in active_tasks: task.cancel()
        # Wait for tasks to finish cancelling
        await asyncio.gather(*active_tasks, return_exceptions=True)
        print("Background tasks cancelled.")

    # Send DISCONNECT message if connection was successful
    if protocol_instance and protocol_instance.session_id and transport and not transport.is_closing():
         window.signals.message_received.emit("Sending DISCONNECT message...", "info")
         # Use DISCONNECT constant imported from client_logic
         disconnect_msg = {'request_type': DISCONNECT, 'session': protocol_instance.session_id}
         try:
             # msgpack should be imported at the top of this file
             transport.sendto(msgpack.packb(disconnect_msg))
             await asyncio.sleep(0.05) # Brief pause to allow sending
         except Exception as e:
             window.signals.message_received.emit(f"Error sending disconnect message: {e}", "error")

    print("Closing transport...")
    if transport and not transport.is_closing():
        transport.close()

    print("Asyncio cleanup finished.")


# --- Main Execution Entry Point ---
if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)

        # Setup asyncqt event loop integration
        loop = asyncqt.QEventLoop(app)
        asyncio.set_event_loop(loop)

        # Event to coordinate shutdown across all tasks and the GUI
        shutdown_event = asyncio.Event()

        # Create the main application window
        window = ChatWindow(loop, shutdown_event)
        window.show() # Make the window visible

        # Schedule the main asynchronous logic (connection, tasks) to run
        loop.create_task(main_async(app, window, shutdown_event))

        print("Starting Qt/Asyncio event loop (run_forever)...")
        # Start the combined Qt and asyncio event loop
        exit_code = loop.run_forever()
        print(f"Event loop finished. Exit code: {exit_code}")
        sys.exit(exit_code) # Exit with the application's exit code

    except KeyboardInterrupt:
        # Handle Ctrl+C in the console (might not always work reliably with GUI loops)
        print("\nKeyboardInterrupt detected. Attempting graceful exit.")
        # Ensure shutdown is signalled if loop interrupted externally
        # This might be tricky depending on where the interrupt is caught
        if 'shutdown_event' in locals() and not shutdown_event.is_set():
             shutdown_event.set()
             # Give cleanup a moment - this might not execute if loop is hard-stopped
             # loop.run_until_complete(asyncio.sleep(0.5))
    except ImportError:
         # Error handled during import, message already printed.
         sys.exit(1)
    except Exception as e:
        # Catch any other unexpected errors during setup or runtime
        print(f"\nFATAL ERROR in main execution: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1) # Exit with a non-zero code indicating an error