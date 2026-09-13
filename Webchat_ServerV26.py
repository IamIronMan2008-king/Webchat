import os
import socket
import threading
import time
import json
import hashlib
import binascii
import tempfile
import traceback

print('SERVER STARTED')
HOST = '0.0.0.0'  # listen on all interfaces inside the container
PORT = int(os.environ.get('SOCKET_PORT', 1310))  # internal port your app listens on
RETRY_INTERVAL = float(os.environ.get('MESSAGE_RETRY_INTERVAL', 1.0))
MESSAGE_SEPARATOR = '<!-WEBCHAT-!>'

# ---------------- AUTH PROTOCOL PREFIXES ---------------- #
# Sent by the client BEFORE it is authenticated.
REGISTER_PREFIX = '<!-WEBCHATREGISTER-!>'   # REGISTER_PREFIX + id + SEP + name + SEP + password
LOGIN_PREFIX = '<!-WEBCHATLOGIN-!>'         # LOGIN_PREFIX + id + SEP + password
CHECKID_PREFIX = '<!-WEBCHATCHECKID-!>'     # CHECKID_PREFIX + id

# Sent back by the server in response to the above.
AUTH_OK_PREFIX = '<!-WEBCHATAUTHOK-!>'      # AUTH_OK_PREFIX + id
AUTH_FAIL_PREFIX = '<!-WEBCHATAUTHFAIL-!>'  # AUTH_FAIL_PREFIX + reason_code
ID_AVAILABLE_PREFIX = '<!-WEBCHATIDAVAILABLE-!>'  # ID_AVAILABLE_PREFIX + id
ID_TAKEN_PREFIX = '<!-WEBCHATIDTAKEN-!>'          # ID_TAKEN_PREFIX + id

# Failure reason codes sent after AUTH_FAIL_PREFIX
REASON_ID_TAKEN = 'ID_TAKEN'
REASON_USER_NOT_FOUND = 'USER_NOT_FOUND'
REASON_BAD_PASSWORD = 'INVALID_CREDENTIALS'
REASON_BAD_REQUEST = 'BAD_REQUEST'
REASON_SERVER_ERROR = 'SERVER_ERROR'

print(f'listening on {HOST}:{PORT}')
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(10)  # Number of connections accepted at a time

clients = {}
clients_lock = threading.Lock()

# ---------------- USER DATABASE ---------------- #
# A simple JSON file on the server storing, per user id:
#   { "<user_id>": {"name": "...", "salt": "<hex>", "hash": "<hex>"} }
# Passwords are never stored in plaintext - only a salted PBKDF2-SHA256
# hash, so reading the file doesn't reveal anyone's password.
USERS_DB_PATH = os.environ.get('USERS_DB_PATH', os.path.join(tempfile.gettempdir(), 'webchat_users_db.json'))
PBKDF2_ITERATIONS = 200_000
db_lock = threading.Lock()


def _load_users():
    """Read the user database from disk. Returns {} if it doesn't exist yet
    or is corrupted (rather than crashing the server)."""
    if not os.path.exists(USERS_DB_PATH):
        return {}
    try:
        with open(USERS_DB_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as error:
        print('USER DB READ ERROR:', error)
        return {}


def _save_users(users):
    """Write the user database to disk atomically (write to a temp file,
    then replace) so a crash mid-write can't corrupt the file."""
    tmp_path = USERS_DB_PATH + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(users, f)
    os.replace(tmp_path, USERS_DB_PATH)


def _hash_password(password, salt=None):
    """Returns (salt_hex, hash_hex) for a password. Generates a fresh
    random salt if one isn't supplied (i.e. on registration)."""
    if salt is None:
        salt_bytes = os.urandom(16)
    else:
        salt_bytes = binascii.unhexlify(salt)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, PBKDF2_ITERATIONS)
    return binascii.hexlify(salt_bytes).decode('ascii'), binascii.hexlify(hashed).decode('ascii')


def _verify_password(password, salt_hex, expected_hash_hex):
    _, computed_hash_hex = _hash_password(password, salt=salt_hex)
    # Constant-time comparison to avoid leaking timing information.
    return hmac_compare(computed_hash_hex, expected_hash_hex)


def hmac_compare(a, b):
    import hmac
    return hmac.compare_digest(a, b)


def id_is_taken(user_id):
    with db_lock:
        users = _load_users()
        return user_id in users


def register_user(user_id, name, password):
    """Attempts to create a new user. Returns (True, name) on success or
    (False, reason_code) on failure. The taken-check and the write happen
    under the same lock so two clients racing to register the same id
    can't both succeed."""
    with db_lock:
        users = _load_users()
        if user_id in users:
            return False, REASON_ID_TAKEN
        salt_hex, hash_hex = _hash_password(password)
        users[user_id] = {'name': name, 'salt': salt_hex, 'hash': hash_hex}
        _save_users(users)
        return True, name


def authenticate_user(user_id, password):
    """Returns (True, name) if the id/password pair is valid, otherwise
    (False, reason_code)."""
    with db_lock:
        users = _load_users()
    record = users.get(user_id)
    if record is None:
        return False, REASON_USER_NOT_FOUND
    if not _verify_password(password, record['salt'], record['hash']):
        return False, REASON_BAD_PASSWORD
    return True, record['name']


# Each item has the requested format: [sent, message].
# The message is kept as a dictionary so the sender, recipient, and text are
# all available when the retry worker attempts delivery.
Unsend_Message = []
unsent_message_lock = threading.Lock()


def _remove_pending_message(pending_message):
    """Remove a queued message by object identity, not by value."""
    with unsent_message_lock:
        for index, item in enumerate(Unsend_Message):
            if item is pending_message:
                del Unsend_Message[index]
                return


def _try_send_pending_message(pending_message):
    """Try to deliver one queued message and remove it after success."""
    # Reserve the item so the retry thread and the message-receiving thread
    # cannot send the same message concurrently.
    with unsent_message_lock:
        if not any(item is pending_message for item in Unsend_Message):
            return False
        if pending_message[0]:
            return False
        pending_message[0] = True

    message_details = pending_message[1]
    send_id = message_details['send_id']

    with clients_lock:
        target = clients.get(send_id)

    if target is None:
        # Keep the item in Unsend_Message and make it eligible for retry.
        with unsent_message_lock:
            pending_message[0] = False
        return False

    payload = (
        message_details['sender_id']
        + MESSAGE_SEPARATOR
        + message_details['message']
    )

    try:
        target.sendall(payload.encode('utf-8'))
    except (ConnectionError, OSError) as error:
        print(f'CLIENT DISCONNECTED while sending to {send_id}: {error}')
        with clients_lock:
            # Only remove the socket if it is still the socket that failed.
            if clients.get(send_id) is target:
                del clients[send_id]
        with unsent_message_lock:
            pending_message[0] = False
        return False

    # True indicates that delivery succeeded. Remove the item immediately
    # afterward, as requested, so the list contains only undelivered messages.
    pending_message[0] = True
    _remove_pending_message(pending_message)
    print('msg sent to', send_id)
    return True


def retry_unsent_messages():
    """Continuously retry queued messages without blocking client handlers."""
    while True:
        with unsent_message_lock:
            pending_messages = list(Unsend_Message)

        for pending_message in pending_messages:
            _try_send_pending_message(pending_message)

        time.sleep(RETRY_INTERVAL)


def sevto_msg(sender_id, msg, send_id):
    """Queue an outbound message and attempt immediate delivery."""
    pending_message = [
        False,
        {
            'sender_id': sender_id,
            'message': msg,
            'send_id': send_id,
        },
    ]

    with unsent_message_lock:
        Unsend_Message.append(pending_message)

    # Try immediately when possible. If the recipient is offline or the send
    # fails, the background worker will keep retrying this same list item.
    _try_send_pending_message(pending_message)


def _send_raw(client, text):
    try:
        client.sendall(text.encode('utf-8'))
        return True
    except (ConnectionError, OSError) as error:
        print('AUTH SEND ERROR:', error)
        return False


def _authenticate_client(client):
    """Runs the pre-chat handshake: the client may send any number of
    CHECKID_PREFIX probes, then must send exactly one successful
    REGISTER_PREFIX or LOGIN_PREFIX message before it's allowed to chat.
    Returns the authenticated user_id, or None if the client disconnected
    before authenticating.

    Anything inside this function that raises (e.g. the user DB file
    failing to write) is caught here and reported back to the client as
    AUTH_FAIL_PREFIX + 'SERVER_ERROR', instead of silently killing this
    thread and leaving the client waiting until it times out."""
    while True:
        data = client.recv(4096)
        if not data:
            return None  # client closed the connection before logging in
        data = data.decode('utf-8')

        try:
            if data.startswith(CHECKID_PREFIX):
                candidate_id = data[len(CHECKID_PREFIX):]
                if id_is_taken(candidate_id):
                    _send_raw(client, ID_TAKEN_PREFIX + candidate_id)
                else:
                    _send_raw(client, ID_AVAILABLE_PREFIX + candidate_id)
                continue  # not authenticated yet, keep listening

            if data.startswith(REGISTER_PREFIX):
                parts = data[len(REGISTER_PREFIX):].split(MESSAGE_SEPARATOR)
                if len(parts) != 3:
                    _send_raw(client, AUTH_FAIL_PREFIX + REASON_BAD_REQUEST)
                    continue
                user_id, name, password = parts
                if not user_id or not password:
                    _send_raw(client, AUTH_FAIL_PREFIX + REASON_BAD_REQUEST)
                    continue
                success, info = register_user(user_id, name, password)
                if success:
                    _send_raw(client, AUTH_OK_PREFIX + user_id + MESSAGE_SEPARATOR + info)
                    return user_id
                _send_raw(client, AUTH_FAIL_PREFIX + info)
                continue

            if data.startswith(LOGIN_PREFIX):
                parts = data[len(LOGIN_PREFIX):].split(MESSAGE_SEPARATOR)
                if len(parts) != 2:
                    _send_raw(client, AUTH_FAIL_PREFIX + REASON_BAD_REQUEST)
                    continue
                user_id, password = parts
                success, info = authenticate_user(user_id, password)
                if success:
                    _send_raw(client, AUTH_OK_PREFIX + user_id + MESSAGE_SEPARATOR + info)
                    return user_id
                _send_raw(client, AUTH_FAIL_PREFIX + info)
                continue

            # Anything else before authentication is invalid.
            _send_raw(client, AUTH_FAIL_PREFIX + REASON_BAD_REQUEST)
        except Exception:
            # Log the full traceback server-side so the real cause (e.g. a
            # PermissionError writing USERS_DB_PATH) is visible in the
            # Railway logs, but still give the client a clean response
            # instead of leaving it hanging until it times out.
            print('AUTH HANDLER ERROR:')
            traceback.print_exc()
            _send_raw(client, AUTH_FAIL_PREFIX + REASON_SERVER_ERROR)
            continue


def handle_client(client, addr):
    # Give each connection its own recv loop so a slow/idle client
    # never blocks the server from accepting new connections.
    try:
        my_id = _authenticate_client(client)
    except Exception:
        # Belt-and-braces: _authenticate_client already catches its own
        # errors and reports them to the client, but if a connection
        # drops mid-handshake (recv() raising) there's nothing to reply
        # to - just clean up quietly instead of crashing the thread.
        print(f'AUTH FAILED (connection error) for {addr}:')
        traceback.print_exc()
        client.close()
        return

    if my_id is None:
        client.close()
        print(f'connection closed before login: {addr}')
        return

    with clients_lock:
        clients[my_id] = client
    print(f'authenticated: {my_id}')

    try:
        while True:
            data = client.recv(4096)
            if not data:
                break  # client closed the connection

            data = data.decode('utf-8')
            print(data)

            # After login, the client is trusted to BE my_id, so it only
            # needs to send: message + SEPARATOR + recipient_id. The
            # sender is always my_id - never taken from the client - so
            # one authenticated connection can't spoof another user's id.
            data_list = data.split(MESSAGE_SEPARATOR)
            if len(data_list) < 2:
                print('malformed message, ignoring:', data_list)
                continue

            message, recipient_id = data_list[0], data_list[1]
            sevto_msg(my_id, message, recipient_id)
    except Exception as error:
        print('connection error:', error)
    finally:
        with clients_lock:
            if clients.get(my_id) is client:
                del clients[my_id]
        client.close()
        print(f'connection closed: {addr}')


retry_thread = threading.Thread(
    target=retry_unsent_messages,
    name='unsent-message-retry-worker',
    daemon=True,
)
retry_thread.start()

while True:
    try:
        client, addr = server.accept()
        print('new connection from', addr)
        thread = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        thread.start()
    except Exception as error:
        print('accept error:', error)
