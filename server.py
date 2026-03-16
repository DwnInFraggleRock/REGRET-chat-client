#!/usr/bin/env python3

import sys

REQUIRED = ["colorama", "cryptography"]

def check_dependencies():
    missing = []
    for package in REQUIRED:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    if missing:
        print(f"Missing required packages: {', '.join(missing)}")
        print(f"Install them with:  pip install {' '.join(missing)}")
        print(f"Or install all at once:  pip install -r requirements.txt")
        sys.exit(1)

#────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

import socket, argparse, select, signal, json, os, threading, queue, ssl, hashlib, hmac, secrets

# ─── Globals ────────────────────────────────────────────────────────────────
server_socket = None
connected     = {}   # { clientID: socket }  registered clients
client_ids    = {}   # { socket: clientID }
public_keys   = {}   # { clientID: public_key_string }
msg_queue     = {}   # { clientID: [messages] } offline queue
pending       = []   # sockets connected but not yet registered
cmd_queue     = queue.Queue()
QUEUE_FILE    = "message_queue.json"
USERS_FILE    = "users.json"   # stores registered accounts + hashed passwords

# ─── Argument parsing ────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    # ① TLS: server needs a cert file and a matching private key file.
    #   For a real server use Let's Encrypt (certbot). For local testing use:
    #     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
    parser.add_argument("--cert", required=True, help="Path to TLS certificate (PEM)")
    parser.add_argument("--key",  required=True, help="Path to TLS private key (PEM)")
    return parser.parse_args()

# ─── Get local IP ────────────────────────────────────────────────────────────
def get_local_ip():
    try:
        temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp.connect(("8.8.8.8", 80))
        ip = temp.getsockname()[0]
        temp.close()
        return ip
    except Exception:
        return "0.0.0.0"

# ─── Queue persistence ───────────────────────────────────────────────────────
def save_queue():
    try:
        with open(QUEUE_FILE, "w") as f:
            json.dump(msg_queue, f)
    except Exception:
        pass

def load_queue():
    global msg_queue
    if os.path.exists(QUEUE_FILE):
        try:
            with open(QUEUE_FILE, "r") as f:
                msg_queue = json.load(f)
        except Exception:
            msg_queue = {}

# ─── User / password store ───────────────────────────────────────────────────
# ② Passwords are NEVER stored in plaintext.
#    Each password is stretched with PBKDF2-HMAC-SHA256 using a unique random
#    32-byte salt and 260 000 iterations (OWASP 2023 recommendation).
#    Even if someone steals users.json they cannot reverse the passwords.
#    On-disk format:
#      { "alice": { "salt": "<hex>", "hash": "<hex>" }, ... }

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(password, salt_hex=None):
    # Generate a fresh random salt for new accounts; reuse stored salt to verify.
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex(), digest.hex()

def verify_password(password, salt_hex, stored_hash_hex):
    # ③ hmac.compare_digest prevents timing attacks — it always takes the same
    #    amount of time regardless of where the strings differ.
    _, candidate_hex = hash_password(password, salt_hex)
    return hmac.compare_digest(candidate_hex, stored_hash_hex)

def register_user(client_id, password):
    """Persist a new account. Returns False if name already exists."""
    users = load_users()
    if client_id in users:
        return False
    salt_hex, hash_hex = hash_password(password)
    users[client_id] = {"salt": salt_hex, "hash": hash_hex}
    save_users(users)
    return True

def authenticate_user(client_id, password):
    """Return True only if client_id exists AND password matches."""
    users = load_users()
    entry = users.get(client_id)
    if not entry:
        return False
    return verify_password(password, entry["salt"], entry["hash"])

# ─── Shutdown ────────────────────────────────────────────────────────────────
def shutdown(exit_code=0):
    save_queue()
    for sock in list(connected.values()):
        try:
            sock.sendall("INFO\r\nmessage: Server shutting down.\r\nevent: shutdown\r\n\r\n".encode())
            sock.close()
        except Exception:
            pass
    if server_socket:
        try:
            server_socket.close()
        except Exception:
            pass
    sys.exit(exit_code)

def handle_sigint(sig, frame):
    print("\nShutting down.")
    shutdown(0)

signal.signal(signal.SIGINT, handle_sigint)

# ─── Message parser ──────────────────────────────────────────────────────────
def parse_message(raw):
    lines = raw.strip().split("\r\n")
    if not lines:
        return None, {}
    msg_type = lines[0].strip()
    headers = {}
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key.strip()] = value.strip()
    return msg_type, headers

# ─── Helpers ─────────────────────────────────────────────────────────────────
def broadcast(message, exclude_id=None):
    for cid, sock in list(connected.items()):
        if cid == exclude_id:
            continue
        try:
            sock.sendall(message.encode())
        except Exception:
            remove_client(sock)

def send_to(client_id, message):
    sock = connected.get(client_id)
    if sock:
        try:
            sock.sendall(message.encode())
            return True
        except Exception:
            remove_client(sock)
    return False

def remove_client(sock):
    cid = client_ids.pop(sock, None)
    if cid:
        connected.pop(cid, None)
    if sock in pending:
        pending.remove(sock)
    try:
        sock.close()
    except Exception:
        pass
    return cid

def queue_offline(recipient_id, message):
    if recipient_id not in msg_queue:
        msg_queue[recipient_id] = []
    msg_queue[recipient_id].append(message)
    save_queue()
    print(f"Queued message for offline user {recipient_id}")

def flush_queue(client_id):
    if client_id in msg_queue and msg_queue[client_id]:
        print(f"Delivering {len(msg_queue[client_id])} queued messages to {client_id}")
        for message in msg_queue[client_id]:
            send_to(client_id, message)
        del msg_queue[client_id]
        save_queue()

# ─── Handle incoming data from any socket ────────────────────────────────────
def handle_data(sock):
    try:
        data = sock.recv(4096).decode()
    except Exception as e:
        cid = remove_client(sock)
        if cid:
            print(f"{cid} disconnected (error: {e})")
            broadcast(
                f"INFO\r\nmessage: {cid} has left.\r\nclientID: {cid}\r\nevent: leave\r\n\r\n",
                exclude_id=cid
            )
        return

    if not data:
        cid = remove_client(sock)
        if cid:
            print(f"{cid} disconnected")
            broadcast(
                f"INFO\r\nmessage: {cid} has left.\r\nclientID: {cid}\r\nevent: leave\r\n\r\n",
                exclude_id=cid
            )
        return

    msg_type, headers = parse_message(data)
    print(f"Received {msg_type} from {client_ids.get(sock, 'unregistered')}")

    # ── REGISTER ─────────────────────────────────────────────────────────
    # ④ REGISTER now requires a `password` header.
    #    First connection with a new name  → account is created automatically.
    #    Subsequent connections with that name → password must match.
    #    Wrong password → connection is dropped immediately.
    if msg_type == "REGISTER":
        client_id  = headers.get("clientID", "")
        password   = headers.get("password", "")   # ④ new required field
        public_key = headers.get("publicKey", "")
        client_ip  = headers.get("IP", "")

        # Enforce alphanumeric names server-side (don't trust the client)
        if not client_id or not client_id.isalnum():
            try:
                sock.sendall("ERROR\r\nmessage: Missing or invalid clientID.\r\n\r\n".encode())
            except Exception:
                pass
            remove_client(sock)
            return

        if not password:
            try:
                sock.sendall("ERROR\r\nmessage: Missing password.\r\n\r\n".encode())
            except Exception:
                pass
            remove_client(sock)
            return

        users = load_users()
        if client_id in users:
            # Known account — verify password before doing anything else
            if not authenticate_user(client_id, password):
                try:
                    sock.sendall("ERROR\r\nmessage: Wrong password.\r\n\r\n".encode())
                except Exception:
                    pass
                remove_client(sock)
                print(f"AUTH FAIL: {client_id} from {client_ip}")
                return
            print(f"AUTH OK: {client_id}")
        else:
            # Brand-new name — register it now
            register_user(client_id, password)
            print(f"NEW ACCOUNT: {client_id}")

        if client_id in connected:
            try:
                sock.sendall("ERROR\r\nmessage: Already connected from another session.\r\n\r\n".encode())
                sock.close()
            except Exception:
                pass
            if sock in pending:
                pending.remove(sock)
            return

        # Move from pending → registered
        if sock in pending:
            pending.remove(sock)
        connected[client_id]   = sock
        client_ids[sock]       = client_id
        public_keys[client_id] = public_key
        print(f"REGISTER: {client_id} from {client_ip}")

        member_list = ", ".join(connected.keys())
        try:
            sock.sendall((
                "REGACK\r\n"
                f"clientID: {client_id}\r\n"
                f"members: {member_list}\r\n"
                "\r\n"
            ).encode())
            print(f"Sent REGACK to {client_id}")
        except Exception as e:
            print(f"Error sending REGACK to {client_id}: {e}")
            return

        broadcast(
            f"INFO\r\nmessage: {client_id} has joined.\r\nclientID: {client_id}\r\nevent: join\r\n\r\n",
            exclude_id=client_id
        )
        flush_queue(client_id)

    # ── GETKEY ───────────────────────────────────────────────────────────
    elif msg_type == "GETKEY":
        target_id  = headers.get("clientID", "")
        public_key = public_keys.get(target_id, "")
        if not public_key:
            try:
                sock.sendall(f"ERROR\r\nmessage: No key for {target_id}.\r\n\r\n".encode())
            except Exception:
                pass
            return
        try:
            sock.sendall((
                "KEYACK\r\n"
                f"clientID: {target_id}\r\n"
                f"publicKey: {public_key}\r\n"
                "\r\n"
            ).encode())
        except Exception as e:
            print(f"Error sending KEYACK: {e}")

    # ── CHAT ─────────────────────────────────────────────────────────────
    elif msg_type == "CHAT":
        sender_id    = client_ids.get(sock, "unknown")
        recipient_id = headers.get("to", "")
        message      = headers.get("message", "")

        if recipient_id:
            dm_flag = headers.get("dm", "")
            relay = (
                f"CHAT\r\n"
                f"clientID: {sender_id}\r\n"
                f"to: {recipient_id}\r\n"
                + (f"dm: {dm_flag}\r\n" if dm_flag else "")
                + f"message: {message}\r\n"
                "\r\n"
            )
            if recipient_id in connected:
                send_to(recipient_id, relay)
            else:
                queue_offline(recipient_id, relay)
        else:
            relay = (
                f"CHAT\r\n"
                f"clientID: {sender_id}\r\n"
                f"message: {message}\r\n"
                "\r\n"
            )
            broadcast(relay, exclude_id=sender_id)

    # ── MEMBERS ──────────────────────────────────────────────────────────
    elif msg_type == "MEMBERS":
        member_list = ", ".join(connected.keys())
        try:
            sock.sendall((
                "MEMBERSACK\r\n"
                f"members: {member_list}\r\n"
                "\r\n"
            ).encode())
        except Exception as e:
            print(f"Error sending MEMBERSACK: {e}")

    # ── PING ─────────────────────────────────────────────────────────────
    elif msg_type == "PING":
        try:
            sock.sendall("PONG\r\n\r\n".encode())
        except Exception:
            remove_client(sock)

    # ── QUIT ─────────────────────────────────────────────────────────────
    elif msg_type == "QUIT":
        cid = client_ids.get(sock, "unknown")
        print(f"{cid} quit")
        remove_client(sock)
        broadcast(
            f"INFO\r\nmessage: {cid} has left.\r\nclientID: {cid}\r\nevent: leave\r\n\r\n"
        )

    # ── MALFORMED ────────────────────────────────────────────────────────
    else:
        print(f"Malformed message type: '{msg_type}'", file=sys.stderr)
        try:
            sock.sendall("ERROR\r\nmessage: Malformed message.\r\n\r\n".encode())
        except Exception:
            pass
        remove_client(sock)

# ─── Stdin reader thread ──────────────────────────────────────────────────────
def stdin_reader():
    while True:
        try:
            line = sys.stdin.readline()
            if line:
                cmd_queue.put(line.strip())
        except Exception:
            break

# ─── Process terminal command ─────────────────────────────────────────────────
def process_cmd(cmd):
    if cmd == "/info":
        if not connected:
            print("No clients connected.")
        else:
            print(f"{len(connected)} connected:")
            for cid in connected:
                print(f"  {cid}")
    elif cmd == "/users":
        # ⑤ new server command — shows all registered accounts
        users = load_users()
        print(f"{len(users)} registered: {', '.join(users.keys())}")
    elif cmd == "/quit":
        shutdown(0)
    elif cmd.startswith("/"):
        print("Unknown command. Available: /info, /users, /quit")

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    global server_socket

    args        = parse_args()
    server_port = args.port
    server_ip   = get_local_ip()

    load_queue()

    # ⑥ Build the TLS context.
    #    ssl.PROTOCOL_TLS_SERVER automatically negotiates TLS 1.2 or 1.3.
    #    We enforce a minimum of TLS 1.2 to block old broken versions.
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        tls_ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    except Exception as e:
        print(f"Failed to load TLS cert/key: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind(("0.0.0.0", server_port))
        raw_sock.listen(10)
        # ⑦ Wrap the listening socket in TLS.
        #    Every client that connects will now do a TLS handshake first.
        #    After accept() returns, the socket is already fully encrypted —
        #    no plaintext ever flows, including the REGISTER + password.
        server_socket = tls_ctx.wrap_socket(raw_sock, server_side=True)
    except socket.error as e:
        print(f"Failed to start server: {e}", file=sys.stderr)
        sys.exit(1)

    print("----------------------------------------")
    print("|     Encrypted Relay Chat Server      |")
    print("----------------------------------------")
    print(f"Listening on {server_ip}:{server_port} (TLS enabled)")
    print("Commands: /info, /users, /quit\n")

    t = threading.Thread(target=stdin_reader, daemon=True)
    t.start()

    while True:
        watch = [server_socket] + pending + list(connected.values())

        try:
            readable, _, _ = select.select(watch, [], [], 1.0)
        except Exception as e:
            print(f"Select error: {e}", file=sys.stderr)
            continue

        while not cmd_queue.empty():
            process_cmd(cmd_queue.get())

        for source in readable:
            if source is server_socket:
                try:
                    conn, addr = server_socket.accept()
                    # conn is already a TLS SSLSocket — handshake done inside accept()
                    pending.append(conn)
                    print(f"New TLS connection from {addr[0]}:{addr[1]}")
                except ssl.SSLError as e:
                    print(f"TLS handshake failed: {e}", file=sys.stderr)
                except socket.error as e:
                    print(f"Accept error: {e}", file=sys.stderr)
            else:
                handle_data(source)

if __name__ == "__main__":
    main()