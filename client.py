#!/usr/bin/env python3

import sys, socket, signal, os, json, base64, time, threading, ssl, getpass

# ---------------------------------------------------------------------------------------------------
# checks to see if the user has the needed imports, if not throw error to help them install. 

_REQUIRED = ["colorama", "cryptography"]
_missing  = []
for _pkg in _REQUIRED:
    try:
        __import__(_pkg)
    except ImportError:
        _missing.append(_pkg)
if _missing:
    print(f"--------------------------------------------")
    print(f"ERROR: Missing required packages: {', '.join(_missing)}")
    print(f"SOLUTION: Run:  pip install {' '.join(_missing)}")
    print(f"--------------------------------------------")
    print(f"USAGES: \ncolorama -> Adds color to UserIDs and Error Messages")
    print(f"cryptography -> provides the X25519 key exchange, AES-GCM encryption, \n                and HKDF key derivation that powers the end-to-end encryption.") # dont worry about that space trust its needed
    print(f"--------------------------------------------")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED=YELLOW=GREEN=CYAN=MAGENTA=BLUE=WHITE=LIGHTBLACK_EX=""
        LIGHTCYAN_EX=LIGHTGREEN_EX=LIGHTYELLOW_EX=LIGHTMAGENTA_EX=""
        LIGHTBLUE_EX=LIGHTRED_EX=""
    class Style:
        RESET_ALL=BRIGHT=DIM=""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------------------------------
# globals 
server_sock    = None
client_id      = None
private_key    = None
public_key     = None
_prompt_shown        = False
_no_one_msg_count    = 0
shared_secrets = {}
name_colors    = {}

OTHER_COLOR_POOL = [
    Fore.MAGENTA, Fore.BLUE,
    Fore.LIGHTCYAN_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTBLUE_EX,
    Fore.LIGHTRED_EX, Fore.LIGHTYELLOW_EX
]
color_pool_index = 0

sock_lock        = threading.Lock()
existing_members = []

# ---------------------------------------------------------------------------------------------------
# key encryption 
def generate_keypair():
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()

def serialize_public_key(pub):
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()

def deserialize_public_key(key_str):
    raw = base64.b64decode(key_str)
    return X25519PublicKey.from_public_bytes(raw)

def derive_shared_secret(priv, peer_pub):
    shared = priv.exchange(peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"signal-style-chat"
    ).derive(shared)

def encrypt_message(shared_secret, plaintext):
    aesgcm = AESGCM(shared_secret)
    nonce  = os.urandom(12)
    ct     = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_message(shared_secret, ciphertext):
    try:
        raw   = base64.b64decode(ciphertext)
        nonce = raw[:12]
        ct    = raw[12:]
        return AESGCM(shared_secret).decrypt(nonce, ct, None).decode()
    except Exception:
        return "[could not decrypt]"

def save_keys(priv, pub, filename):
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    with open(filename, "w") as f:
        json.dump({
            "private": base64.b64encode(priv_bytes).decode(),
            "public":  base64.b64encode(pub_bytes).decode()
        }, f)

def load_keys(filename):
    with open(filename, "r") as f:
        data = json.load(f)
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(data["private"]))
    return priv, priv.public_key()

# ---------------------------------------------------------------------------------------------------
# color helper functions 
def color_for(name):
    global color_pool_index
    if name == client_id:
        return Fore.CYAN
    if name not in name_colors:
        color = OTHER_COLOR_POOL[color_pool_index % len(OTHER_COLOR_POOL)]
        name_colors[name] = color
        color_pool_index += 1
    return name_colors[name]

# wrapers for colored text using colorama
def colored_name(name):
    return f"{color_for(name)}{Style.BRIGHT}{name}{Style.RESET_ALL}"

def info(text):    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
def keyinfo(text): return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"
def warn(text):    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
def error(text):   return f"{Fore.RED}{text}{Style.RESET_ALL}"
def dim(text):     return f"{Style.DIM}{text}{Style.RESET_ALL}"

# ---------------------------------------------------------------------------------------------------
# helper functions for the network

# gets local ip and stores it, if none return loop ip
def get_local_ip():
    try:
        temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp.connect(("8.8.8.8", 80))
        ip = temp.getsockname()[0]
        temp.close()
        return ip
    except Exception:
        return "127.0.0.1"

# parses the server address for the terminal input 
def parse_server_address(s):
    try:
        ip, port = s.split(":")
        return ip, int(port)
    except ValueError:
        print("Invalid format. Use IP:port")
        sys.exit(1)

# parses messages
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

# ---------------------------------------------------------------------------------------------------
# encodes your message contents and sends it over the wire 
def send_raw(msg):
    with sock_lock:
        try:
            server_sock.sendall(msg.encode())
        except socket.error as e:
            print(f"\nConnection lost: {e}")
            os._exit(1)

# ---------------------------------------------------------------------------------------------------
# shutdown handler
def shutdown(exit_code=0):
    global server_sock
    if server_sock:
        try:
            server_sock.sendall("QUIT\r\n\r\n".encode())
            server_sock.close()
        except Exception:
            pass
        server_sock = None
    os._exit(exit_code)

def handle_sigint(sig, frame):
    print("\nExiting.")
    shutdown(0)

signal.signal(signal.SIGINT, handle_sigint)

# ---------------------------------------------------------------------------------------------------
# key exchange handler 
keyack_cache = {}
keyack_event = threading.Event()

def establish_secret_with(peer_id):
    if peer_id in shared_secrets:
        return True

    keyack_event.clear()
    with sock_lock:
        try:
            server_sock.sendall(f"GETKEY\r\nclientID: {peer_id}\r\n\r\n".encode())
        except Exception:
            return False

    keyack_event.wait(timeout=5)

    peer_pub_str = keyack_cache.pop(peer_id, None)
    if not peer_pub_str:
        return False

    peer_pub                = deserialize_public_key(peer_pub_str)
    shared_secrets[peer_id] = derive_shared_secret(private_key, peer_pub)
    return True

# ---------------------------------------------------------------------------------------------------
# force print, prints above your current [ ClientID > msg ]
# also marks the prompt as shown since it redraws it
def print_above(text):
    global _prompt_shown
    sys.stdout.write(f"\r{text}\n{Fore.CYAN}{Style.BRIGHT}{client_id}{Style.RESET_ALL} > ")
    sys.stdout.flush()
    _prompt_shown = True

# ---------------------------------------------------------------------------------------------------
# message handler for the server, takes all incoming messages -> gets their type -> does shit
def handle_server_message(data):
    if not data:
        print("\nServer disconnected.")
        os._exit(0)

    msg_type, headers = parse_message(data)

    if msg_type == "CHAT":
        sender    = headers.get("clientID", "unknown")
        target    = headers.get("to", "")
        is_dm     = headers.get("dm", "") == "true"
        encrypted = headers.get("message", "")

        if sender not in shared_secrets:
            if not establish_secret_with(sender):
                print_above(error(f"[Could not decrypt previous message from {sender}]"))
                return

        plaintext = decrypt_message(shared_secrets[sender], encrypted)

        if is_dm:
            dm_label = f"{Fore.LIGHTGREEN_EX}{Style.BRIGHT}"
            if sender == client_id:
                print_above(f"{dm_label}DM to{Style.RESET_ALL} {colored_name(target)} > {plaintext}")
            else:
                print_above(f"{dm_label}DM from{Style.RESET_ALL} {colored_name(sender)} > {plaintext}")
        else:
            print_above(f"{colored_name(sender)} > {plaintext}")

    elif msg_type == "INFO":
        message   = headers.get("message", "")
        event     = headers.get("event", "")
        joined_id = headers.get("clientID", "")
        if event == "shutdown":
            print(error("\nServer is shutting down. Goodbye!"))
            os._exit(0)
        else:
            print_above(warn(f"*** {message} ***"))
            if event == "join" and joined_id and joined_id != client_id:
                if joined_id not in existing_members:
                    existing_members.append(joined_id)
                if establish_secret_with(joined_id):
                    print_above(info(f"[Secure connection established with {joined_id}]"))

    elif msg_type == "MEMBERSACK":
        raw_members = headers.get("members", "none")
        colored_members = ", ".join(
            colored_name(m.strip()) for m in raw_members.split(",") if m.strip()
        )
        print_above(warn(f"*** Online: ") + colored_members + warn(" ***"))

    elif msg_type == "KEYACK":
        peer_id      = headers.get("clientID", "")
        peer_pub_str = headers.get("publicKey", "")
        if peer_id and peer_pub_str:
            keyack_cache[peer_id] = peer_pub_str
            keyack_event.set()

    elif msg_type == "PONG":
        pass

    elif msg_type == "ERROR":
        print_above(error(f"[Error: {headers.get('message', '')}]"))

    elif msg_type == "QUIT":
        print("\nDisconnected by server.")
        os._exit(0)

# ---------------------------------------------------------------------------------------------------
# handles lost connections with the server
def receive_thread():
    while True:
        try:
            data = server_sock.recv(4096).decode()
        except Exception:
            print("\nConnection lost.")
            os._exit(1)
        if not data:
            print("\nServer disconnected.")
            os._exit(0)
        handle_server_message(data)

# ---------------------------------------------------------------------------------------------------
# ping server to see if connection still is up, if no pong response, kill connection
def heartbeat_thread():
    while server_sock:
        time.sleep(25)
        try:
            with sock_lock:
                if server_sock:
                    server_sock.sendall("PING\r\n\r\n".encode())
        except Exception:
            break

# ---------------------------------------------------------------------------------------------------
# reprints the userID prompt only if it hasn't already been drawn
def show_prompt(client_id):
    global _prompt_shown
    if not _prompt_shown:
        sys.stdout.write(f"{Fore.CYAN}{Style.BRIGHT}{client_id}{Style.RESET_ALL} > ")
        sys.stdout.flush()
        _prompt_shown = True

# ---------------------------------------------------------------------------------------------------
# handles all messages typed into the terminal
def handle_input(line):
    global _no_one_msg_count, _prompt_shown
    line = line.rstrip("\n").rstrip("\r")
    sent = False

    # performs quit
    if line == "/quit":
        print("Goodbye!")
        shutdown(0)

    # lists all connected members to the chat room
    elif line == "/members":
        send_raw("MEMBERS\r\n\r\n")

    # shows your userID
    elif line == "/id":
        print_above(f"Your ID: {client_id}")

    # parses and handles DMs to users
    elif line.startswith("/dm "):
        parts = line.split(" ", 2)
        if len(parts) < 3:
            print_above("Usage: /dm <name> <message>")
        else:
            target  = parts[1]
            message = parts[2]
            if not establish_secret_with(target):
                print_above(f"Could not establish secure connection with {target}")
                print_above(warn(f"Reconnecting with {target} . . ."))
            else:
                encrypted = encrypt_message(shared_secrets[target], message)
                send_raw(
                    f"CHAT\r\nclientID: {client_id}\r\nto: {target}\r\ndm: true\r\nmessage: {encrypted}\r\n\r\n"
                )
                print_above(f"DM to {colored_name(target)} > {message}")

    # they attempted to write a command and we dont know what it was so list all commands to help out
    elif line.startswith("/"):
        print_above("Unknown command. Available: /members, /dm <name> <msg>, /id, /quit")

    # checks to see if a connection exists for the users, if it doesn't, establish it
    elif line.strip():
        for member in existing_members:
            if member == client_id:
                continue
            if member not in shared_secrets:
                establish_secret_with(member)
            if member in shared_secrets:
                encrypted = encrypt_message(shared_secrets[member], line)
                send_raw(
                    f"CHAT\r\nclientID: {client_id}\r\nto: {member}\r\nmessage: {encrypted}\r\n\r\n"
                )
                sent = True

        if not sent:
            _no_one_msg_count += 1
            if _no_one_msg_count == 1 or (_no_one_msg_count - 1) % 3 == 0:
                print_above(warn("[No one else is online yet]"))
            else:
                _prompt_shown = False  # force show_prompt to redraw since print_above was skipped
        time.sleep(0.05)
        show_prompt(client_id)

# ---------------------------------------------------------------------------------------------------
# MAIN
def main():
    global server_sock, client_id, private_key, public_key

    print(Fore.CYAN + "----------------------------------------")
    print(Fore.CYAN + "|           REGRET V1.2.6              |")
    print(Fore.CYAN + "----------------------------------------" + Style.RESET_ALL + "\n")

    server_str = input("Enter server address (IP:port): ").strip()
    server_ip, server_port = parse_server_address(server_str)
    client_ip  = get_local_ip()

    # TLS PROTOCOL
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_ctx.check_hostname  = False   # set True + cafile for production
    tls_ctx.verify_mode     = ssl.CERT_NONE  # set CERT_REQUIRED for production

    # asks user for ID again if ID was already in use or taken
    while True:
        # Get UserID
        while True:
            name = input("Enter your UserID: ").strip()
            if name and name.isalnum():
                client_id = name
                break
            print("UserID must be letters and numbers only.")

        # load or generate keypair for this name
        key_file = f"{client_id}_keys.json"
        if os.path.exists(key_file):
            private_key, public_key = load_keys(key_file)
            print(info(f"Loaded existing keys from {key_file}"))
        else:
            private_key, public_key = generate_keypair()
            save_keys(private_key, public_key, key_file)
            print(warn(f"No existing keypair . . . "))
            print(info(f"Generating a new keypair and saved to {key_file}"))
            print(keyinfo(f"You are a new User, the password you enter now will be saved \nIt can not be changed"))

        pub_key_str = serialize_public_key(public_key)

        # password loop, asks 3 times for password
        MAX_ATTEMPTS = 3
        session_in_use = False
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if attempt == 1:
                password = getpass.getpass("Enter password: ")
            else:
                password = getpass.getpass(f"Wrong password, try again ({attempt}/{MAX_ATTEMPTS}): ")

            if not password:
                print(error("Password cannot be empty."))
                continue

            # open a fresh TCP + TLS connection for each attempt.
            # the server closes the socket on wrong password so we must reconnect.
            print(f"\nConnecting to {server_ip}:{server_port}...")
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.connect((server_ip, server_port))
                # wrap the connected socket ( TLS handshake happens here )
                server_sock = tls_ctx.wrap_socket(raw_sock, server_hostname=server_ip)
                print(info(f"TLS connected ({server_sock.version()})"))
            except ssl.SSLError as e:
                print(error(f"TLS error: {e}"))
                sys.exit(1)
            except socket.error as e:
                print(error(f"Could not connect: {e}"))
                sys.exit(1)

            server_sock.sendall((
                f"REGISTER\r\n"
                f"clientID: {client_id}\r\n"
                f"password: {password}\r\n"
                f"IP: {client_ip}\r\n"
                f"publicKey: {pub_key_str}\r\n"
                "\r\n"
            ).encode())

            server_sock.settimeout(10)
            try:
                data = server_sock.recv(4096).decode()
            except socket.timeout:
                print(error("Timed out waiting for server response."))
                sys.exit(1)
            server_sock.settimeout(None)

            msg_type, headers = parse_message(data)

            if msg_type == "REGACK":
                # success — break all the way out
                members = headers.get("members", client_id)
                print(info("Registered successfully!"))
                colored_members = ", ".join(
                    colored_name(m.strip()) for m in members.split(",") if m.strip()
                )
                print(info("Currently online: ") + colored_members)
                existing_members[:] = [
                    m.strip() for m in members.split(",")
                    if m.strip() and m.strip() != client_id
                ]
                break

            elif msg_type == "ERROR":
                err_msg = headers.get("message", "unknown error")
                print(error(f"Error: {err_msg}"))
                try:
                    server_sock.close()
                except Exception:
                    pass

                if "Already connected" in err_msg:
                    print(warn("That name is already in an active session. Please choose a different name."))
                    session_in_use = True
                    break
                elif "Wrong password" in err_msg:
                    if attempt == MAX_ATTEMPTS:
                        print(error("Too many failed attempts. Exiting."))
                        sys.exit(1)
                else:
                    sys.exit(1)

            else:
                print(error(f"Unexpected response: {msg_type}"))
                sys.exit(1)

        # if we broke out of the password loop due to a successful REGACK, stop outer loop too
        if msg_type == "REGACK":
            break
        # if session was in use, outer loop continues and re-asks for name
        if not session_in_use:
            break

    threading.Thread(target=receive_thread, daemon=True).start()
    threading.Thread(target=heartbeat_thread, daemon=True).start()

    for member in existing_members:
        if establish_secret_with(member):
            print(info("Secure connection established with ") + colored_name(member))
        else:
            print(error(f"Could not establish secure connection with {member}"))

    print(warn("\n----------------------------------------"))
    print(warn("|     You are in the chat room         |"))
    print(warn("----------------------------------------"))
    print(info("\nCommands: /members, /dm <name> <msg>, /id, /quit"))
    print(info("\nJust type and press Enter to send to everyone.\n"))
    print(warn("-------------------------------------------------------------------"))

    sys.stdout.write(f"{Fore.CYAN}{Style.BRIGHT}{client_id}{Style.RESET_ALL} > ")
    sys.stdout.flush()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                shutdown(0)
            _prompt_shown = False  # user hit enter, prompt was consumed
            handle_input(line)
        except KeyboardInterrupt:
            shutdown(0)

if __name__ == "__main__":
    main()