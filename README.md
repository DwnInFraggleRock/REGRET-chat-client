# REGRET Chat Client


Python-based encrypted chat client. Uses a self hosted server with a terminal client with end-to-end encryption via X25519 + AES-GCM over TLS.

---

## Features

- End-to-end encryption (X25519 key exchange + AES-GCM)
- TLS transport layer (minimum TLS 1.2)
- Password authentication with PBKDF2-SHA256 hashing
- Broadcast messaging and direct messages (DMs)


---

## Requirements

- Python 3.8+
- The following packages: cryptography , colorama
  ```
  pip install cryptography colorama
  ```

---

# Server Setup

### 1. Choose a machine

The server can run on any machine you have access to. A Linux-based system is recommended a VPS works well for persistent hosting.

### 2. Generate a TLS certificate

The server requires a TLS certificate and private key. If you are only useing this for personal use, run the following on your server:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

You will be prompted to fill in certificate details. These can be left at their defaults for a self-signed cert. This produces two files:

- `cert.pem` -> the certificate 
- `key.pem` -> the private key (do not share this file)

## Note : 
If this is not for personal use, use a proper TLS certificate, and modify `client.py` for a proper TLS.


### 3. Run the server

```bash
python3 server.py --port 5000 --cert cert.pem --key key.pem
```

The server will start listening on the specified port (in this example that is port 5000). Make sure that port is open in your firewall or cloud provider's security rules.

---

# Client Setup

### 1. Get the certificate

If you are requiring the TLS certificate (by delfault this is set to false in `client.py`) Copy `cert.pem` from the server to your local machine. This is required for the client to verify the TLS connection. You can transfer it using `scp`:

```bash
scp user@your-server-ip:/path/to/cert.pem ./cert.pem
```

### 2. Run the client

```bash
python3 client.py
```

The client will prompt you for:

- **Server address** -> the IP or hostname of your server
- **Port** -> the port the server is running on 
- **Username and password** -> used to authenticate with the server

*On first connection, your account is created automatically.*

### 3. Connecting over the network

If you are connecting to a remote server, make sure you have the correct IP address or domain name. If the server is on a cloud VM, use its public IP. It is recommended to reserve a static IP on your cloud provider to avoid the address changing.

---

## Usage

Once connected, you can:

- **Send a message to everyone:** Just type and press Enter
- **Send a direct message:** Type `@username your message`
- **See who is online:** Type `/users`

---
## DEV Notes

- This is by no means a service garentee, this was a simple networking project I devolped to have fun. 

---

## License

MIT