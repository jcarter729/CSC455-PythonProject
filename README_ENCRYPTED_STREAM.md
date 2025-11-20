Encrypted Python-to-Python Video Stream (AES-GCM)
===============================================

Files added:
- `crypto_utils.py` -- key derivation and AES-GCM helpers
- `enc_stream_server.py` -- TCP server: receives encrypted JPEG frames, decrypts and displays
- `enc_stream_client.py` -- TCP client: captures camera, JPEG-encodes, encrypts and sends frames
- `requirements.txt` -- dependencies

Quick setup
-----------
1. Install dependencies (create venv recommended):

```powershell
python -m pip install -r requirements.txt
```

2. Put a passphrase in `secret.txt` (single line). The scripts will derive an AES-256 key from it.

Running
-------
1. Start the server on the machine that will display incoming video:

```powershell
python enc_stream_server.py
```

2. Start the client on the sending machine (change host to server IP):

```powershell
python enc_stream_client.py
```

Notes
-----
- This is a demo using a pre-shared passphrase. For production use implement proper key exchange (TLS/DTLS, Signal, or similar).
- The framing uses a 4-byte big-endian length followed by a 12-byte nonce, 16-byte tag, then ciphertext.
- If frames fail to decrypt, they will be dropped.
