# Real‑Time Encrypted Video Conferencing

This project demonstrates a bidirectional encrypted video conferencing system using Python, OpenCV, sockets, and PyCryptodome. Both participants can see each other's video feeds simultaneously with end-to-end encryption.

## Quick Start (Windows / PowerShell)

### Setup Environment

**Create a Python 3.11 venv and install dependencies:**
```powershell
py -3.11 -m venv .venv311
.\.venv311\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install opencv-python pycryptodome numpy
```

**Alternate (run without activating):**
```powershell
.\.venv311\Scripts\python.exe -m pip install --upgrade pip
.\.venv311\Scripts\python.exe -m pip install opencv-python pycryptodome numpy
```

### Running Bidirectional Video Chat

**Machine A (your computer):**
```powershell
.\.venv311\Scripts\Activate.ps1
python .\client.py
```
- When prompted, enter Machine B's IP address
- You'll see two windows: "You (Local)" and "Remote (Them)"

**Machine B (partner's computer):**
```powershell
.\.venv311\Scripts\Activate.ps1
python .\partner_client.py
```
- When prompted, enter Machine A's IP address
- You'll see two windows: "You (Local)" and "Remote (Them)"

### Firewall Setup Required

Both machines need these ports open:
```powershell
New-NetFirewallRule -DisplayName "Video Chat 9998" -Direction Inbound -LocalPort 9998 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Video Chat 9999" -Direction Inbound -LocalPort 9999 -Protocol TCP -Action Allow
```

## Notes & Troubleshooting

- **Server terminal blocks** — the server prints `Server listening...` and holds the terminal. Open a second terminal for the client.
- **`ModuleNotFoundError: No module named 'cv2'`** — make sure you installed packages into the same interpreter used to run the scripts. Using the `.venv311` Python above is recommended.
  - Check interpreter version:
    ```powershell
    .\.venv311\Scripts\python.exe --version
    .\.venv311\Scripts\python.exe -m pip --version
    ```
- **Camera can't open / MSMF errors** — Windows sometimes has issues with the default Media Foundation backend. If you see warnings about `videoio(MSMF)` or `can't grab frame`, try forcing DirectShow in the scripts or test manually:
  - Quick test (DirectShow):
    ```powershell
    .\.venv311\Scripts\python.exe -c "import cv2; cap=cv2.VideoCapture(0, cv2.CAP_DSHOW); print('opened', cap.isOpened()); ret,frame=cap.read(); print('read', ret); cap.release()"
    ```
  - To force DirectShow in the code, change `cv2.VideoCapture(0)` to `cv2.VideoCapture(0, cv2.CAP_DSHOW)` in `client.py` and/or `server.py`.
- **Camera sharing** — many webcams cannot be opened by two processes at the same time. If both server and client try to open the same physical webcam, one will fail. Workarounds:
  - Run the server first, then the client.
  - Use a prerecorded video file on one side: edit the capture call to `cv2.VideoCapture('sample.mp4')` for the client or server you want to simulate.
  - Use a virtual webcam driver (3rd-party) if you need two simultaneous webcam streams.

## Useful utilities

- Save the environment packages so you can recreate the venv later:
```powershell
.\.venv311\Scripts\python.exe -m pip freeze > requirements.txt
```

- Delete an unused venv to reclaim space (example: remove `./.venv` if you don't need it):
```powershell
Remove-Item -Recurse -Force .\.venv
```

## Files
- `client.py` – bidirectional video client for Machine A
- `partner_client.py` – bidirectional video client for Machine B  
- `server.py` – *(legacy, not used in bidirectional setup)*

## How It Works

### Bidirectional Architecture
Each machine runs a client that acts as both sender and receiver:

**Machine A (`client.py`):**
- Sends video TO Machine B on port 9999
- Receives video FROM Machine B on port 9998

**Machine B (`partner_client.py`):**
- Sends video TO Machine A on port 9998  
- Receives video FROM Machine A on port 9999

### Security Features
- **AES-GCM Encryption**: All video frames encrypted before transmission
- **Authenticated Encryption**: Prevents tampering with video data
- **Unique Nonces**: Each frame uses proper cryptographic nonces

## Testing Connectivity

**Check if partner is reachable:**
```powershell
Test-NetConnection -ComputerName [PARTNER_IP] -Port 9998
Test-NetConnection -ComputerName [PARTNER_IP] -Port 9999
```

**Find your IP address:**
```powershell
ipconfig
# Look for IPv4 Address under your active network adapter
```

## Single Machine Testing

For testing on one machine, you can run both clients:
1. Run `client.py` and enter `127.0.0.1` as partner IP
2. Run `partner_client.py` and enter `127.0.0.1` as partner IP

Note: This uses the same camera for both, so you'll see identical feeds.

Security note
- The example uses a symmetric AES key hardcoded in the scripts for demonstration. For any real deployment:
  - Use a secure key exchange (e.g., Diffie-Hellman over TLS) and unique keys per session.
  - Never hardcode long-term secrets into source files in production.\

