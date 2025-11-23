# Real‑Time Encrypted Video Conferencing

This project demonstrates a simple encrypted video conferencing app using Python, OpenCV, sockets, and PyCryptodome.

## Quick Start (Windows / PowerShell)

Follow these exact commands to create a known-working environment and run both sides on one machine.

- **Create a Python 3.11 venv and install dependencies**
```powershell
py -3.11 -m venv .venv311
.\.venv311\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install opencv-python pycryptodome
```

- **(Alternate — run without activating)**
```powershell
.\.venv311\Scripts\python.exe -m pip install --upgrade pip
.\.venv311\Scripts\python.exe -m pip install opencv-python pycryptodome
```

- **Set the client to connect to the local server (one-machine test)**
  - Edit `client.py` and make sure the `HOST` line reads:
    ```python
    HOST = '127.0.0.1'
    ```
  - Or run this PowerShell one-liner (it replaces the HOST line automatically):
    ```powershell
(Get-Content client.py) -replace "HOST = '.*'","HOST = '127.0.0.1'" | Set-Content client.py
    ```

- **Run the server (Terminal 1)**
```powershell
# activate venv (optional)
.\.venv311\Scripts\Activate.ps1
# or run directly without activating:
.\.venv311\Scripts\python.exe .\server.py
```

- **Run the client (Terminal 2 — new terminal)**
```powershell
.\.venv311\Scripts\Activate.ps1
python .\client.py
# or without activating:
.\.venv311\Scripts\python.exe .\client.py
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
- `server.py` – listens for incoming video
- `client.py` – connects and sends video

## Quick Test (one machine)

1. Create & install the venv as shown above.
2. Ensure `client.py` has `HOST = '127.0.0.1'`.
3. In Terminal 1 run the server:
   ```powershell
   .\.venv311\Scripts\python.exe .\server.py
   ```
4. In Terminal 2 run the client:
   ```powershell
   .\.venv311\Scripts\python.exe .\client.py
   ```
5. Press `q` in either OpenCV window to quit.

If anything fails, copy the exact error output and paste it into an issue or here — the README intentionally includes the most common fixes so you don't need to repeat the setup process.

## Run on Different Machines (server + client on separate computers)

Follow these steps when the server and client are on different machines on the same LAN or over the internet.

Important: The server must be reachable from the client on the TCP port (default `9999`). If the machines are on different networks (internet), you will need to configure router port forwarding or use VPN.

Server machine (public or LAN server)

1. Create/activate the same venv and install dependencies (run in PowerShell on the server):
```powershell
py -3.11 -m venv .venv311
.\.venv311\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install opencv-python pycryptodome
```

2. Find the server's IP address (use the address reachable by the client):
```powershell
ipconfig
# Look for the IPv4 Address under the active network adapter (e.g. 192.168.1.42)
```

3. Make sure the server's TCP port is open (example: allow port 9999 in Windows Firewall):
```powershell
New-NetFirewallRule -DisplayName "Allow 9999" -Direction Inbound -LocalPort 9999 -Protocol TCP -Action Allow
```

4. Run the server (replace `.<venv>` path if needed):
```powershell
.\.venv311\Scripts\python.exe .\server.py
```

Client machine

1. Create/activate the venv and install dependencies exactly as on the server (see server step 1).

2. Set the `HOST` in `client.py` to the server's IP (example 192.168.1.42) or run this one-liner to replace it:
```powershell
(Get-Content client.py) -replace "HOST = '.*'","HOST = '192.168.1.42'" | Set-Content client.py
```

3. Test connectivity to the server from the client (replace with your server IP):
```powershell
Test-NetConnection -ComputerName 192.168.1.42 -Port 9999
# or use: tnc 192.168.1.42 -Port 9999
```

4. Run the client:
```powershell
.\.venv311\Scripts\python.exe .\client.py
```

Notes for internet (non-LAN) setups
- If the server is behind a home router, enable port forwarding on the router from the public port (e.g. 9999) to the server's LAN IP and port 9999.
- For public exposure, prefer using a secure tunnel (SSH, VPN) or a proper TURN/STUN signaling stack — this example does not include NAT traversal or authentication.

Security note
- The example uses a symmetric AES key hardcoded in the scripts for demonstration. For any real deployment:
  - Use a secure key exchange (e.g., Diffie-Hellman over TLS) and unique keys per session.
  - Never hardcode long-term secrets into source files in production.

If you want, I can add a short checklist to the README for router port forwarding, or patch the code to accept `--host`/`--port` command-line arguments so you don't edit the file each time.

