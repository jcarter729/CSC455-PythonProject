#Encrypted Video Chat

Real-time encrypted video conferencing between two computers. Both participants can see each other simultaneously with AES-GCM encryption.

## What This Does

- **Bidirectional Video**: Both people can see each other at the same time
- **End-to-End Encryption**: All video data is encrypted with AES-GCM
- **No Central Server**: Direct peer-to-peer connection between computers
- **Dynamic IP Support**: Enter partner's IP address at runtime

## Prerequisites

- **Python 3.11+** installed on both computers
- **Webcam** on both computers
- **Network connection** between computers (same WiFi/LAN or internet)
- **Windows PowerShell** (instructions below are for Windows)

## Setup Instructions

### Step 1: Install Dependencies (Both Computers)

Run these commands on **BOTH** computers:

```powershell
# Install required packages
pip install opencv-python pycryptodome numpy
```

### Step 2: Configure Firewall (Both Computers)

Open PowerShell as **Administrator** and run on **BOTH** computers:

```powershell
# Allow incoming connections on required ports
New-NetFirewallRule -DisplayName "Video Chat Port 9998" -Direction Inbound -LocalPort 9998 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Video Chat Port 9999" -Direction Inbound -LocalPort 9999 -Protocol TCP -Action Allow
```

### Step 3: Find IP Addresses

On **BOTH** computers, find your IP address:

```powershell
ipconfig
```

Look for the **IPv4 Address** under your active network adapter (example: `192.168.1.100`)

## Starting the Application

**IMPORTANT: Startup Order Matters!**

### Step 1: Partner (Computer B) Starts FIRST

Your partner at `172.26.85.81` must start first:

```powershell
python partner_client.py
```

Enter your IP address when prompted: `172.26.29.7`

You'll see: `Listening for incoming video on port 9999`

### Step 2: You (Computer A) Start SECOND

After your partner is listening, then you run:

```powershell
python client.py
```

Enter partner's IP when prompted: `172.26.85.81`

### Step 3: Connection Should Establish

Both should see:
- `Connected to [IP]:PORT for sending video`
- `Receiving video from [IP]`
- Two video windows appear

## ⚠️ If "Cleanup complete" Appears Immediately

This means connection failed. Try these fixes:

### Fix 1: Check Partner is Running First
- Partner MUST run `partner_client.py` first
- Wait for "Listening for incoming video on port 9999"
- Then you run `client.py`

### Fix 2: Test Basic Connection
```powershell
# You run this to test partner's port
Test-NetConnection -ComputerName 172.26.85.81 -Port 9999

# Partner runs this to test your port  
Test-NetConnection -ComputerName 172.26.29.7 -Port 9998
```

### Fix 3: Simple Socket Test
Have your partner run this first:
```powershell
python -c "import socket; s=socket.socket(); s.bind(('0.0.0.0', 9999)); s.listen(1); print('Ready on port 9999'); s.accept()"
```

Then you test connection:
```powershell
python -c "import socket; s=socket.socket(); s.connect(('172.26.85.81', 9999)); print('Connected!'); s.close()"
```

## 📺 What You'll See

Once connected, both computers will show:

- **"You (Local)"** window - Your own camera feed
- **"Remote (Them)"** window - Partner's camera feed

Press **'q'** in any window to disconnect.

## Troubleshooting

### Connection Issues

**Test connectivity between computers:**
```powershell
Test-NetConnection -ComputerName [PARTNER_IP] -Port 9998
Test-NetConnection -ComputerName [PARTNER_IP] -Port 9999
```

**If connection fails:**
- Verify IP addresses are correct
- Check firewall rules are applied
- Ensure both computers are on same network
- Try temporarily disabling Windows Firewall for testing

### Camera Issues

**If camera won't open:**
```powershell
# Test camera access
python -c "import cv2; cap=cv2.VideoCapture(0); print('Camera working:', cap.isOpened()); cap.release()"
```

**Force DirectShow if needed (add to code):**
```python
cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)  # Instead of cv2.VideoCapture(0)
```

### Port Already in Use

**Check what's using the ports:**
```powershell
netstat -an | findstr :9998
netstat -an | findstr :9999
```

**Kill processes if needed or restart computers**

## Internet/Remote Connections

For connections over the internet (not same network):

1. **Router Port Forwarding**: Forward ports 9998 and 9999 to your computer
2. **Use Public IP**: Use your router's public IP instead of local IP
3. **VPN Alternative**: Use VPN to create virtual LAN connection

## Security Notes

- **Shared Key**: Both computers use the same encryption key (hardcoded for demo)
- **Production Use**: Replace hardcoded key with proper key exchange
- **Network Security**: Use VPN for internet connections when possible

## Files

- `client.py` - Main client for Computer A
- `partner_client.py` - Client for Computer B  
- `server.py` - Legacy file (not used)

## Quick Test (Same Computer)

To test on a single computer:

1. Run `client.py` in one terminal, enter `127.0.0.1`
2. Run `partner_client.py` in another terminal, enter `127.0.0.1`
3. Both will use the same camera (you'll see identical feeds)

---

**Ready to start your encrypted video chat!** 🎉