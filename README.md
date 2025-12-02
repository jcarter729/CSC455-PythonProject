# Encrypted Video Chat Application

## Overview

This is a peer-to-peer encrypted video chat application built with Python. Users can create or join video chat rooms and communicate securely with end-to-end encryption.

## Prerequisites

- Python 3.8 or higher
- Webcam/camera device
- Network connection (same local network for LAN connections)

## Required Dependencies

Install the following Python packages:

```bash
pip install opencv-python
pip install numpy
pip install pycryptodome
pip install pillow
pip install pymongo
```

Or create a `requirements.txt` file with:

```
opencv-python
numpy
pycryptodome
pillow
pymongo
```

Then install with:

```bash
pip install -r requirements.txt
```

## Setup

1. Clone or download the repository
2. Ensure you have all dependencies installed
3. (Optional) Configure MongoDB connection by creating a `.env` file with:
   ```
   MONGO_URI=your_mongodb_connection_string
   ```
   If MongoDB is not available, the app will use local JSON files for data storage.

## Running the Application

### Start the Application

```bash
python tk_video_rooms.py
```

### First Time Setup

1. When the application starts, you'll see the main room list window
2. Click "Account" button to create a user account or login
3. Enter a username and password to create your account
4. After logging in, your username will be displayed at the bottom of the window

### Creating a Video Chat Room

1. Click the "Create Room" button
2. Enter a room name
3. (Optional) Set a password for the room
4. The room will appear in the available rooms list
5. Double-click the room to join as the host

### Joining an Existing Room

1. Select a room from the available rooms list
2. Click "Join Room" button
3. If the room is password-protected, enter the correct password
4. The video chat window will open

### Starting Video Chat

1. Once in a room, click the "Start" button to activate your camera
2. Your local video feed will appear on the left panel
3. The right panel shows the remote partner's video feed
4. Wait for your partner to join and start their camera
5. The application will automatically connect when both users are ready

### Room Discovery

- The application uses UDP broadcast for automatic room discovery on the local network
- Rooms created by other users on the same network will appear in your room list
- The host's connection information is automatically shared when they start their camera

### Ending a Session

1. Click "Stop" to stop your camera feed
2. Click "Exit" to leave the room
3. If you're the host, you can choose to delete the room when exiting

## How It Works

### Architecture

The application uses a hybrid peer-to-peer architecture with the following components:

**1. Room Management**
- Rooms are stored locally in JSON files or MongoDB
- Each room has a unique ID, name, optional password, and owner information
- Room metadata is persisted across sessions

**2. Network Discovery**
- UDP broadcast on port 37020 for room discovery
- Hosts broadcast their room information every 2 seconds
- Clients listen for broadcasts to discover available rooms automatically

**3. Video Streaming**
- Peer-to-peer TCP connections for video transmission
- Each user opens a random port for receiving video
- OpenCV captures frames from the webcam
- Frames are compressed as JPEG before transmission

**4. Encryption**
- End-to-end AES-256-GCM encryption for all video data
- Encryption key derived from room password using PBKDF2
- Each frame is individually encrypted with a unique nonce
- Authentication tags ensure data integrity

**5. Connection Flow**

When a user starts their camera:
- Opens a TCP server socket on a random available port
- Stores their IP and port in the database
- Begins broadcasting connection info (if host)
- Starts a receive thread waiting for incoming connections
- Attempts to connect to partner's port for sending video

When both users are ready:
- Each user connects to the other's receive port
- Two TCP connections are established (one for each direction)
- Video frames are captured, encrypted, and sent continuously
- Received frames are decrypted and displayed in real-time

**6. Data Storage**

The application uses a dual-storage approach:
- Primary: MongoDB (if configured) for user accounts and room data
- Fallback: Local JSON files (`rooms.json`, `users.json`)
- User passwords are hashed using SHA-256
- IP addresses and ports are stored encrypted in the database

### Security Features

- Password-protected rooms
- AES-256-GCM encryption for video streams
- Hashed password storage
- Encrypted storage of connection information
- Per-frame encryption with unique nonces

### Technical Components

**Frontend**
- Tkinter GUI for user interface
- Dual video panels (local and remote)
- Real-time video display using PIL/ImageTk

**Backend**
- OpenCV for camera capture and frame processing
- Socket programming for network communication
- Threading for concurrent operations
- PyCryptodome for encryption

**Database**
- MongoDB (optional) for persistent storage
- JSON file fallback for offline operation
- User authentication and room management

## Troubleshooting

**Camera not working:**
- Ensure no other application is using the camera
- Check camera permissions in your OS settings
- The app will try DirectShow backend on Windows if initial capture fails

**Cannot connect to partner:**
- Ensure both users are on the same local network
- Check that firewall isn't blocking the application
- Verify both users entered the same room password
- Make sure both users clicked "Start" to begin streaming

**Room not appearing:**
- Click "Refresh" to update the room list
- Check that UDP port 37020 is not blocked
- Ensure you're on the same network as the room host

**Connection drops:**
- Check network stability
- Ensure firewalls allow the application through
- Verify both users have stable network connections

## Network Requirements

- Same local network (LAN/WiFi) for automatic discovery
- Open UDP port 37020 for room discovery
- Random TCP ports for video streaming (system-assigned)
- Firewall exceptions may be needed for the Python executable

## Limitations

- Designed for local network use (same LAN/WiFi)
- Limited to peer-to-peer (one-to-one) video chat
- No built-in NAT traversal for internet connections
- Camera quality depends on compression settings

## File Structure

```
tk_video_rooms.py       Main application file
db_helpers.py           Database operations and encryption helpers
rooms.json              Local storage for room data
users.json              Local storage for user accounts
.env                    MongoDB configuration (optional)
```
