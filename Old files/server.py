import cv2
import socket
import struct
import pickle
import numpy as np
from Crypto.Cipher import AES

# Shared AES key (must match client)
# AES key must be 16, 24 or 32 bytes. Use 16 bytes here.
key = b'supersecretkey12'  # 16 bytes
# GCM nonce is normally 12 bytes
nonce = b'unique_nonce'    # 12 bytes

# Socket setup
HOST = '0.0.0.0'
PORT = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)
print("Server listening...")
conn, addr = sock.accept()
print("Connected by", addr)

data = b""
payload_size = struct.calcsize("Q")

cap = cv2.VideoCapture(0)

while True:
    # Show local webcam
    ret, local_frame = cap.read()
    if ret:
        cv2.imshow("You", local_frame)

    # Receive peer frame
    while len(data) < payload_size:
        packet = conn.recv(4096)
        if not packet:
            break
        data += packet

    if len(data) < payload_size:
        break

    packed_msg_size = data[:payload_size]
    msg_size = struct.unpack("Q", packed_msg_size)[0]
    data = data[payload_size:]

    while len(data) < msg_size:
        data += conn.recv(4096)

    frame_data = data[:msg_size]
    data = data[msg_size:]

    payload = pickle.loads(frame_data)

    # Decrypt (GCM) — payload contains ciphertext and tag
    ciphertext = payload.get("ct")
    tag = payload.get("tag")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
    except ValueError:
        # Authentication failed
        print("WARNING: AES GCM tag verification failed")
        continue

    # Decode JPEG
    peer_frame = cv2.imdecode(
        np.frombuffer(plaintext, dtype=np.uint8), cv2.IMREAD_COLOR
    )

    if peer_frame is not None:
        cv2.imshow("Peer", peer_frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
conn.close()
cv2.destroyAllWindows()