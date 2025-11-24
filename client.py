import cv2
import socket
import struct
import pickle
from Crypto.Cipher import AES

# Shared AES key (must match server)
# AES key must be 16, 24 or 32 bytes. Use 16 bytes here.
key = b'supersecretkey12'  # 16 bytes
# GCM nonce is normally 12 bytes
nonce = b'unique_nonce'    # 12 bytes

# Socket setup
HOST = '172.26.22.58'  # replace with server IP
PORT = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

cap = cv2.VideoCapture(0)

while True:
    ret, frame = cap.read()
    if not ret:
        break

    cv2.imshow("You", frame)

    # Encode frame as JPEG
    _, buffer = cv2.imencode('.jpg', frame)
    data = buffer.tobytes()

    # Encrypt with GCM and send ciphertext + tag
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    tag = cipher.digest()

    # Send a small dict containing ciphertext and tag
    message = pickle.dumps({"ct": ciphertext, "tag": tag})
    sock.sendall(struct.pack("Q", len(message)) + message)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
sock.close()
cv2.destroyAllWindows()