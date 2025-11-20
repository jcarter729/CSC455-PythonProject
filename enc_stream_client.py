import socket
import struct
import time
import cv2
from threading import Thread
from crypto_utils import load_key_from_file, encrypt_frame


def send_all(sock, data: bytes):
    totalsent = 0
    while totalsent < len(data):
        sent = sock.send(data[totalsent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        totalsent += sent


def capture_and_send(server_host="127.0.0.1", server_port=6000, secret_path="secret.txt", quality=70, target_fps=15):
    key = load_key_from_file(secret_path)
    print(f"Using key derived from {secret_path}")

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise RuntimeError("Could not open video device")

    sock = socket.create_connection((server_host, server_port))
    print(f"Connected to {server_host}:{server_port}")

    try:
        frame_interval = 1.0 / target_fps
        while True:
            start = time.time()
            ret, frame = cap.read()
            if not ret:
                print("Failed to read frame")
                break

            # Optional: resize to reduce bandwidth
            h, w = frame.shape[:2]
            maxw = 640
            if w > maxw:
                newh = int(h * (maxw / w))
                frame = cv2.resize(frame, (maxw, newh))

            # JPEG encode
            ret2, jpg = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
            if not ret2:
                print("JPEG encode failed")
                continue
            data = jpg.tobytes()

            # Encrypt
            packet = encrypt_frame(data, key)

            # Send length prefix and packet
            hdr = struct.pack(">I", len(packet))
            send_all(sock, hdr)
            send_all(sock, packet)

            # throttle to target FPS
            elapsed = time.time() - start
            tosleep = frame_interval - elapsed
            if tosleep > 0:
                time.sleep(tosleep)
    finally:
        sock.close()
        cap.release()


if __name__ == "__main__":
    # change host to remote server IP when running across machines
    capture_and_send(server_host="127.0.0.1", server_port=6000)
