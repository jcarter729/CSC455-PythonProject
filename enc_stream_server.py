import socket
import struct
import cv2
import numpy as np
from crypto_utils import load_key_from_file, decrypt_frame


def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def run_server(host="0.0.0.0", port=6000, secret_path="secret.txt"):
    key = load_key_from_file(secret_path)
    print(f"Using key derived from {secret_path}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    print(f"Server listening on {host}:{port}")
    conn, addr = srv.accept()
    print("Client connected:", addr)

    try:
        while True:
            hdr = recvall(conn, 4)
            if not hdr:
                print("Connection closed by client")
                break
            (length,) = struct.unpack(">I", hdr)
            packet = recvall(conn, length)
            if packet is None:
                print("Connection closed while reading packet")
                break
            try:
                plain = decrypt_frame(packet, key)
            except Exception as e:
                print("Decryption failed:", e)
                continue

            # Decode JPEG bytes
            arr = np.frombuffer(plain, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if frame is None:
                print("Failed to decode frame")
                continue

            cv2.imshow("Remote", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
    finally:
        conn.close()
        srv.close()
        cv2.destroyAllWindows()


if __name__ == "__main__":
    run_server()
