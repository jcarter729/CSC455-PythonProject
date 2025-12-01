import cv2
import socket
import struct
import pickle
import threading
import time
import numpy as np
from Crypto.Cipher import AES

# Shared AES key (must match on both machines)
key = b'supersecretkey12'  # 16 bytes
nonce = b'unique_nonce'    # 12 bytes

class BidirectionalClient:
    def __init__(self, server_host, send_port, receive_port):
        self.server_host = server_host
        self.send_port = send_port  # Port to send video to
        self.receive_port = receive_port  # Port to receive video on
        self.cap = cv2.VideoCapture(0)
        self.running = True
        
    def recvall(self, sock, count):
        """Helper to receive exact number of bytes"""
        buf = b''
        while len(buf) < count:
            chunk = sock.recv(count - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf
    
    def send_video_thread(self):
        """Send local video to remote machine"""
        print(f"Attempting to connect to {self.server_host}:{self.send_port}")
        
        # Try multiple times to connect
        sock = None
        for attempt in range(10):  # Try for 10 seconds
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.server_host, self.send_port))
                print(f"Connected to {self.server_host}:{self.send_port} for sending video")
                break
            except (socket.timeout, ConnectionRefusedError):
                if sock:
                    sock.close()
                print(f"Attempt {attempt + 1}/10 - waiting for partner...")
                time.sleep(1)
        else:
            print("Could not connect to partner after 10 attempts")
            return
        
        try:
            while self.running:
                ret, frame = self.cap.read()
                if not ret:
                    print("Failed to capture frame")
                    break

                # Show local video
                cv2.imshow("You (Local)", frame)
                
                # Encode frame as JPEG
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
                data = buffer.tobytes()

                # Encrypt with GCM
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext = cipher.encrypt(data)
                tag = cipher.digest()

                # Send encrypted frame
                message = pickle.dumps({"ct": ciphertext, "tag": tag})
                try:
                    sock.sendall(struct.pack("Q", len(message)) + message)
                except Exception as e:
                    print(f"Connection lost: {e}")
                    break

                if cv2.waitKey(1) & 0xFF == ord('q'):
                    self.running = False
                    break
                    
        except Exception as e:
            print(f"Send video error: {e}")
        finally:
            if sock:
                sock.close()
    
    def receive_video_thread(self):
        """Receive video from remote machine"""
        server_sock = None
        conn = None
        try:
            # Create server socket to receive video
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('0.0.0.0', self.receive_port))
            server_sock.listen(1)
            print(f"Listening for incoming video on port {self.receive_port}")
            
            server_sock.settimeout(20)  # 20 second timeout
            conn, addr = server_sock.accept()
            print(f"Receiving video from {addr}")
            
            payload_size = struct.calcsize("Q")
            frame_count = 0
            
            while self.running:
                # Read message size
                packed_size = self.recvall(conn, payload_size)
                if not packed_size:
                    print("Connection closed by sender")
                    break
                    
                msg_size = struct.unpack("Q", packed_size)[0]
                
                # Read the full message
                msg_data = self.recvall(conn, msg_size)
                if not msg_data:
                    print("Connection closed while receiving frame")
                    break
                
                try:
                    # Decrypt and display
                    packet = pickle.loads(msg_data)
                    ciphertext = packet.get("ct")
                    tag = packet.get("tag")
                    
                    if ciphertext is None or tag is None:
                        continue
                    
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    
                    # Decode JPEG to image
                    nparr = np.frombuffer(plaintext, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    
                    if frame is not None:
                        frame_count += 1
                        cv2.imshow("Remote (Them)", frame)
                        if cv2.waitKey(1) & 0xFF == ord('q'):
                            self.running = False
                            break
                        
                        # Print status every 60 frames
                        if frame_count % 60 == 0:
                            print(f"Received {frame_count} frames")
                        
                except ValueError:
                    continue  # Skip bad frames
                except Exception:
                    continue  # Skip problematic frames
                    
        except socket.timeout:
            print("No partner connected within 20 seconds")
        except Exception as e:
            print(f"Receive error: {e}")
        finally:
            if conn:
                conn.close()
            if server_sock:
                server_sock.close()
    
    def start(self):
        """Start both sending and receiving threads"""
        print("Starting bidirectional video client...")

        # Create the named windows so visibility checks won't fail before any frames arrive
        try:
            cv2.namedWindow("You (Local)")
            cv2.namedWindow("Remote (Them)")
        except Exception:
            # If OpenCV window creation fails, continue; we'll still attempt to run
            pass

        # Start receive thread (server for incoming video)
        receive_thread = threading.Thread(target=self.receive_video_thread)
        receive_thread.daemon = True
        receive_thread.start()

        # Start send thread (client for outgoing video)
        send_thread = threading.Thread(target=self.send_video_thread)
        send_thread.daemon = True
        send_thread.start()

        print("Press 'q' in any video window to quit")
        print("Both video windows should appear shortly...")

        try:
            # Keep main thread alive until the user quits or both windows are closed
            while self.running:
                time.sleep(0.1)
                try:
                    y_vis = cv2.getWindowProperty("You (Local)", cv2.WND_PROP_VISIBLE)
                    r_vis = cv2.getWindowProperty("Remote (Them)", cv2.WND_PROP_VISIBLE)
                    # Only break if both windows existed and are now closed
                    if y_vis >= 0 and r_vis >= 0 and y_vis < 1 and r_vis < 1:
                        break
                except cv2.error:
                    # If OpenCV throws because the window hasn't been created yet, ignore and continue
                    pass
        except KeyboardInterrupt:
            print("Interrupted by user")
            self.running = False
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.cap:
            self.cap.release()
        cv2.destroyAllWindows()
        print("Cleanup complete")

if __name__ == "__main__":
    print("=== Bidirectional Encrypted Video Chat (Partner) ===")
    print("This machine will:")
    print("- Send video TO partner on port 9998")
    print("- Receive video FROM partner on port 9999")
    print()
    
    # Get partner's IP address dynamically
    while True:
        partner_ip = input("Enter your partner's IP address: ").strip()
        if partner_ip:
            # Basic IP validation
            parts = partner_ip.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                break
            else:
                print("Invalid IP format. Please use format: 192.168.1.100")
        else:
            print("IP address cannot be empty.")
    
    print(f"\nConnecting to partner at {partner_ip}...")
    
    client = BidirectionalClient(
        server_host=partner_ip,     # Partner's IP (entered by user)
        send_port=9998,             # Port to send to on partner's machine
        receive_port=9999           # Port to listen on for partner's video
    )
    
    client.start()