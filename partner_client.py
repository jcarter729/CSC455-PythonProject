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
        time.sleep(3)  # Wait for remote server to start
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_host, self.send_port))
            print(f"Connected to {self.server_host}:{self.send_port} for sending video")
            
            while self.running:
                ret, frame = self.cap.read()
                if not ret:
                    print("Failed to capture frame")
                    break

                # Show local video
                cv2.imshow("You (Local)", frame)
                
                # Encode frame as JPEG
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                data = buffer.tobytes()

                # Encrypt with GCM
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext = cipher.encrypt(data)
                tag = cipher.digest()

                # Send encrypted frame
                message = pickle.dumps({"ct": ciphertext, "tag": tag})
                try:
                    sock.sendall(struct.pack("Q", len(message)) + message)
                except:
                    print("Failed to send frame")
                    break

                if cv2.waitKey(1) & 0xFF == ord('q'):
                    self.running = False
                    break
                    
        except Exception as e:
            print(f"Send video error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
    
    def receive_video_thread(self):
        """Receive video from remote machine"""
        try:
            # Create server socket to receive video
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('0.0.0.0', self.receive_port))
            server_sock.listen(1)
            print(f"Listening for incoming video on port {self.receive_port}")
            
            conn, addr = server_sock.accept()
            print(f"Receiving video from {addr}")
            
            payload_size = struct.calcsize("Q")
            
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
                        print("Malformed packet received")
                        continue
                    
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    
                    # Decode JPEG to image
                    nparr = np.frombuffer(plaintext, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    
                    if frame is not None:
                        cv2.imshow("Remote (Them)", frame)
                        if cv2.waitKey(1) & 0xFF == ord('q'):
                            self.running = False
                            break
                    else:
                        print("Failed to decode received frame")
                        
                except ValueError as e:
                    print(f"Decryption failed: {e}")
                    continue
                except Exception as e:
                    print(f"Error processing received frame: {e}")
                    continue
                    
        except Exception as e:
            print(f"Receive video error: {e}")
        finally:
            try:
                conn.close()
                server_sock.close()
            except:
                pass
    
    def start(self):
        """Start both sending and receiving threads"""
        print("Starting bidirectional video client...")
        
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
            # Keep main thread alive
            while self.running:
                time.sleep(0.1)
                # Check if windows were closed
                if cv2.getWindowProperty("You (Local)", cv2.WND_PROP_VISIBLE) < 1:
                    if cv2.getWindowProperty("Remote (Them)", cv2.WND_PROP_VISIBLE) < 1:
                        break
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
    # Configuration for MACHINE B (Partner's machine)
    
    # MACHINE B Configuration:
    client = BidirectionalClient(
        server_host='172.26.85.81',  # Your IP (where to send partner's video)  
        send_port=9998,              # Port to send to on your machine
        receive_port=9999            # Port to listen on for your video
    )
    
    client.start()