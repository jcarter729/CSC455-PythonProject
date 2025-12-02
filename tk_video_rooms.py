import json
import db_helpers
import socket
import struct
import threading
import time
import tkinter as tk
from tkinter import simpledialog, messagebox

import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import pbkdf2_hmac
from PIL import Image, ImageTk
import uuid
import pickle


ROOMS_FILE = "rooms.json"


def load_rooms():
    try:
        with open(ROOMS_FILE, "r", encoding="utf-8") as f:
            rooms = json.load(f)
    except Exception:
        rooms = []

    # Migrate legacy rooms without an 'id' by adding a UUID for reliable identification
    migrated = False
    for r in rooms:
        if not isinstance(r, dict):
            continue
        if 'id' not in r:
            r['id'] = str(uuid.uuid4())
            migrated = True

    if migrated:
        try:
            save_rooms(rooms)
        except Exception:
            pass

    return rooms



def save_rooms(rooms):
    with open(ROOMS_FILE, "w", encoding="utf-8") as f:
        json.dump(rooms, f, indent=2)


def derive_key(password: str, salt: bytes = b"stream_salt") -> bytes:
    # PBKDF2-HMAC-SHA256 -> 32 bytes key
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)


class VideoRoomApp:
    def __init__(self, root, user_manager):
        self.root = root
        root.title("Video Rooms")
        self.rooms = db_helpers.load_rooms()
        self.user_manager = user_manager
        frame = tk.Frame(root)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        tk.Label(frame, text="Available Rooms").pack(anchor=tk.W)
        self.listbox = tk.Listbox(frame, height=8)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        self.refresh_rooms()
        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(6, 0))
        tk.Button(btn_frame, text="Create Room", command=self.create_room).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Join Room", command=self.join_room).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="Delete Room", command=self.delete_selected_room).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_rooms).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Account", command=self._account_menu).pack(side=tk.RIGHT)
        self.status_frame = tk.Frame(frame)
        self.status_frame.pack(fill=tk.X, pady=(6, 0))
        self.info_label = tk.Label(frame, text="Info: This app shows local rooms only. Share your IP with your partner.")
        self.info_label.pack(anchor=tk.W, pady=(8, 0))

    def refresh_rooms(self):
        self.rooms = db_helpers.load_rooms()
        self.listbox.delete(0, tk.END)
        for r in self.rooms:
            name = r.get("name")
            protected = "(protected)" if r.get("password") else ""
            self.listbox.insert(tk.END, f"{name} {protected}")

    def create_room(self):
        name = simpledialog.askstring("Room name", "Enter a name for the room:")
        if not name:
            return
        password = simpledialog.askstring("Password (optional)", "Enter a room password (optional):", show="*")
        room = {"id": str(uuid.uuid4()), "name": name, "password": password}
        result = db_helpers.create_room(room)
        if result:
            self.rooms = db_helpers.load_rooms()
            self.refresh_rooms()
            RoomWindow(self.root, room, is_host=True, app=self)
            messagebox.showinfo("Room Created", "Room created and saved to database (if available).")
        else:
            # Check MongoDB connection status
            db = getattr(db_helpers, '_get_mongo_db', lambda: None)()
            if db is None:
                messagebox.showerror("Error", "Failed to create room in MongoDB. Falling back to local file storage.")
            else:
                messagebox.showerror("Error", "Failed to create room. Unknown database error.")

    def join_room(self):
        # Require login before joining a room
        if not getattr(self.user_manager, "logged_in_user", None):
            messagebox.showerror("Login Required", "You must log in before joining a room.")
            return
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Select room", "Please select a room to join or create a new one.")
            return
        idx = sel[0]
        room = self.rooms[idx]
        # Use get_room_by_id for up-to-date info
        db_room = db_helpers.get_room_by_id(room.get("id"))
        if db_room:
            room = db_room
        if room.get("password"):
            pw = simpledialog.askstring("Password required", "Enter room password:", show="*")
            if pw != room.get("password"):
                messagebox.showerror("Wrong password", "The password you entered is incorrect.")
                return
        RoomWindow(self.root, room, is_host=False, app=self)



    def _local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start_stream(self):
        if self.running:
            return
        partner = self.partner_ip.get().strip()
        if not partner:
            if not self.is_host:
                messagebox.showerror("Partner IP required", "Enter partner IP to connect to.")
                return
        self.key = derive_key(self.passphrase.get())

        self.running = True
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showwarning("Camera", "Unable to open camera. Trying with DirectShow...")
            self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

        # Start receive server
        t_recv = threading.Thread(target=self._receive_thread, daemon=True)
        t_recv.start()

        # Start send thread (if partner specified)
        if partner:
            t_send = threading.Thread(target=self._send_thread, args=(partner,), daemon=True)
            t_send.start()

        # start local preview updater
        self._update_local()

    def stop_stream(self):
        self.running = False
        try:
            if self.cap:
                self.cap.release()
        except Exception:
            pass
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
        try:
            if self.send_sock:
                self.send_sock.close()
        except Exception:
            pass
        # Notify connected peers (incoming or outgoing) that the room is closing
        try:
            control_pkt = pickle.dumps({"control": "close"})
            payload = struct.pack("Q", len(control_pkt)) + control_pkt
            # notify inbound connection (peer who connected to our server)
            try:
                if getattr(self, 'conn', None):
                    try:
                        self.conn.sendall(payload)
                    except Exception:
                        pass
            except Exception:
                pass

            # notify outgoing send socket (peer we connected to)
            try:
                if getattr(self, 'send_sock', None):
                    try:
                        self.send_sock.sendall(payload)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception as e:
            print(f"Error sending control close: {e}")

        # If this window was the host for the room, remove the room entry immediately
        try:
            if self.is_host and getattr(self, 'app', None):
                try:
                    room_id = self.room.get('id')
                    if room_id:
                        if db_helpers.delete_room_by_id(room_id):
                            self.app.rooms = db_helpers.load_rooms()
                            self.app.refresh_rooms()
                        else:
                            print("Error removing room from DB")
                except Exception as e:
                    print(f"Error removing room: {e}")
        except Exception:
            pass
    def delete_selected_room(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Select room", "Please select a room to delete.")
            return
        idx = sel[0]
        room = self.rooms[idx]
        ok = messagebox.askyesno('Confirm delete', f"Delete room '{room.get('name')}'? This will remove it for everyone.")
        if not ok:
            return
        rid = room.get('id')
        if rid:
            deleted = db_helpers.delete_room_by_id(rid)
            if deleted:
                self.rooms = db_helpers.load_rooms()
                self.refresh_rooms()
            else:
                messagebox.showerror('Delete Room', 'Failed to delete room.')

    def _account_menu(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Account')
        tk.Button(dlg, text='Create User', command=lambda: self._create_user_with_port(dlg)).pack(fill=tk.X)
        tk.Button(dlg, text='Login', command=lambda: self.user_manager.login()).pack(fill=tk.X)
        tk.Button(dlg, text='Delete User', command=lambda: self.user_manager.delete_user()).pack(fill=tk.X)
        tk.Button(dlg, text='Logout', command=lambda: self._logout(dlg)).pack(fill=tk.X)

    def _create_user_with_port(self, parent):
        username = simpledialog.askstring('Create User', 'Enter username:', parent=parent)
        if not username:
            return
        password = simpledialog.askstring('Create User', 'Enter password:', parent=parent, show='*')
        if not password:
            return
        ip = self._local_ip() if hasattr(self, '_local_ip') else '127.0.0.1'
        # Assign a unique port automatically
        if db_helpers.create_user_with_ip_port(username, password, ip):
            messagebox.showinfo("User", "User created successfully.")
        else:
            messagebox.showerror("User", "Failed to create user.")

    def _logout(self, parent=None):
        self.user_manager.logged_in_user = None
        self.info_label.config(text="Info: This app shows local rooms only. Share your IP with your partner.")
        if parent:
            parent.destroy()
        messagebox.showinfo('Logout', 'You have been logged out.')

    def _send_thread(self, partner_ip):
        port = int(self.send_port.get())
        time.sleep(1)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((partner_ip, port))
            sock.settimeout(None)
            self.send_sock = sock
        except Exception as e:
            print(f"Send connect error: {e}")
            return

        import pickle

        while self.running:
            ret, frame = self.cap.read()
            if not ret:
                time.sleep(0.05)
                continue

            # preview local frame
            # encoding
            _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
            data = buffer.tobytes()

            # encrypt with AES-GCM and random nonce
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ciphertext = cipher.encrypt(data)
            tag = cipher.digest()

            packet = {"nonce": nonce, "ct": ciphertext, "tag": tag}
            try:
                msg = struct.pack("Q", len(pickle.dumps(packet))) + pickle.dumps(packet)
                self.send_sock.sendall(msg)
            except Exception as e:
                print(f"Send error: {e}")
                break

        try:
            if self.send_sock:
                self.send_sock.close()
        except Exception:
            pass

    def _receive_thread(self):
        import pickle

        port = int(self.receive_port.get())
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(1)
        self.server_sock = server
        try:
            server.settimeout(20)
            conn, addr = server.accept()
            conn.settimeout(None)
            self.conn = conn
            print(f"Connected from {addr}")
        except socket.timeout:
            print("No incoming connection within timeout")
            return
        except Exception as e:
            print(f"Accept error: {e}")
            return

        payload_size = struct.calcsize("Q")
        while self.running:
            packed = self._recvall(conn, payload_size)
            if not packed:
                break
            msg_size = struct.unpack("Q", packed)[0]
            data = self._recvall(conn, msg_size)
            if not data:
                break
            try:
                packet = pickle.loads(data)
                # handle control packets (no encryption)
                if isinstance(packet, dict) and packet.get("control"):
                    if packet.get("control") == "close":
                        # schedule UI notification and stop
                        def do_close():
                            try:
                                messagebox.showinfo("Room closed", "Host has closed the room. The window will close now.")
                            except Exception:
                                pass
                        try:
                            self.after(1, do_close)
                        except Exception:
                            pass
                        self.running = False
                        break

                else:
                    # encrypted frame packet
                    nonce = packet.get("nonce")
                    ct = packet.get("ct")
                    tag = packet.get("tag")
                    cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ct, tag)
                    nparr = np.frombuffer(plaintext, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    if frame is not None:
                        # convert to PIL image and schedule update
                        img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        pil = Image.fromarray(img)
                        self._schedule_remote_update(pil)
            except Exception as e:
                print(f"Receive processing error: {e}")
                continue

        try:
            conn.close()
        except Exception:
            pass

    def _recvall(self, sock, count):
        buf = b''
        while len(buf) < count:
            try:
                chunk = sock.recv(count - len(buf))
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _update_local(self):
        if not self.running or self.cap is None:
            return
        ret, frame = self.cap.read()
        if ret:
            img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil = Image.fromarray(img)
            self._schedule_local_update(pil)
        self.after(30, self._update_local)

    def _schedule_local_update(self, pil_image):
        imgtk = ImageTk.PhotoImage(pil_image.resize((320, 240)))
        # keep a reference to avoid GC
        self.local_label.imgtk = imgtk
        self.local_label.config(image=imgtk)

    def _schedule_remote_update(self, pil_image):
        def do_update():
            imgtk = ImageTk.PhotoImage(pil_image.resize((320, 240)))
            self.remote_label.imgtk = imgtk
            self.remote_label.config(image=imgtk)
        self.after(1, do_update)


# User management integration (minimal UI for demonstration)
class UserManager:
    def __init__(self, root):
        self.root = root
        self.users = db_helpers.load_users()
        self.logged_in_user = None

    def create_user(self):
        username = simpledialog.askstring("Create User", "Enter username:")
        password = simpledialog.askstring("Create User", "Enter password:", show="*")
        if not username or not password:
            return
        salt, hashed = db_helpers.hash_password(password)
        data = {"password_hash": hashed.hex(), "salt": salt.hex()}
        if db_helpers.create_user(username, data):
            messagebox.showinfo("User", "User created successfully.")
        else:
            messagebox.showerror("User", "Failed to create user.")

    def login(self):
        username = simpledialog.askstring("Login", "Enter username:")
        password = simpledialog.askstring("Login", "Enter password:", show="*")
        if not username or not password:
            return
        user = db_helpers.get_user(username)
        if not user:
            messagebox.showerror("Login Failed", "User not found.")
            return
        salt_hex = user.get("salt")
        hash_hex = user.get("password_hash")
        if not salt_hex or not hash_hex:
            messagebox.showerror("Login Failed", "User record is missing password info.")
            return
        import binascii
        salt = binascii.unhexlify(salt_hex)
        hashed = db_helpers.hash_password(password, salt)[1]
        if hashed.hex() == hash_hex:
            db_helpers.update_user(username, {"password_hash": hash_hex, "salt": salt_hex})
            self.logged_in_user = username
            messagebox.showinfo("Login Success", f"Welcome, {username}! You are now logged in.")
            # Update main screen label immediately if present
            try:
                for w in self.root.winfo_children():
                    if hasattr(w, 'user_label'):
                        w.user_label.config(text=f"User: {username}")
                    if hasattr(w, 'info_label'):
                        w.info_label.config(text=f"Welcome, {username}! You are logged in.")
            except Exception:
                pass
        else:
            messagebox.showerror("Login Failed", "Incorrect password.")

    def delete_user(self):
        username = simpledialog.askstring("Delete User", "Enter username:")
        if db_helpers.delete_user(username):
            messagebox.showinfo("User", "User deleted successfully.")
        else:
            messagebox.showerror("User", "Failed to delete user.")

        # Close the room window after stopping
        try:
            self.destroy()
        except Exception:
            pass

    def _send_thread(self, partner_ip):
        port = int(self.send_port.get())
        time.sleep(1)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((partner_ip, port))
            sock.settimeout(None)
            self.send_sock = sock
        except Exception as e:
            print(f"Send connect error: {e}")
            return

        import pickle

        while self.running:
            ret, frame = self.cap.read()
            if not ret:
                time.sleep(0.05)
                continue

            # preview local frame
            # encoding
            _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
            data = buffer.tobytes()

            # encrypt with AES-GCM and random nonce
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ciphertext = cipher.encrypt(data)
            tag = cipher.digest()

            packet = {"nonce": nonce, "ct": ciphertext, "tag": tag}
            try:
                msg = struct.pack("Q", len(pickle.dumps(packet))) + pickle.dumps(packet)
                self.send_sock.sendall(msg)
            except Exception as e:
                print(f"Send error: {e}")
                break

        try:
            if self.send_sock:
                self.send_sock.close()
        except Exception:
            pass

    def _receive_thread(self):
        import pickle

        port = int(self.receive_port.get())
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(1)
        self.server_sock = server
        try:
            server.settimeout(20)
            conn, addr = server.accept()
            conn.settimeout(None)
            self.conn = conn
            print(f"Connected from {addr}")
        except socket.timeout:
            print("No incoming connection within timeout")
            return
        except Exception as e:
            print(f"Accept error: {e}")
            return

        payload_size = struct.calcsize("Q")
        while self.running:
            packed = self._recvall(conn, payload_size)
            if not packed:
                break
            msg_size = struct.unpack("Q", packed)[0]
            data = self._recvall(conn, msg_size)
            if not data:
                break
            try:
                packet = pickle.loads(data)
                # handle control packets (no encryption)
                if isinstance(packet, dict) and packet.get("control"):
                    if packet.get("control") == "close":
                        # schedule UI notification and stop
                        def do_close():
                            try:
                                messagebox.showinfo("Room closed", "Host has closed the room. The window will close now.")
                            except Exception:
                                pass
                        try:
                            self.after(1, do_close)
                        except Exception:
                            pass
                        self.running = False
                        break

                else:
                    # encrypted frame packet
                    nonce = packet.get("nonce")
                    ct = packet.get("ct")
                    tag = packet.get("tag")
                    cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ct, tag)
                    nparr = np.frombuffer(plaintext, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    if frame is not None:
                        # convert to PIL image and schedule update
                        img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        pil = Image.fromarray(img)
                        self._schedule_remote_update(pil)
            except Exception as e:
                print(f"Receive processing error: {e}")
                continue

        try:
            conn.close()
        except Exception:
            pass

    def _recvall(self, sock, count):
        buf = b''
        while len(buf) < count:
            try:
                chunk = sock.recv(count - len(buf))
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _update_local(self):
        if not self.running or self.cap is None:
            return
        ret, frame = self.cap.read()
        if ret:
            img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil = Image.fromarray(img)
            self._schedule_local_update(pil)
        self.after(30, self._update_local)

    def _schedule_local_update(self, pil_image):
        imgtk = ImageTk.PhotoImage(pil_image.resize((320, 240)))
        # keep a reference to avoid GC
        self.local_label.imgtk = imgtk
        self.local_label.config(image=imgtk)

    def _schedule_remote_update(self, pil_image):
        def do_update():
            imgtk = ImageTk.PhotoImage(pil_image.resize((320, 240)))
            self.remote_label.imgtk = imgtk
            self.remote_label.config(image=imgtk)
        self.after(1, do_update)


# Add RoomWindow class definition here
class RoomWindow(tk.Toplevel):
    def __init__(self, parent, room, is_host=False, app=None):
        super().__init__(parent)
        self.room = room
        self.is_host = is_host
        self.app = app
        self.title(f"Room: {room.get('name')}")
        # Ports are now handled automatically; no UI fields needed
        self.partner_username = tk.StringVar()
        self.passphrase = tk.StringVar(value=room.get("password") or "secret")
        top = tk.Frame(self)
        top.pack(fill=tk.X, padx=6, pady=6)
        tk.Label(top, text=f"Room: {room.get('name')}").pack(anchor=tk.W)
        tk.Label(top, text=f"This machine IP: {self._local_ip()} (share with partner)").pack(anchor=tk.W)
        cfg = tk.Frame(self)
        cfg.pack(fill=tk.X, padx=6, pady=(6, 0))
        tk.Label(cfg, text="Partner Username:").grid(row=0, column=0, sticky=tk.W)
        tk.Entry(cfg, textvariable=self.partner_username).grid(row=0, column=1, sticky=tk.EW)
        tk.Label(cfg, text="Passphrase:").grid(row=1, column=0, sticky=tk.W)
        tk.Entry(cfg, textvariable=self.passphrase, show="*").grid(row=1, column=1, sticky=tk.EW)
        cfg.columnconfigure(1, weight=1)
        btns = tk.Frame(self)
        btns.pack(fill=tk.X, padx=6, pady=(6, 3))
        self.btn_start = tk.Button(btns, text="Start", command=self.start_stream)
        self.btn_start.pack(side=tk.LEFT)
        tk.Button(btns, text="Stop", command=self.stop_stream).pack(side=tk.LEFT, padx=(6, 0))
        vids = tk.Frame(self)
        vids.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        left = tk.LabelFrame(vids, text="You (Local)")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = tk.LabelFrame(vids, text="Remote (Them)")
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.local_label = tk.Label(left)
        self.local_label.pack(fill=tk.BOTH, expand=True)
        self.remote_label = tk.Label(right)
        self.remote_label.pack(fill=tk.BOTH, expand=True)
        self.cap = None
        self.send_sock = None
        self.server_sock = None
        self.conn = None
        self.running = False
        self.key = None
    def _local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    def start_stream(self):
        if self.running:
            return
        partner_username = self.partner_username.get().strip()
        partner_ip = None
        partner_port = None
        if partner_username:
            import db_helpers
            partner_user = db_helpers.get_user(partner_username)
            if partner_user:
                partner_ip = partner_user.get('ip') or partner_user.get('ip_address')
                partner_port = partner_user.get('port')
            if not partner_ip or not partner_port:
                from tkinter import messagebox
                messagebox.showerror("User Not Found", f"Could not find IP and port for user '{partner_username}'.")
                return
        else:
            from tkinter import messagebox
            messagebox.showerror("Missing Username", "Please enter the partner's username.")
            return
        self.key = derive_key(self.passphrase.get())
        self.running = True
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showwarning("Camera", "Unable to open camera. Trying with DirectShow...")
            self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        t_recv = threading.Thread(target=self._receive_thread, daemon=True)
        t_recv.start()
        if partner_ip and partner_port:
            t_send = threading.Thread(target=self._send_thread, args=(partner_ip, int(partner_port)), daemon=True)
            t_send.start()
        self._update_local()
    def stop_stream(self):
        self.running = False
        try:
            if self.cap:
                self.cap.release()
        except Exception:
            pass
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
        try:
            if self.send_sock:
                self.send_sock.close()
        except Exception:
            pass
        try:
            control_pkt = pickle.dumps({"control": "close"})
            payload = struct.pack("Q", len(control_pkt)) + control_pkt
            if getattr(self, 'conn', None):
                try:
                    self.conn.sendall(payload)
                except Exception:
                    pass
            if getattr(self, 'send_sock', None):
                try:
                    self.send_sock.sendall(payload)
                except Exception:
                    pass
        except Exception as e:
            print(f"Error sending control close: {e}")
        try:
            if self.is_host and getattr(self, 'app', None):
                room_id = self.room.get('id')
                if room_id:
                    db_helpers.delete_room_by_id(room_id)
                    self.app.rooms = db_helpers.load_rooms()
                    self.app.refresh_rooms()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
    def _send_thread(self, partner_ip, partner_port):
        time.sleep(1)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((partner_ip, partner_port))
            sock.settimeout(None)
            self.send_sock = sock
        except Exception as e:
            print(f"Send connect error: {e}")
            return
        import pickle
        while self.running:
            ret, frame = self.cap.read()
            if not ret:
                time.sleep(0.05)
                continue
            _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
            data = buffer.tobytes()
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ciphertext = cipher.encrypt(data)
            tag = cipher.digest()
            packet = {"nonce": nonce, "ct": ciphertext, "tag": tag}
            try:
                msg = struct.pack("Q", len(pickle.dumps(packet))) + pickle.dumps(packet)
                self.send_sock.sendall(msg)
            except Exception as e:
                print(f"Send error: {e}")
                break
        try:
            if self.send_sock:
                self.send_sock.close()
        except Exception:
            pass
    def _receive_thread(self):
        import pickle
        # Use our own assigned port (from DB) for receiving
        import db_helpers
        my_username = getattr(self.app.user_manager, 'logged_in_user', None) if self.app else None
        my_port = None
        if my_username:
            my_user = db_helpers.get_user(my_username)
            if my_user:
                my_port = my_user.get('port')
        if not my_port:
            print("Could not determine own port for receiving.")
            return
        port = int(my_port)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(1)
        self.server_sock = server
        try:
            server.settimeout(20)
            conn, addr = server.accept()
            conn.settimeout(None)
            self.conn = conn
            print(f"Connected from {addr}")
        except socket.timeout:
            print("No incoming connection within timeout")
            return
        except Exception as e:
            print(f"Accept error: {e}")
            return
        payload_size = struct.calcsize("Q")
        while self.running:
            packed = self._recvall(conn, payload_size)
            if not packed:
                break
            msg_size = struct.unpack("Q", packed)[0]
            data = self._recvall(conn, msg_size)
            if not data:
                break
            try:
                packet = pickle.loads(data)
                if isinstance(packet, dict) and packet.get("control"):
                    if packet.get("control") == "close":
                        def do_close():
                            try:
                                messagebox.showinfo("Room closed", "Host has closed the room. The window will close now.")
                            except Exception:
                                pass
                        try:
                            self.after(1, do_close)
                        except Exception:
                            pass
                        self.running = False
                        break
                else:
                    nonce = packet.get("nonce")
                    ct = packet.get("ct")
                    tag = packet.get("tag")
                    cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ct, tag)
                    nparr = np.frombuffer(plaintext, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    if frame is not None:
                        img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        pil = Image.fromarray(img)
                        self._schedule_remote_update(pil)
            except Exception as e:
                print(f"Receive processing error: {e}")
                continue
        try:
            conn.close()
        except Exception:
            pass
    def _recvall(self, sock, count):
        buf = b''
        while len(buf) < count:
            try:
                chunk = sock.recv(count - len(buf))
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf
    def _update_local(self):
        if not self.running or self.cap is None:
            return
        ret, frame = self.cap.read()
        if ret:
            img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil = Image.fromarray(img)
            self._schedule_local_update(pil)
        self.after(30, self._update_local)
    def _schedule_local_update(self, pil_image):
        imgtk = ImageTk.PhotoImage(pil_image.resize((320, 240)))
        self.local_label.imgtk = imgtk
        self.local_label.config(image=imgtk)
    def _schedule_remote_update(self, pil_image):
        def do_update():
            imgtk = ImageTk.PhotoImage(pil_image.resize((320, 240)))
            self.remote_label.imgtk = imgtk
            self.remote_label.config(image=imgtk)
        self.after(1, do_update)


if __name__ == "__main__":
    import db_helpers
    import tkinter as tk
    import threading
    import cv2
    import numpy as np
    from PIL import Image, ImageTk
    import uuid
    import struct
    import pickle
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    root = tk.Tk()
    user_manager = UserManager(root)
    app = VideoRoomApp(root, user_manager)
    root.mainloop()
