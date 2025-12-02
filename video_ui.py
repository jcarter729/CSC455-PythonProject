import tkinter as tk
from tkinter import simpledialog, messagebox
import threading
import time
import socket
import struct
import pickle
import errno
import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image, ImageTk
import uuid
import json
from db_helpers import (
    load_rooms, save_rooms, load_users, save_users,
    create_room, get_room_by_id, update_room, delete_room_by_id,
    create_user, get_user, update_user, delete_user, hash_password
)

# Add derive_key function (copied from tk_video_rooms.py)
from hashlib import pbkdf2_hmac
def derive_key(password: str, salt: bytes = b"stream_salt") -> bytes:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)

DISCOVERY_PORT = 37020
DISCOVERY_INTERVAL = 2.0

class VideoRoomApp:
    def join_room(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Select room", "Please select a room to join or create a new one.")
            return
        idx = sel[0]
        room = self.display_rooms[idx]
        if room.get("password"):
            pw = simpledialog.askstring("Password required", "Enter room password:", show="*")
            if pw != room.get("password"):
                messagebox.showerror("Wrong password", "The password you entered is incorrect.")
                return
        if room.get('discovered'):
            partner_ip = room.get('ip')
            partner_port = room.get('port', 9999)
            if not partner_ip or not partner_port:
                messagebox.showerror("Connection", "Could not find the host's IP or port. Please wait for the room to be discovered.")
                return
            w = RoomWindow(self.root, room, is_host=False, app=self, partner_ip=partner_ip, partner_port=partner_port)
            return
        # Fallback: try to find partner IP from users database
        users = load_users()
        partner_ip = None
        partner_port = None
        for username, data in users.items():
            if username != self.current_user and data.get('ip'):
                ip_data = data.get('ip')
                try:
                    if isinstance(ip_data, dict) and 'nonce' in ip_data:
                        pw = room.get('password') or ''
                        key = derive_key(pw)
                        nonce = bytes.fromhex(ip_data['nonce'])
                        ct = bytes.fromhex(ip_data['ct'])
                        tag = bytes.fromhex(ip_data['tag'])
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        partner_ip = cipher.decrypt_and_verify(ct, tag).decode('utf-8')
                    else:
                        partner_ip = str(ip_data)
                    partner_port = data.get('port', 9999)
                    break
                except Exception:
                    continue
        if not partner_ip:
            messagebox.showinfo("Connection", 
                "No other users found in this room yet.\n\n" +
                "To connect:\n" +
                "1. Make sure the other person has created an account and is logged in\n" +
                "2. They should create the room first (as host)\n" +
                "3. Wait for their room to appear in 'discovered' rooms, then join\n\n" +
                "Or ask them to share their IP address directly.")
            return
        w = RoomWindow(self.root, room, is_host=False, app=self, partner_ip=partner_ip, partner_port=partner_port)

    def __init__(self, root):
        self.root = root
        root.title("Video Rooms")

        self.rooms = load_rooms()
        self.users = load_users()
        self.current_user = None
        self.discovered_rooms = {}  # room_id -> info
        self.display_rooms = []

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
        self.user_label = tk.Label(self.status_frame, text="Not logged in")
        self.user_label.pack(side=tk.LEFT)

        t = threading.Thread(target=self._discovery_listener, daemon=True)
        t.start()

        tk.Label(frame, text="Info: This app shows local rooms only. Share your IP with your partner.").pack(anchor=tk.W, pady=(8, 0))

    def _local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def refresh_rooms(self):
        self.rooms = load_rooms()
        self.display_rooms = []
        self.listbox.delete(0, tk.END)
        for r in self.rooms:
            self.display_rooms.append(r)
            name = r.get("name")
            protected = "(protected)" if r.get("password") else ""
            self.listbox.insert(tk.END, f"{name} {protected}")
        now = time.time()
        for rid, info in list(self.discovered_rooms.items()):
            if now - info.get('ts', 0) > 10:
                del self.discovered_rooms[rid]
                continue
            if any(r.get('id') == rid for r in self.rooms):
                continue
            disp = {
                'id': rid,
                'name': info.get('name', '<unknown>'),
                'password': None,
                'discovered': True
            }
            self.display_rooms.append(disp)
            label = f"{disp['name']} (discovered)"
            self.listbox.insert(tk.END, label)

    def create_room(self):
        if not self.current_user:
            try:
                resp = messagebox.askyesno('Login required', 'You must be logged in to create a room.\n\nYes = Create account, No = Login to existing account')
            except Exception:
                resp = False
            if resp:
                try:
                    self._create_account(self.root)
                except Exception:
                    pass
            else:
                try:
                    self._login_account(self.root)
                except Exception:
                    pass
        if not self.current_user:
            try:
                messagebox.showerror('Login required', 'You must be logged in to create a room.')
            except Exception:
                pass
            return
        name = simpledialog.askstring("Room name", "Enter a name for the room:")
        if not name:
            return
        password = simpledialog.askstring("Password (optional)", "Enter a room password (optional):", show="*")
        room = {"id": str(uuid.uuid4()), "name": name, "password": password, "owner": self.current_user}
        ok = create_room(room)
        if not ok:
            self.rooms.append(room)
            try:
                save_rooms(self.rooms)
                try:
                    messagebox.showwarning('Storage', 'Could not write new room to remote DB; saved locally instead.')
                except Exception:
                    pass
            except Exception:
                messagebox.showwarning("Save failed", "Failed to persist new room to storage.")
        else:
            try:
                self.rooms = load_rooms()
            except Exception:
                pass
        self.refresh_rooms()
        RoomWindow(self.root, room, is_host=True, app=self)

    def delete_selected_room(self):
        sel = self.listbox.curselection()
        if not sel:
            try:
                messagebox.showinfo('Select room', 'Please select a room to delete.')
            except Exception:
                pass
            return
        idx = sel[0]
        room = self.display_rooms[idx]
        if room.get('discovered'):
            self.display_rooms.pop(idx)
            self.listbox.delete(idx)
            return
        if not self.current_user:
            try:
                resp = messagebox.askyesno('Login required', 'You must be logged in to delete a room.\n\nYes = Create account, No = Login to existing account')
            except Exception:
                resp = False
            if resp:
                try:
                    self._create_account(self.root)
                except Exception:
                    pass
            else:
                try:
                    self._login_account(self.root)
                except Exception:
                    pass
        if not self.current_user:
            try:
                messagebox.showerror('Login required', 'You must be logged in to delete a room.')
            except Exception:
                pass
            return
        owner = room.get('owner')
        if owner and self.current_user != owner:
            try:
                messagebox.showwarning('Not owner', 'Only the room owner can delete this room from the list.')
            except Exception:
                pass
            return
        try:
            ok = messagebox.askyesno('Confirm delete', f"Delete room '{room.get('name')}'? This will remove it for everyone.")
        except Exception:
            ok = False
        if not ok:
            return
        rid = room.get('id')
        if rid:
            deleted = delete_room_by_id(rid)
            if deleted:
                try:
                    self.rooms = load_rooms()
                except Exception:
                    self.rooms = [r for r in (self.rooms or []) if r.get('id') != rid]
                try:
                    self.refresh_rooms()
                except Exception:
                    pass
                try:
                    messagebox.showinfo('Deleted', 'Room deleted.')
                except Exception:
                    pass
                return
            original = list(self.rooms or [])
            new_rooms = [r for r in original if r.get('id') != rid]
            if len(new_rooms) != len(original):
                self.rooms = new_rooms
                try:
                    save_rooms(self.rooms)
                    try:
                        messagebox.showwarning('Storage', 'Could not delete room from remote DB; removed locally instead.')
                    except Exception:
                        pass
                except Exception:
                    try:
                        messagebox.showerror('Save failed', 'Failed to persist deletion to storage.')
                    except Exception:
                        pass
                try:
                    self.refresh_rooms()
                except Exception:
                    pass
                return
            try:
                messagebox.showerror('Delete failed', 'Failed to delete the selected room.')
            except Exception:
                pass
            return

    def _account_menu(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Account')
        tk.Button(dlg, text='Create Account', command=lambda: self._create_account(dlg)).pack(fill=tk.X)
        tk.Button(dlg, text='Login', command=lambda: self._login_account(dlg)).pack(fill=tk.X)
        tk.Button(dlg, text='Logout', command=lambda: self._logout(dlg)).pack(fill=tk.X)

    def _logout(self, parent=None):
        self.current_user = None
        self.user_label.config(text='Not logged in')
        if parent:
            parent.destroy()
        messagebox.showinfo('Logout', 'You have been logged out.')

    def _create_account(self, parent):
        username = simpledialog.askstring('Create account', 'Username:', parent=parent)
        if not username:
            return
        password = simpledialog.askstring('Create account', 'Password:', parent=parent, show='*')
        if not password:
            return
        users = self.users or {}
        if username in users:
            messagebox.showerror('Exists', 'That username already exists.')
            return
        salt, h = hash_password(password)
        ip = self._local_ip() if hasattr(self, '_local_ip') else RoomWindow._local_ip(self)
        data = {'salt': salt.hex(), 'hash': h.hex(), 'ip': ip, 'port': 9999}
        ok = create_user(username, data)
        if not ok:
            users[username] = data
            try:
                save_users(users)
                try:
                    messagebox.showwarning('Storage', 'Could not write account to remote DB; saved locally instead.')
                except Exception:
                    pass
            except Exception:
                messagebox.showwarning('Save failed', 'Failed to persist account to storage.')
        else:
            try:
                self.users = load_users()
            except Exception:
                self.users[username] = data
        try:
            self.current_user = username
            self.user_label.config(text=f'User: {username}')
        except Exception:
            pass
        messagebox.showinfo('Account', 'Account created')

    def _login_account(self, parent):
        username = simpledialog.askstring('Login', 'Username:', parent=parent)
        if not username:
            return
        password = simpledialog.askstring('Login', 'Password:', parent=parent, show='*')
        if not password:
            return
        users = self.users or {}
        u = users.get(username)
        if not u:
            messagebox.showerror('Login', 'Unknown user')
            return
        salt = bytes.fromhex(u.get('salt'))
        expected = bytes.fromhex(u.get('hash'))
        _, h = hash_password(password, salt)
        if h == expected:
            ip = self._local_ip() if hasattr(self, '_local_ip') else RoomWindow._local_ip(self)
            update_user(username, {**u, 'ip': ip, 'port': 9999})
            self.current_user = username
            self.user_label.config(text=f'User: {username}')
            messagebox.showinfo('Login', 'Logged in')
        else:
            messagebox.showerror('Login', 'Bad password')

    def _discovery_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        try:
            s.bind(('', DISCOVERY_PORT))
        except Exception:
            return
        s.settimeout(1.0)
        while True:
            try:
                data, addr = s.recvfrom(4096)
            except Exception:
                time.sleep(0.1)
                continue
            try:
                info = json.loads(data.decode('utf-8'))
                rid = info.get('id') or info.get('name') + '@' + addr[0]
                info['ip'] = addr[0]
                info['port'] = info.get('port', 9999)
                info['ts'] = time.time()
                self.discovered_rooms[rid] = info
                try:
                    self.root.after(1, self.refresh_rooms)
                except Exception:
                    pass
            except Exception:
                continue

class RoomWindow(tk.Toplevel):
    def _send_encrypted_metadata(self, sock, metadata: dict):
        try:
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ct = cipher.encrypt(pickle.dumps(metadata))
            tag = cipher.digest()
            packet = {"nonce": nonce, "ct": ct, "tag": tag}
            payload = pickle.dumps(packet)
            msg = struct.pack("Q", len(payload)) + payload
            sock.sendall(msg)
        except Exception as e:
            print(f"Error sending encrypted metadata: {e}")

    def _is_socket_open(self, sock):
        try:
            return sock is not None and sock.fileno() >= 0
        except Exception:
            return False

    def _local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def __init__(self, parent, room, is_host=False, app=None, partner_ip=None, partner_port=None):
        super().__init__(parent)
        self.geometry('900x600')
        self.room = room
        self.is_host = is_host
        self.app = app
        self.title(f"Room: {room.get('name')}")
        self.partner_ip = tk.StringVar(value=partner_ip or "")
        self.partner_port = tk.IntVar(value=partner_port or 0)
        self.passphrase = tk.StringVar(value=room.get("password") or "secret")
        top = tk.Frame(self)
        top.pack(fill=tk.X, padx=6, pady=6)
        tk.Label(top, text=f"Room: {room.get('name')}").pack(anchor=tk.W)
        cfg = tk.Frame(self)
        cfg.pack(fill=tk.X, padx=6, pady=(6, 0))
        tk.Label(cfg, text="Passphrase:").grid(row=0, column=0, sticky=tk.W)
        tk.Entry(cfg, textvariable=self.passphrase, show="*").grid(row=0, column=1, sticky=tk.EW)
        def update_password():
            new_pw = self.passphrase.get()
            current_user = self.app.current_user if self.app else None
            owner = self.room.get('owner')
            if not current_user or current_user != owner:
                messagebox.showerror('Permission denied', 'Only the room owner can change the password.')
                return
            self.room['password'] = new_pw
            update_room(self.room)
            messagebox.showinfo('Password changed', 'Password changed.')
        tk.Button(cfg, text="Update password", command=update_password).grid(row=0, column=2, padx=(6,0))
        cfg.columnconfigure(1, weight=1)
        btns = tk.Frame(self)
        btns.pack(fill=tk.X, padx=6, pady=(6, 3))
        self.btn_start = tk.Button(btns, text="Start", command=self.start_stream)
        self.btn_start.pack(side=tk.LEFT)
        tk.Button(btns, text="Stop", command=self.stop_stream).pack(side=tk.LEFT, padx=(6, 0))
        tk.Button(btns, text="Exit", command=self._exit_room).pack(side=tk.LEFT, padx=(6, 0))
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
        self._panel_size = (320, 240)
        self._max_panel_size = (640, 480)
        self._remote_has_video = False
        self.running = False
        self._set_local_placeholder()
        self._set_remote_placeholder()
        self.bind('<Configure>', self._on_resize)
        self.cap = None
        self.send_sock = None
        self.server_sock = None
        self.conn = None
        self.key = None
        self._disco_thread = None

        # Host: start broadcasting immediately
        if self.is_host:
            def disco():
                import json, time, socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                except Exception:
                    pass
                payload = json.dumps({
                    'id': self.room.get('id'),
                    'name': self.room.get('name'),
                    'port': 9999  # Placeholder until start_stream sets real port
                }).encode('utf-8')
                while not self.running:
                    try:
                        sock.sendto(payload, ('<broadcast>', DISCOVERY_PORT))
                    except Exception:
                        try:
                            sock.sendto(payload, ('255.255.255.255', DISCOVERY_PORT))
                        except Exception:
                            pass
                    time.sleep(DISCOVERY_INTERVAL)
                try:
                    sock.close()
                except Exception:
                    pass
            self._disco_thread = threading.Thread(target=disco, daemon=True)
            self._disco_thread.start()
        # Non-host: disable Start until discovered
        if not self.is_host:
            self.btn_start.config(state=tk.DISABLED)
            self._check_discovered()

    def _check_discovered(self):
        # Enable Start if discovered info is available
        if hasattr(self.app, 'discovered_rooms') and self.room.get('id') in getattr(self.app, 'discovered_rooms', {}):
            self.btn_start.config(state=tk.NORMAL)
        else:
            self.after(1000, self._check_discovered)

    def _exit_room(self):
        self.running = False
        try:
            if self.cap:
                self.cap.release()
        except Exception:
            pass
        try:
            if self._is_socket_open(self.conn):
                self.conn.close()
        except Exception:
            pass
        try:
            if self._is_socket_open(self.server_sock):
                self.server_sock.close()
        except Exception:
            pass
        try:
            if self._is_socket_open(self.send_sock):
                self.send_sock.close()
        except Exception:
            pass
        self.destroy()

    def _set_local_placeholder(self):
        pil = self._make_placeholder("No video")
        self._schedule_local_update(pil)

    def _set_remote_placeholder(self):
        pil = self._make_placeholder("No video")
        self._schedule_remote_update(pil)

    def _make_placeholder(self, text):
        from PIL import ImageDraw, ImageFont
        w, h = self._panel_size
        img = Image.new('RGB', (w, h), color=(60, 60, 60))
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("arial.ttf", 18)
        except Exception:
            font = ImageFont.load_default()
        try:
            tw, th = font.getsize(text)
        except Exception:
            tw, th = (100, 30)
        draw.text(((w-tw)//2, (h-th)//2), text, font=font, fill=(200, 200, 200))
        return img

    def _on_resize(self, event):
        try:
            w = max(160, min(self.winfo_width() // 2 - 20, self._max_panel_size[0]))
            h = max(120, min(self.winfo_height() - 100, self._max_panel_size[1]))
            self._panel_size = (w, h)
            if hasattr(self.local_label, 'imgtk'):
                self._schedule_local_update(getattr(self.local_label, 'last_pil', None))
            if hasattr(self.remote_label, 'imgtk'):
                self._schedule_remote_update(getattr(self.remote_label, 'last_pil', None))
        except Exception:
            pass

    def _send_encrypted_bytes(self, sock, plaintext_bytes: bytes):
        try:
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ct = cipher.encrypt(plaintext_bytes)
            tag = cipher.digest()
            packet = {"nonce": nonce, "ct": ct, "tag": tag}
            payload = pickle.dumps(packet)
            msg = struct.pack("Q", len(payload)) + payload
            sock.sendall(msg)
        except Exception:
            raise

    def start_stream(self):
        if self.running:
            return
        # Always try to use discovered room info if available
        partner = self.partner_ip.get().strip()
        partner_port = self.partner_port.get()
        discovered = None
        if hasattr(self.app, 'discovered_rooms') and self.room.get('id') in getattr(self.app, 'discovered_rooms', {}):
            discovered = self.app.discovered_rooms[self.room.get('id')]
        if discovered:
            partner = discovered.get('ip', partner)
            partner_port = discovered.get('port', None)
            print(f"[DEBUG] Using discovered info: ip={partner}, port={partner_port}")
        else:
            print(f"[DEBUG] Using fallback info: ip={partner}, port={partner_port}")
        if not partner_port or partner_port == 0:
            print("[WARNING] Partner port missing or zero, defaulting to 9999 (may be incorrect)")
            partner_port = 9999
        self.key = derive_key(self.passphrase.get())
        self.running = True
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showwarning("Camera", "Unable to open camera. Trying with DirectShow...")
            self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        def start_receive():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', 0))
            assigned_port = server.getsockname()[1]
            self.receive_port = assigned_port
            self.server_sock = server
            if self._is_socket_open(self.send_sock):
                self._send_encrypted_metadata(self.send_sock, {"ip": self._local_ip(), "port": assigned_port, "user": self.app.current_user})
            t_recv = threading.Thread(target=self._receive_thread, args=(assigned_port,), daemon=True)
            t_recv.start()
        start_receive()
        if partner and partner_port:
            t_send = threading.Thread(target=self._send_thread, args=(partner, partner_port), daemon=True)
            t_send.start()
        if self.is_host:
            def disco():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                except Exception:
                    pass
                payload = json.dumps({
                    'id': self.room.get('id'),
                    'name': self.room.get('name'),
                    'port': self.receive_port
                }).encode('utf-8')
                while self.running:
                    try:
                        sock.sendto(payload, ('<broadcast>', DISCOVERY_PORT))
                    except Exception:
                        try:
                            sock.sendto(payload, ('255.255.255.255', DISCOVERY_PORT))
                        except Exception:
                            pass
                    time.sleep(DISCOVERY_INTERVAL)
                try:
                    sock.close()
                except Exception:
                    pass
            self._disco_thread = threading.Thread(target=disco, daemon=True)
            self._disco_thread.start()
        self._update_local()

    def stop_stream(self):
        self.running = False
        pil = self._make_placeholder("No video")
        self._schedule_local_update(pil)
        delete_on_stop = True
        try:
            if self.is_host and getattr(self, 'app', None):
                resp = messagebox.askyesno("Confirm room deletion", "Do you want to delete this room from the list when stopping?\n\nYes = delete room\nNo = keep room")
                delete_on_stop = bool(resp)
        except Exception:
            delete_on_stop = True
        try:
            ctl = pickle.dumps({"control": "close"})
            if self._is_socket_open(self.conn):
                try:
                    self._send_encrypted_bytes(self.conn, ctl)
                except Exception:
                    pass
            if self._is_socket_open(self.send_sock):
                try:
                    self._send_encrypted_bytes(self.send_sock, ctl)
                except Exception:
                    pass
        except Exception as e:
            print(f"Error sending control close: {e}")
        try:
            if self.cap:
                try:
                    self.cap.release()
                except Exception:
                    pass
                finally:
                    self.cap = None
        except Exception:
            pass
        try:
            if self._is_socket_open(self.conn):
                try:
                    self.conn.close()
                except Exception:
                    pass
            self.conn = None
        except Exception:
            self.conn = None
        try:
            if self._is_socket_open(self.server_sock):
                try:
                    self.server_sock.close()
                except Exception:
                    pass
            self.server_sock = None
        except Exception:
            self.server_sock = None
        try:
            if self._is_socket_open(self.send_sock):
                try:
                    self.send_sock.close()
                except Exception:
                    pass
            self.send_sock = None
        except Exception:
            self.send_sock = None

    def _send_thread(self, partner_ip, partner_port):
        time.sleep(1)
        # Validate partner_ip and partner_port
        print(f"[DEBUG] Attempting to connect to partner_ip={partner_ip!r}, partner_port={partner_port!r}")
        if not partner_ip or not isinstance(partner_ip, str) or partner_ip.strip() == '':
            print("[ERROR] partner_ip is invalid or empty. Aborting send thread.")
            return
        try:
            partner_port = int(partner_port)
        except Exception:
            print(f"[ERROR] partner_port '{partner_port}' is not a valid integer. Aborting send thread.")
            return
        if partner_port <= 0 or partner_port > 65535:
            print(f"[ERROR] partner_port '{partner_port}' is out of valid range. Aborting send thread.")
            return
        last_err = None
        for attempt in range(3):
            sock = None
            try:
                print(f"[DEBUG] Creating new socket for attempt {attempt+1}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print(f"[DEBUG] Connect attempt {attempt+1} to {partner_ip}:{partner_port}")
                sock.settimeout(5)
                sock.connect((partner_ip, partner_port))
                sock.settimeout(None)
                self.send_sock = sock
                print(f"Connected to {partner_ip}:{partner_port} for sending video")
                last_err = None
                break
            except Exception as e:
                last_err = e
                print(f"[ERROR] Connect attempt {attempt+1} failed: {e}")
                if sock:
                    try:
                        sock.close()
                    except Exception as ce:
                        print(f"[DEBUG] Error closing socket after failed attempt: {ce}")
                time.sleep(1)
        if last_err is not None:
            print(f"Send connect error: {last_err}")
            return
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

    def _receive_thread(self, port):
        server = self.server_sock
        server.listen(1)
        try:
            server.settimeout(20)
            conn, addr = server.accept()
            conn.settimeout(None)
            self.conn = conn
            print(f"Connected from {addr}")
            
            # Show connection status in UI
            try:
                def update_remote_status():
                    pil = self._make_placeholder("Connected - waiting for video...")
                    self._schedule_remote_update(pil)
                self.after(1, update_remote_status)
            except Exception:
                pass
        except socket.timeout:
            print("No incoming connection within timeout")
            return
        except OSError as e:
            win_err = getattr(e, 'winerror', None)
            if win_err == 10038 or getattr(e, 'errno', None) == errno.EBADF:
                return
            print(f"Accept error: {e}")
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
                outer = pickle.loads(data)
                nonce = outer.get("nonce")
                ct = outer.get("ct")
                tag = outer.get("tag")
                if not (nonce and ct and tag):
                    continue
                try:
                    cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ct, tag)
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    continue
                # Try to decode as video frame first
                try:
                    # Decode JPEG to image
                    nparr = np.frombuffer(plaintext, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    
                    if frame is not None:
                        # Convert BGR to RGB for PIL
                        img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        pil = Image.fromarray(img)
                        # Schedule UI update on main thread
                        self._schedule_remote_update(pil)
                        continue
                except Exception:
                    # Not a video frame, try as control message
                    pass
                
                # Try to decode as control message
                try:
                    inner = pickle.loads(plaintext)
                    if isinstance(inner, dict) and inner.get("control"):
                        if inner.get("control") == "close":
                            self.running = False
                            break
                except Exception:
                    # Not a control message either, skip
                    continue
            except Exception as e:
                print(f"Receive processing error: {e}")
                continue
        try:
            conn.close()
        except Exception:
            pass
        try:
            pil = self._make_placeholder("Peer left")
            self._schedule_remote_update(pil)
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
            self._schedule_local_update(None)
            return
        ret, frame = self.cap.read()
        if ret:
            img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil = Image.fromarray(img)
            self._schedule_local_update(pil)
        else:
            self._schedule_local_update(None)
        self.after(30, self._update_local)

    def _schedule_local_update(self, pil_image):
        if pil_image is None:
            pil_image = self._make_placeholder("No video")
        w, h = self._panel_size
        imgtk = ImageTk.PhotoImage(pil_image.resize((w, h)))
        self.local_label.imgtk = imgtk
        self.local_label.last_pil = pil_image
        self.local_label.config(image=imgtk)

    def _schedule_remote_update(self, pil_image):
        def do_update():
            w, h = self._panel_size
            imgtk = ImageTk.PhotoImage(pil_image.resize((w, h)))
            self.remote_label.imgtk = imgtk
            self.remote_label.last_pil = pil_image
            self.remote_label.config(image=imgtk)
        self.after(1, do_update)

# You can copy all the VideoRoomApp and RoomWindow methods and logic here as needed.
# For brevity, only the structure is shown. Copy all relevant code from tk_video_rooms.py.

if __name__ == "__main__":
    root = tk.Tk()
    app = VideoRoomApp(root)
    root.mainloop()
