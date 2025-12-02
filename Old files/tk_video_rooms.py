import json
import socket
import struct
import threading
import time
import tkinter as tk
from tkinter import simpledialog, messagebox

import pickle
import errno
import hashlib
import os

import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import pbkdf2_hmac
from PIL import Image, ImageTk
import uuid
try:
    import pymongo
    _PYMONGO_AVAILABLE = True
except Exception:
    pymongo = None
    _PYMONGO_AVAILABLE = False
    print("Warning: 'pymongo' not available; MongoDB persistence disabled.")

# Lightweight .env loader (keeps credentials out of source)
def _load_env_file(path='.env'):
    try:
        if not os.path.exists(path):
            return
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


# Load `.env` if present (do this before reading MONGO_URI)
_load_env_file()

# MongoDB: optional. Set environment variable `MONGO_URI` to enable.
MONGO_URI = os.getenv('MONGO_URI')
_MONGO_CLIENT = None
_MONGO_DB = None
_MONGO_CONNECT_CHECKED = False
_MONGO_FAILED_ALERTED = False

def _get_mongo_db():
    global _MONGO_CLIENT, _MONGO_DB
    # If pymongo isn't installed, behave as if MongoDB is not configured.
    if not _PYMONGO_AVAILABLE:
        return None

    if _MONGO_DB is not None:
        return _MONGO_DB
    if not MONGO_URI:
        return None
    try:
        if _MONGO_CLIENT is None:
            _MONGO_CLIENT = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            # try a lightweight server selection to fail fast
            _MONGO_CLIENT.admin.command('ping')
        # use database named by query param appName or fallback to 'csc_rooms'
        # If URI contains a database path, pymongo will parse it; otherwise use default
        dbname = None
        try:
            parsed = pymongo.uri_parser.parse_uri(MONGO_URI)
            dbname = parsed.get('database')
        except Exception:
            dbname = None
        if not dbname:
            dbname = 'csc_rooms'
        _MONGO_DB = _MONGO_CLIENT[dbname]
        return _MONGO_DB
    except Exception:
        # Fail quietly at startup: print traceback once and set alerted flag.
        import traceback
        tb = traceback.format_exc()
        global _MONGO_FAILED_ALERTED
        if not _MONGO_FAILED_ALERTED:
            _MONGO_FAILED_ALERTED = True
            try:
                print("MongoDB connection failed (will use local storage where allowed):\n", tb)
            except Exception:
                pass
        return None



ROOMS_FILE = "rooms.json"
USERS_FILE = "users.json"
DISCOVERY_PORT = 37020
DISCOVERY_INTERVAL = 2.0


def load_rooms():
    # Try MongoDB first (optional)
    db = _get_mongo_db()
    if db is not None:
        try:
            docs = list(db.rooms.find({}))
            rooms = []
            for d in docs:
                r = {k: v for k, v in d.items() if k != '_id'}
                # ensure id exists as string
                if 'id' not in r:
                    r['id'] = str(uuid.uuid4())
                rooms.append(r)
            return rooms
        except Exception:
            pass

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
    db = _get_mongo_db()
    if db is not None:
        try:
            # Replace entire collection for simplicity
            db.rooms.delete_many({})
            if rooms:
                db.rooms.insert_many([{**r} for r in rooms])
            return
        except Exception:
            import traceback
            tb = traceback.format_exc()
            print("save_rooms DB error:\n", tb)
            try:
                messagebox.showerror('MongoDB', 'Failed to write rooms collection to MongoDB (see console).')
            except Exception:
                pass
    # Enforce MongoDB persistence for writes. If DB is not available, fail loudly.
    try:
        message = 'MongoDB not configured or unavailable; cannot persist rooms.'
        print(message)
        try:
            messagebox.showerror('MongoDB', message)
        except Exception:
            pass
    except Exception:
        pass


def derive_key(password: str, salt: bytes = b"stream_salt") -> bytes:
    # PBKDF2-HMAC-SHA256 -> 32 bytes key
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)


def load_users():
    db = _get_mongo_db()
    if db is not None:
        try:
            docs = list(db.users.find({}))
            users = {}
            for d in docs:
                u = {k: v for k, v in d.items() if k != '_id'}
                users[u.get('username')] = {k: v for k, v in u.items() if k != 'username'}
            return users
        except Exception:
            pass

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_users(u):
    db = _get_mongo_db()
    if db is not None:
        try:
            db.users.delete_many({})
            docs = []
            for username, data in (u or {}).items():
                doc = {'username': username, **data}
                docs.append(doc)
            if docs:
                db.users.insert_many(docs)
            return
        except Exception:
            import traceback
            tb = traceback.format_exc()
            print("save_users DB error:\n", tb)
            try:
                messagebox.showerror('MongoDB', 'Failed to write users collection to MongoDB (see console).')
            except Exception:
                pass
    # Enforce MongoDB persistence for writes. If DB is not available, fail loudly.
    try:
        message = 'MongoDB not configured or unavailable; cannot persist users.'
        print(message)
        try:
            messagebox.showerror('MongoDB', message)
        except Exception:
            pass
    except Exception:
        pass


### Mongo/JSON-backed CRUD helpers for rooms and users
def create_room(room: dict) -> bool:
    """Create a room document (DB) or append to local JSON. Returns True on success."""
    db = _get_mongo_db()
    if db is None:
        try:
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot create room.')
        except Exception:
            pass
        print('create_room aborted: no MongoDB')
        return False

    try:
        db.rooms.insert_one({**room})
        return True
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("create_room DB error:\n", tb)
        try:
            messagebox.showerror('MongoDB', f'Failed to create room in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False


def get_room_by_id(room_id: str) -> dict | None:
    """Return room dict by `id` or None."""
    db = _get_mongo_db()
    if db is not None:
        try:
            d = db.rooms.find_one({'id': room_id}, projection={'_id': False})
            return d
        except Exception as e:
            import traceback
            print("get_room_by_id DB error:\n", traceback.format_exc())
            try:
                messagebox.showerror('MongoDB', 'Error reading room from MongoDB (see console).')
            except Exception:
                pass
            return None

    for r in load_rooms() or []:
        if r.get('id') == room_id:
            return r
    return None


def update_room(room: dict) -> bool:
    """Update (or upsert) a room in DB or JSON. Expects room to contain 'id'."""
    rid = room.get('id')
    if not rid:
        return False
    db = _get_mongo_db()
    if db is None:
        try:
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot update room.')
        except Exception:
            pass
        print('update_room aborted: no MongoDB')
        return False

    try:
        db.rooms.update_one({'id': rid}, {'$set': {**room}}, upsert=True)
        return True
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("update_room DB error:\n", tb)
        try:
            messagebox.showerror('MongoDB', f'Failed to update room in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False


def delete_room_by_id(room_id: str) -> bool:
    """Delete a room by id from DB or JSON. Returns True if deleted or no-op when not found."""
    db = _get_mongo_db()
    if db is None:
        try:
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot delete room.')
        except Exception:
            pass
        print('delete_room_by_id aborted: no MongoDB')
        return False

    try:
        db.rooms.delete_one({'id': room_id})
        return True
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("delete_room_by_id DB error:\n", tb)
        try:
            messagebox.showerror('MongoDB', f'Failed to delete room in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False


def create_user(username: str, data: dict) -> bool:
    """Create a user entry. `data` should be mapping like {'salt':..., 'hash':...} (hex strings)."""
    db = _get_mongo_db()
    if db is None:
        try:
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot create user.')
        except Exception:
            pass
        print('create_user aborted: no MongoDB')
        return False

    try:
        doc = {'username': username, **(data or {})}
        db.users.insert_one(doc)
        return True
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("create_user DB error:\n", tb)
        try:
            messagebox.showerror('MongoDB', f'Failed to create user in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False


def get_user(username: str) -> dict | None:
    """Return user data dict (without username key) or None."""
    db = _get_mongo_db()
    if db is not None:
        try:
            d = db.users.find_one({'username': username}, projection={'_id': False})
            if not d:
                return None
            d2 = {k: v for k, v in d.items() if k != 'username'}
            return d2
        except Exception as e:
            import traceback
            print("get_user DB error:\n", traceback.format_exc())
            try:
                messagebox.showerror('MongoDB', 'Error reading user from MongoDB (see console).')
            except Exception:
                pass
            return None

    users = load_users() or {}
    return users.get(username)


def update_user(username: str, data: dict) -> bool:
    """Update (or create) a user entry."""
    if not username:
        return False
    db = _get_mongo_db()
    if db is None:
        try:
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot update user.')
        except Exception:
            pass
        print('update_user aborted: no MongoDB')
        return False

    try:
        doc = {'username': username, **(data or {})}
        db.users.update_one({'username': username}, {'$set': doc}, upsert=True)
        return True
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("update_user DB error:\n", tb)
        try:
            messagebox.showerror('MongoDB', f'Failed to update user in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False


def delete_user(username: str) -> bool:
    """Remove a user by username."""
    db = _get_mongo_db()
    if db is None:
        try:
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot delete user.')
        except Exception:
            pass
        print('delete_user aborted: no MongoDB')
        return False

    try:
        db.users.delete_one({'username': username})
        return True
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("delete_user DB error:\n", tb)
        try:
            messagebox.showerror('MongoDB', f'Failed to delete user in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    # Return (salt, hash)
    if salt is None:
        salt = os.urandom(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)
    return salt, dk


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
        # Find any available user in the room except self
        users = load_users()
        partner_ip = None
        partner_name = None
        for username, data in users.items():
            if username != self.current_user and data.get('ip'):
                partner_ip = data.get('ip')
                partner_name = username
                break
        if not partner_ip:
            messagebox.showerror("Connection", "Could not find any available user's IP address in this room. Make sure at least one other user is online and logged in.")
            return
        w = RoomWindow(self.root, room, is_host=False, app=self, partner_ip=partner_ip)
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

        # status / user label
        self.status_frame = tk.Frame(frame)
        self.status_frame.pack(fill=tk.X, pady=(6, 0))
        self.user_label = tk.Label(self.status_frame, text="Not logged in")
        self.user_label.pack(side=tk.LEFT)

        # Start discovery listener thread
        t = threading.Thread(target=self._discovery_listener, daemon=True)
        t.start()

        tk.Label(frame, text="Info: This app shows local rooms only. Share your IP with your partner.").pack(anchor=tk.W, pady=(8, 0))

    def refresh_rooms(self):
        self.rooms = load_rooms()
        # merge persistent rooms and discovered ones (don't overwrite saved rooms)
        self.display_rooms = []
        self.listbox.delete(0, tk.END)
        for r in self.rooms:
            self.display_rooms.append(r)
            name = r.get("name")
            protected = "(protected)" if r.get("password") else ""
            self.listbox.insert(tk.END, f"{name} {protected}")

        # append discovered (ephemeral) rooms that are not already saved
        now = time.time()
        for rid, info in list(self.discovered_rooms.items()):
            # expire old discoveries
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
        # require a logged-in user before creating a room
        if not self.current_user:
            try:
                resp = messagebox.askyesno('Login required', 'You must be logged in to create a room.\n\nYes = Create account, No = Login to existing account')
            except Exception:
                resp = False
            if resp:
                # Create account (blocking simpledialog)
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
        # Try to persist using MongoDB helpers (fall back to JSON save)
        ok = create_room(room)
        if not ok:
            # fallback to in-memory + JSON
            self.rooms.append(room)
            try:
                save_rooms(self.rooms)
                # inform user that DB write failed but local save succeeded
                try:
                    messagebox.showwarning('Storage', 'Could not write new room to remote DB; saved locally instead.')
                except Exception:
                    pass
            except Exception:
                messagebox.showwarning("Save failed", "Failed to persist new room to storage.")
        else:
            # reload rooms from storage to reflect authoritative source
            try:
                self.rooms = load_rooms()
            except Exception:
                pass
        self.refresh_rooms()
        # Open the room as host (pass app reference so room can be removed)
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

        # Discovered rooms are ephemeral and not deletable from main storage
        if room.get('discovered'):
            # Remove from display immediately
            self.display_rooms.pop(idx)
            self.listbox.delete(idx)
            return

        # Require login
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

        # Try DB deletion first
        rid = room.get('id')
        if rid:
            deleted = delete_room_by_id(rid)
            if deleted:
                try:
                    self.rooms = load_rooms()
                except Exception:
                    # best-effort local removal
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

            # DB delete failed: try local removal and save
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
            # ...existing code...

    def delete_selected_room(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Delete Room", "Please select a room to delete.")
            return
        idx = sel[0]
        room = self.display_rooms[idx]
        owner = room.get('owner')
        if not self.current_user:
            messagebox.showerror('Delete Room', 'You must be logged in to delete a room.')
            return
        if owner and self.current_user != owner:
            messagebox.showwarning('Delete Room', 'Only the room owner can delete this room.')
            return
        room_id = room.get('id')
        if room_id:
            deleted = delete_room_by_id(room_id)
            if deleted:
                messagebox.showinfo('Delete Room', 'Room deleted.')
                self.rooms = load_rooms()
                self.refresh_rooms()
            else:
                messagebox.showerror('Delete Room', 'Failed to delete room (see console).')
        else:
            # legacy: remove by name+password
            name = room.get('name')
            pw = room.get('password')
            new_rooms = [r for r in self.rooms if not (r.get('name') == name and r.get('password') == pw)]
            self.rooms = new_rooms
            try:
                save_rooms(self.rooms)
                messagebox.showinfo('Delete Room', 'Room deleted.')
            except Exception:
                messagebox.showerror('Delete Room', 'Failed to delete room (see console).')
            self.refresh_rooms()
        # Legacy rooms without id: remove by name/password
        name = room.get('name')
        pw = room.get('password')
        original = list(self.rooms or [])
        new_rooms = [r for r in original if not (r.get('name') == name and r.get('password') == pw)]
        if len(new_rooms) != len(original):
            self.rooms = new_rooms
            try:
                save_rooms(self.rooms)
            except Exception:
                try:
                    messagebox.showwarning('Save failed', 'Failed to persist deletion to storage.')
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
        data = {'salt': salt.hex(), 'hash': h.hex(), 'ip': ip}
        ok = create_user(username, data)
        if not ok:
            # fallback to local JSON
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
            # refresh users from storage
            try:
                self.users = load_users()
            except Exception:
                self.users[username] = data
        # set current user on successful creation
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
            # Update user document with current IP
            update_user(username, {**u, 'ip': ip})
            self.current_user = username
            self.user_label.config(text=f'User: {username}')
            messagebox.showinfo('Login', 'Logged in')
            def _local_ip(self):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(('8.8.8.8', 80))
                    ip = s.getsockname()[0]
                    s.close()
                    return ip
                except Exception:
                    return '127.0.0.1'
        else:
            messagebox.showerror('Login', 'Bad password')

    def _discovery_listener(self):
        # Listen for UDP broadcasts announcing rooms
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
        # Encrypt metadata dict and send as length-prefixed pickled dict
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

    def __init__(self, parent, room, is_host=False, app=None, partner_ip=None):
        super().__init__(parent)
        # Set a larger initial window size
        self.geometry('900x600')
        self.room = room
        self.is_host = is_host
        self.app = app
        self.title(f"Room: {room.get('name')}")


        self.partner_ip = tk.StringVar(value=partner_ip or "")
        self.partner_port = tk.IntVar(value=0)
        self.passphrase = tk.StringVar(value=room.get("password") or "secret")

        top = tk.Frame(self)
        top.pack(fill=tk.X, padx=6, pady=6)
        tk.Label(top, text=f"Room: {room.get('name')}").pack(anchor=tk.W)

        cfg = tk.Frame(self)
        cfg.pack(fill=tk.X, padx=6, pady=(6, 0))
        tk.Label(cfg, text="Passphrase:").grid(row=0, column=0, sticky=tk.W)
        tk.Entry(cfg, textvariable=self.passphrase, show="*").grid(row=0, column=1, sticky=tk.EW)
        cfg.columnconfigure(1, weight=1)

        btns = tk.Frame(self)
        btns.pack(fill=tk.X, padx=6, pady=(6, 3))
        self.btn_start = tk.Button(btns, text="Start", command=self.start_stream)
        self.btn_start.pack(side=tk.LEFT)
        tk.Button(btns, text="Stop", command=self.stop_stream).pack(side=tk.LEFT, padx=(6, 0))
        tk.Button(btns, text="Exit", command=self._exit_room).pack(side=tk.LEFT, padx=(6, 0))
    def _exit_room(self):
        # Clean up and close the room window
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

        # Video panels
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

        # Store current panel sizes
        self._panel_size = (320, 240)
        self._max_panel_size = (640, 480)

        # Add placeholder to both panels initially
        self._remote_has_video = False
        self.running = False  # Ensure running is always initialized
        self._set_local_placeholder()
        self._set_remote_placeholder()
    def _set_local_placeholder(self):
        pil = self._make_placeholder("No video")
        self._schedule_local_update(pil)

        # Store current panel sizes
        self._panel_size = (320, 240)
        self._max_panel_size = (640, 480)

        # Add placeholder to remote panel initially
        self._remote_has_video = False
        self.running = False  # Ensure running is always initialized
        self._set_remote_placeholder()

        # Bind resize event to update video panels (only on window resize)
        self.bind('<Configure>', self._on_resize)
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
        # Only update panel size when the window itself is resized
        try:
            # Get window size
            w = max(160, min(self.winfo_width() // 2 - 20, self._max_panel_size[0]))
            h = max(120, min(self.winfo_height() - 100, self._max_panel_size[1]))
            self._panel_size = (w, h)
            # Redraw current frames to fit new size
            if hasattr(self.local_label, 'imgtk'):
                self._schedule_local_update(getattr(self.local_label, 'last_pil', None))
            if hasattr(self.remote_label, 'imgtk'):
                self._schedule_remote_update(getattr(self.remote_label, 'last_pil', None))
        except Exception:
            pass

        # Networking/video state
        self.cap = None
        self.send_sock = None
        self.server_sock = None
        self.conn = None
        self.running = False
        self.key = None
        self._disco_thread = None

        # The following code is only valid in the main app window, not RoomWindow. Remove these lines to fix undefined variable errors.
    def _send_encrypted_bytes(self, sock, plaintext_bytes: bytes):
        # AES-GCM encrypt plaintext_bytes with self.key and send as length-prefixed pickled dict
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
        partner = self.partner_ip.get().strip()
        partner_port = self.partner_port.get()
        self.key = derive_key(self.passphrase.get())

        self.running = True
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showwarning("Camera", "Unable to open camera. Trying with DirectShow...")
            self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

        # Start receive server (bind to port 0 for auto-assignment)
        def start_receive():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', 0))
            assigned_port = server.getsockname()[1]
            self.receive_port = assigned_port
            self.server_sock = server
            # Share assigned port with partner (encrypted)
            if self._is_socket_open(self.send_sock):
                self._send_encrypted_metadata(self.send_sock, {"ip": self._local_ip(), "port": assigned_port, "user": self.app.current_user})
            # Start listening thread
            t_recv = threading.Thread(target=self._receive_thread, args=(assigned_port,), daemon=True)
            t_recv.start()

        start_receive()

        # Start send thread (if partner specified)
        if partner and partner_port:
            t_send = threading.Thread(target=self._send_thread, args=(partner, partner_port), daemon=True)
            t_send.start()

        # If hosting, start discovery broadcaster so peers can auto-find us
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

        # start local preview updater
        self._update_local()

    def stop_stream(self):
        self.running = False
        # Show placeholder but do not trigger resize
        pil = self._make_placeholder("No video")
        # Use current panel size for placeholder
        self._schedule_local_update(pil)

        # If host, ask whether to delete the room from the saved list
        delete_on_stop = True
        try:
            if self.is_host and getattr(self, 'app', None):
                # Ask: Yes = delete room from list, No = keep room entry
                resp = messagebox.askyesno("Confirm room deletion", "Do you want to delete this room from the list when stopping?\n\nYes = delete room\nNo = keep room")
                delete_on_stop = bool(resp)
        except Exception:
            delete_on_stop = True

        # Send encrypted control-close to peers first (if sockets are open)
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

        # Release camera
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

        # Close any sockets and clear references
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

        # No room deletion on stop; just stop the video feed and keep the window open

    def _send_thread(self, partner_ip, partner_port):
        time.sleep(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        last_err = None
        # Try a few times to connect, in case remote server is starting
        for attempt in range(3):
            try:
                sock.settimeout(5)
                sock.connect((partner_ip, partner_port))
                sock.settimeout(None)
                self.send_sock = sock
                last_err = None
                break
            except Exception as e:
                last_err = e
                time.sleep(1)
        if last_err is not None:
            try:
                sock.close()
            except Exception:
                pass
            print(f"Send connect error: {last_err}")
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

    def _receive_thread(self, port):
        import pickle

        server = self.server_sock
        server.listen(1)
        try:
            server.settimeout(20)
            conn, addr = server.accept()
            conn.settimeout(None)
            self.conn = conn
            print(f"Connected from {addr}")
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

                try:
                    inner = pickle.loads(plaintext)
                except Exception:
                    inner = None

                if isinstance(inner, dict) and inner.get("control"):
                    if inner.get("control") == "close":
                        def do_close():
                            try:
                                messagebox.showinfo("Room closed", "Host has closed the room.")
                            except Exception:
                                pass
                        try:
                            self.after(1, do_close)
                        except Exception:
                            pass
                        try:
                            pil = self._make_placeholder("Host closed")
                            self._schedule_remote_update(pil)
                        except Exception:
                            pass
                        self.running = False
                        break
                else:
                    try:
                        nparr = np.frombuffer(plaintext, np.uint8)
                        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                        if frame is not None:
                            img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                            pil = Image.fromarray(img)
                            self._schedule_remote_update(pil)
                    except Exception as e:
                        print(f"Frame decode error: {e}")
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


if __name__ == "__main__":
    root = tk.Tk()
    app = VideoRoomApp(root)
    root.mainloop()
