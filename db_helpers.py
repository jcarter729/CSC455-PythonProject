def get_all_ports():
    """Return a set of all ports currently assigned to users in the DB."""
    db = _get_mongo_db()
    ports = set()
    if db is not None:
        try:
            for user in db.users.find({}, {"port": 1}):
                port = user.get("port")
                if port:
                    ports.add(int(port))
        except Exception:
            pass
    else:
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                users = json.load(f)
                for u in users.values():
                    port = u.get("port")
                    if port:
                        ports.add(int(port))
        except Exception:
            pass
    return ports

def find_available_port(start=10000, end=65535):
    """Find a port not already assigned to any user."""
    used = get_all_ports()
    for port in range(start, end):
        if port not in used:
            return port
    raise RuntimeError("No available ports in range.")
import socket
import os
import json
import uuid
import traceback
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

_load_env_file()

MONGO_URI = os.getenv('MONGO_URI')
_MONGO_CLIENT = None
_MONGO_DB = None
_MONGO_CONNECT_CHECKED = False
_MONGO_FAILED_ALERTED = False

ROOMS_FILE = "rooms.json"
USERS_FILE = "users.json"

# MongoDB connection
def _get_mongo_db():
    global _MONGO_CLIENT, _MONGO_DB
    if not _PYMONGO_AVAILABLE:
        return None
    if _MONGO_DB is not None:
        return _MONGO_DB
    if not MONGO_URI:
        return None
    try:
        if _MONGO_CLIENT is None:
            _MONGO_CLIENT = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            _MONGO_CLIENT.admin.command('ping')
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
        tb = traceback.format_exc()
        global _MONGO_FAILED_ALERTED
        if not _MONGO_FAILED_ALERTED:
            _MONGO_FAILED_ALERTED = True
            try:
                print("MongoDB connection failed (will use local storage where allowed):\n", tb)
            except Exception:
                pass
        return None

def load_rooms():
    db = _get_mongo_db()
    if db is not None:
        try:
            docs = list(db.rooms.find({}))
            rooms = []
            for d in docs:
                r = {k: v for k, v in d.items() if k != '_id'}
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
            db.rooms.delete_many({})
            if rooms:
                db.rooms.insert_many([{**r} for r in rooms])
            return
        except Exception:
            tb = traceback.format_exc()
            print("save_rooms DB error:\n", tb)
            try:
                from tkinter import messagebox
                messagebox.showerror('MongoDB', 'Failed to write rooms collection to MongoDB (see console).')
            except Exception:
                pass
    try:
        message = 'MongoDB not configured or unavailable; cannot persist rooms.'
        print(message)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', message)
        except Exception:
            pass
    except Exception:
        pass

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
            tb = traceback.format_exc()
            print("save_users DB error:\n", tb)
            try:
                from tkinter import messagebox
                messagebox.showerror('MongoDB', 'Failed to write users collection to MongoDB (see console).')
            except Exception:
                pass
    try:
        message = 'MongoDB not configured or unavailable; cannot persist users.'
        print(message)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', message)
        except Exception:
            pass
    except Exception:
        pass

def create_room(room: dict) -> bool:
    db = _get_mongo_db()
    if db is None:
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot create room.')
        except Exception:
            pass
        print('create_room aborted: no MongoDB')
        return False
    try:
        db.rooms.insert_one({**room})
        return True
    except Exception as e:
        tb = traceback.format_exc()
        print("create_room DB error:\n", tb)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', f'Failed to create room in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False

def get_room_by_id(room_id: str):
    db = _get_mongo_db()
    if db is not None:
        try:
            d = db.rooms.find_one({'id': room_id}, projection={'_id': False})
            return d
        except Exception as e:
            print("get_room_by_id DB error:\n", traceback.format_exc())
            try:
                from tkinter import messagebox
                messagebox.showerror('MongoDB', 'Error reading room from MongoDB (see console).')
            except Exception:
                pass
            return None
    for r in load_rooms() or []:
        if r.get('id') == room_id:
            return r
    return None

def update_room(room: dict) -> bool:
    rid = room.get('id')
    if not rid:
        return False
    db = _get_mongo_db()
    if db is None:
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot update room.')
        except Exception:
            pass
        print('update_room aborted: no MongoDB')
        return False
    try:
        db.rooms.update_one({'id': rid}, {'$set': {**room}}, upsert=True)
        return True
    except Exception as e:
        tb = traceback.format_exc()
        print("update_room DB error:\n", tb)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', f'Failed to update room in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False

def delete_room_by_id(room_id: str) -> bool:
    db = _get_mongo_db()
    if db is None:
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot delete room.')
        except Exception:
            pass
        print('delete_room_by_id aborted: no MongoDB')
        return False
    try:
        db.rooms.delete_one({'id': room_id})
        return True
    except Exception as e:
        tb = traceback.format_exc()
        print("delete_room_by_id DB error:\n", tb)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', f'Failed to delete room in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False

def create_user(username: str, data: dict) -> bool:
    db = _get_mongo_db()
    if db is None:
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot create user.')
        except Exception:
            pass
        print('create_user aborted: no MongoDB')
        return False
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        doc = {'username': username, **(data or {}), 'ip_address': ip_address}
        db.users.insert_one(doc)
        return True
    except Exception as e:
        tb = traceback.format_exc()
        print("create_user DB error:\n", tb)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', f'Failed to create user in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False

def get_user(username: str):
    db = _get_mongo_db()
    if db is not None:
        try:
            d = db.users.find_one({'username': username}, projection={'_id': False})
            if not d:
                return None
            d2 = {k: v for k, v in d.items() if k != 'username'}
            return d2
        except Exception as e:
            print("get_user DB error:\n", traceback.format_exc())
            try:
                from tkinter import messagebox
                messagebox.showerror('MongoDB', 'Error reading user from MongoDB (see console).')
            except Exception:
                pass
            return None
    users = load_users() or {}
    return users.get(username)

def update_user(username: str, data: dict) -> bool:
    if not username:
        return False
    db = _get_mongo_db()
    if db is None:
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot update user.')
        except Exception:
            pass
        print('update_user aborted: no MongoDB')
        return False
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        doc = {'username': username, **(data or {}), 'ip_address': ip_address}
        db.users.update_one({'username': username}, {'$set': doc}, upsert=True)
        return True
    except Exception as e:
        tb = traceback.format_exc()
        print("update_user DB error:\n", tb)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', f'Failed to update user in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False

def delete_user(username: str) -> bool:
    db = _get_mongo_db()
    if db is None:
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot delete user.')
        except Exception:
            pass
        print('delete_user aborted: no MongoDB')
        return False
    try:
        db.users.delete_one({'username': username})
        return True
    except Exception as e:
        tb = traceback.format_exc()
        print("delete_user DB error:\n", tb)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', f'Failed to delete user in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False

def hash_password(password: str, salt: bytes = None):
    from hashlib import pbkdf2_hmac
    import os
    if salt is None:
        salt = os.urandom(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)
    return salt, dk

def create_user_with_ip_port(username, password, ip, port=None):
    db = _get_mongo_db()
    if db is None:
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', 'MongoDB not configured or unreachable; cannot create user.')
        except Exception:
            pass
        print('create_user aborted: no MongoDB')
        return False
    try:
        salt, hashed = hash_password(password)
        # Assign a unique port if not provided
        if port is None:
            port = find_available_port()
        else:
            # Ensure port is unique
            used_ports = get_all_ports()
            if int(port) in used_ports:
                raise ValueError(f"Port {port} is already in use.")
        doc = {
            'username': username,
            'password_hash': hashed.hex(),
            'salt': salt.hex(),
            'ip': ip,
            'port': port
        }
        db.users.insert_one(doc)
        return True
    except Exception as e:
        tb = traceback.format_exc()
        print("create_user_with_ip_port DB error:\n", tb)
        try:
            from tkinter import messagebox
            messagebox.showerror('MongoDB', f'Failed to create user in MongoDB:\n{tb.splitlines()[-1]}')
        except Exception:
            pass
        return False
