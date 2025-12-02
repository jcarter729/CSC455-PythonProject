#!/usr/bin/env python3
"""Migrate local rooms.json and users.json into MongoDB.

Usage:
  set MONGO_URI=mongodb+srv://user:pass@...    (Windows cmd)
  python migrate_to_mongo.py [--yes]

This script will connect to the database specified by `MONGO_URI` and
replace the `rooms` and `users` collections with the contents of the
local JSON files (if present).
"""
import os
import json
import argparse
from pymongo import MongoClient


def get_db(uri):
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    # try to derive a database name from the URI, otherwise use csc_rooms
    try:
        from pymongo.uri_parser import parse_uri
        parsed = parse_uri(uri)
        dbname = parsed.get('database')
    except Exception:
        dbname = None
    if not dbname:
        dbname = 'csc_rooms'
    return client[dbname]


def load_json_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        raise


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--uri', help='MongoDB connection URI (overrides MONGO_URI env var)')
    p.add_argument('--yes', action='store_true', help='Perform migration without prompting')
    args = p.parse_args()

    uri = args.uri or os.getenv('MONGO_URI')
    if not uri:
        print('MONGO_URI not set. Provide --uri or set the environment variable and re-run.')
        return

    db = get_db(uri)
    print('Connected to MongoDB, using database:', db.name)

    rooms = load_json_file('rooms.json')
    users = load_json_file('users.json')

    print('Found:', 'rooms.json ->' , 'present' if rooms is not None else 'missing', ',', 'users.json ->', 'present' if users is not None else 'missing')
    if not args.yes:
        ok = input('This will replace collections `rooms` and `users` in the database. Continue? [y/N]: ')
        if ok.lower() not in ('y', 'yes'):
            print('Aborting.')
            return

    if rooms is not None:
        # normalize rooms (ensure id exists)
        for r in rooms:
            if not isinstance(r, dict):
                continue
            if 'id' not in r:
                import uuid
                r['id'] = str(uuid.uuid4())
        print('Replacing rooms collection...')
        db.rooms.delete_many({})
        if rooms:
            db.rooms.insert_many([{**r} for r in rooms])
        print('Inserted', db.rooms.count_documents({}), 'room documents')

    if users is not None:
        # users is expected to be a dict mapping username -> {salt,hash}
        docs = []
        if isinstance(users, dict):
            for username, data in users.items():
                doc = {'username': username, **(data or {})}
                docs.append(doc)
        elif isinstance(users, list):
            # in case users.json is a list of documents
            docs = users
        print('Replacing users collection...')
        db.users.delete_many({})
        if docs:
            db.users.insert_many(docs)
        print('Inserted', db.users.count_documents({}), 'user documents')

    print('Migration complete.')


if __name__ == '__main__':
    main()
