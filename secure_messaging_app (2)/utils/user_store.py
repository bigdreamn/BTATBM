import json
import os

USER_FILE = "users.json"

def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f)

def add_user(username, password_hash):
    users = load_users()
    users[username] = {'password': password_hash.decode()}
    save_users(users)

def get_user(username):
    users = load_users()
    return users.get(username)