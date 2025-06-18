import json
import os

def get_msg_file(username):
    return f"messages/{username}.json"

def load_inbox(username):
    path = get_msg_file(username)
    if not os.path.exists(path):
        return []
    with open(path, 'r') as f:
        return json.load(f)

def save_message(to_user, msg):
    inbox = load_inbox(to_user)
    inbox.append(msg)
    with open(get_msg_file(to_user), 'w') as f:
        json.dump(inbox, f)