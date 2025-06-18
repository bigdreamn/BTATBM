from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def generate_keys(username):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    os.makedirs(f'keys/{username}', exist_ok=True)

    with open(f'keys/{username}/private.pem', 'wb') as f:
        f.write(private_key)

    with open(f'keys/{username}/public.pem', 'wb') as f:
        f.write(public_key)

def sign_data(username, data):
    with open(f'keys/{username}/private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    hash = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hash)
    return signature

def verify_signature(username, data, signature):
    with open(f'keys/{username}/public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    hash = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False