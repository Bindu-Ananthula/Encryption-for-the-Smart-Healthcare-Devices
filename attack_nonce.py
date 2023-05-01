from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from secrets import token_bytes
import json

# Generate an Elliptic Curve Diffie-Hellman key pair
curve = ec.SECP256R1()
private_key = ec.generate_private_key(curve)

# Generate a shared secret with the server's public key using ECDH
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()
shared_secret = private_key.exchange(ec.ECDH(), server_public_key)

# Use HKDF to derive a symmetric key from the shared secret
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'smart healthcare',
).derive(shared_secret)

# Generate a random nonce for AES-CCM encryption
nonce = token_bytes(12)
# Example data to authenticate
data = {
    "patient_id": "9848676",
    "heart_rate": 80,
    "temperature": 37.5,
}
# Serialize the data to JSON and encode as bytes
json_data = json.dumps(data).encode()
print(f"The value of json_data is {json_data}.")
# Generate a random session key for 5G-AKA
session_key = token_bytes(32)
print(f"The value of session_key is {session_key}.")
# Use HKDF to derive a key for AES-CCM encryption
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'5G-AKA',
).derive(hkdf)
# Encrypt the nonce, JSON data, and session key using AES-CCM with the derived key
aesccm = AESCCM(key=derived_key, tag_length=8)
encrypted_data = aesccm.encrypt(nonce, json_data+session_key, None)
# Decrypt the encrypted data using AES-CCM with the wrong nonce
wrong_nonce = token_bytes(12)
try:
    decrypted_data = aesccm.decrypt(wrong_nonce, encrypted_data, None)
    decrypted_json_data, decrypted_session_key = decrypted_data[:-32], decrypted_data[-32:]
    if decrypted_json_data == json_data and decrypted_session_key == session_key:
        print("Authentication successful")
    else:
        print("Authentication failed")
except:
    print("Decryption failed")
