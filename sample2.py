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
print(f"the session_key value {session_key}")

# Concatenate the nonce, JSON data, and session key to form the 5G-AKA token
aka_token = nonce + json_data + session_key
print(f"the aka_token value {aka_token}")
# Encrypt the 5G-AKA token with AES-CCM using the derived key and nonce
aesccm = AESCCM(key=hkdf, tag_length=8)
print(f"the aesccm value {aesccm}")
ciphertext = aesccm.encrypt(nonce, aka_token, None)
print(f"the ciphertext value {ciphertext}")
# Decrypt and verify the 5G-AKA token with AES-CCM using the derived key and nonce
try:
    decrypted_token = aesccm.decrypt(nonce, ciphertext, None)
    if decrypted_token == aka_token:
        print("Authentication successful ")
    else:
        print("Authentication failed")

except:
    print("Decryption failed")


