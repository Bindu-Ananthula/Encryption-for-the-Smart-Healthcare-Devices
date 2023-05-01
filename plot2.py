import os
import timeit
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
# Get ECC public key from private key
public_key = private_key.public_key()
# Get the public key serialized in bytes
public_key_bytes = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
# Data sizes to be encrypted
data_sizes = [10, 100, 1000, 10000, 100000]
# List to store encryption times
encryption_times = []
for data_size in data_sizes:
    # Generate random data to be encrypted
    data = b"A" * data_size
    # Encrypt and time the encryption operation
    start_time = timeit.default_timer()
    # Generate ephemeral ECC key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()
    # Serialize the ephemeral public key
    ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    # Generate shared key using ECDH
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    # Derive a 25
	# 6-bit encryption key using HKDF with a random salt
    length = 32
    salt = os.urandom(16)
    info = None
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    encryption_key = hkdf.derive(shared_key)
    # Generate a random 96-bit nonce
    nonce = os.urandom(12)
	
    # Create the AES-CCM cipher object
    cipher = AESCCM(key=encryption_key, tag_length=16)
    # Encrypt the data
    encrypted_data = cipher.encrypt(nonce, data, None)
    # Calculate the encryption time
    encryption_time = timeit.default_timer() - start_time
    # Add the encryption time to the list
    encryption_times.append(encryption_time)
    # Print the encryption time
    print(f"Encrypting and decrypting {len(data)} bytes of data... done in {encryption_time:.6f} seconds.")

# Plot the encryption times
plt.plot(data_sizes, encryption_times, label='Encryption')

# Add title and labels to the plot
plt.title('AES-CCM Encryption Time vs Data Size')
plt.xlabel('Data Size (bytes)')
plt.ylabel('Encryption Time (s)')

# Add a legend to the plot
plt.legend()

# Show the plot
plt.show()
