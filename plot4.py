import os
import timeit
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())	# Generate ECC private key
public_key = private_key.public_key()	# Get ECC public key from private key
# Get the public key serialized in bytes
public_key_bytes = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
data_sizes = [10, 100, 1000, 10000, 100000]		# Data sizes to be encrypted
num_simulations = 10		# Number of simulations
encryption_times = [[] for _ in range(num_simulations)]   # List to store encryption times for each simulation
for i in range(num_simulations):
    for data_size in data_sizes:
        data = b"A" * data_size		# Generate random data to be encrypted
        start_time = timeit.default_timer()		# Encrypt and time the encryption operation
        ephemeral_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())	# Generate ephemeral ECC key pair
        ephemeral_public_key = ephemeral_private_key.public_key()
        # Serialize the ephemeral public key
        ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        # Generate shared key using ECDH
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
        length = 32		# Derive a 256-bit encryption key using HKDF with a random salt
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
        nonce = os.urandom(12)	# Generate a random 96-bit nonce
        cipher = AESCCM(key=encryption_key, tag_length=16)	# Create the AES-CCM cipher object
        encrypted_data = cipher.encrypt(nonce, data, None)	# Encrypt the data
        encryption_time = timeit.default_timer() - start_time	# Calculate the encryption time
        encryption_times[i].append(encryption_time)		# Add the encryption time to the list for the current simulation
        # Print the encryption time
        print(f"Simulation {i+1}: Encrypting and decrypting {len(data)} bytes of data... done in {encryption_time:.6f} seconds.")

		
# Plot a bar graph for each data size for all simulations
for j, data_size in enumerate(data_sizes):
    plt.bar([f" {i+1}" for i in range(num_simulations)], [encryption_times[i][j] for i in range(num_simulations)])
    plt.title(f"AES-CCM Encryption Time vs Simulation for Data Size {data_size} bytes")
    plt.xlabel("Simulation")
    plt.ylabel('Encryption Time (s)')
    plt.show()
