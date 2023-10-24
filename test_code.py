from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate an RSA key pair
key = RSA.generate(2048)
public_key = key.publickey()

# Data to be "encrypted" with the private key
plaintext_data = b'This is the data to be "encrypted" with the private key'

# Use the public key for "encryption"
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(plaintext_data)

# Use the public key for "decryption"
decipher = PKCS1_OAEP.new(key)
decrypted_data = decipher.decrypt(ciphertext)

# The decrypted data should match the original plaintext
print("Original Data:", plaintext_data.decode('utf-8'))
print("Decrypted Data:", decrypted_data.decode('utf-8'))
