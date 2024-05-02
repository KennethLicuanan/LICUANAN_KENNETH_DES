from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Generate a secure DES key
def generate_des_key():
    return get_random_bytes(8)

# Create a DES Cipher instance
def create_des_cipher(key, mode=DES.MODE_ECB):
    return DES.new(key, mode)

# Convert string to byte array
def string_to_bytes(message):
    return message.encode('utf-8')

# Convert byte array to string
def bytes_to_string(byte_array):
    return byte_array.decode('utf-8')

# Encrypt plaintext
def encrypt(plaintext, key):
    cipher = create_des_cipher(key)
    plaintext_bytes = string_to_bytes(plaintext)
    padded_plaintext = pad(plaintext_bytes, DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode('utf-8')

# Decrypt ciphertext
def decrypt(ciphertext, key):
    cipher = create_des_cipher(key)
    ciphertext_bytes = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(ciphertext_bytes)
    unpadded_decrypted = unpad(decrypted, DES.block_size)
    return bytes_to_string(unpadded_decrypted)

# Example usage
if __name__ == "__main__":
    key = generate_des_key()
    plaintext = "Hello, this is a secret message!"
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)
    print("Decrypted:", decrypted)
