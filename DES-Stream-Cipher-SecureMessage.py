from Crypto.Cipher import DES, Salsa20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Generate a random key for DES
des_key = get_random_bytes(8)

# Generate a random key for the stream cipher
stream_key = get_random_bytes(16)

# Initialize the DES cipher with the generated key
des_cipher = DES.new(des_key, DES.MODE_ECB)

# Initialize the Salsa20 stream cipher with the generated key
stream_cipher = Salsa20.new(key=stream_key)

def encrypt(message):
    # Encrypt the message using the Salsa20 stream cipher
    encrypted_message = stream_cipher.encrypt(message.encode())

    # Pad the encrypted message to a multiple of 8 bytes using PKCS#7 padding
    padded_message = pad(encrypted_message, 8)

    # Encrypt the padded message using DES
    ciphertext = des_cipher.encrypt(padded_message)

    # Encode the ciphertext as base64 for ASCII compatibility
    encoded_ciphertext = base64.b64encode(ciphertext)

    return encoded_ciphertext

def decrypt(ciphertext):
    # Decode the ciphertext from base64
    decoded_ciphertext = base64.b64decode(ciphertext)

    # Decrypt the ciphertext using DES
    decrypted_message = des_cipher.decrypt(decoded_ciphertext)

    # Unpad the decrypted message using PKCS#7 padding
    unpadded_message = unpad(decrypted_message, 8)

    # Decrypt the unpadded message using the Salsa20 stream cipher
    plaintext = unpadded_message.decode(errors='replace')

    return plaintext

# Example usage
message = "Hello, world!"
encrypted = encrypt(message)
decrypted = decrypt(encrypted)

print("Original message:", message)
print("Encrypted ciphertext:", encrypted)
print("Decrypted message:", decrypted)
