from Crypto.Cipher import DES, Salsa20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Generate a random key for DES
des_key = get_random_bytes(8)

# Generate a random key for the stream cipher
stream_key = get_random_bytes(16)

# Generate a random IV for the stream cipher
iv = get_random_bytes(8)

# Initialize the DES cipher with the generated key
des_cipher = DES.new(des_key, DES.MODE_ECB)

# Initialize the Salsa20 stream cipher with the generated key and IV
stream_cipher = Salsa20.new(key=stream_key, nonce=iv)

def encrypt(message):
    # Pad the message to a multiple of 8 bytes using PKCS#7 padding
    padded_message = pad(message.encode(), 8)

    # Encrypt the padded message using DES
    ciphertext = des_cipher.encrypt(padded_message)

    # Encrypt the ciphertext using the Salsa20 stream cipher
    encrypted_message = stream_cipher.encrypt(ciphertext)

    # Encode the encrypted message and IV as base64 for ASCII compatibility
    encoded_message = base64.b64encode(encrypted_message)
    encoded_iv = base64.b64encode(iv)

    return encoded_message, encoded_iv

def decrypt(encrypted_message, iv):
    # Decode the encrypted message and IV from base64
    decoded_message = base64.b64decode(encrypted_message)
    decoded_iv = base64.b64decode(iv)

    # Initialize the Salsa20 stream cipher with the key and IV
    stream_cipher = Salsa20.new(key=stream_key, nonce=decoded_iv)

    # Decrypt the encrypted message using the Salsa20 stream cipher
    decrypted_message = stream_cipher.decrypt(decoded_message)

    # Decrypt the decrypted message using DES
    unpadded_message = des_cipher.decrypt(decrypted_message)

    # Unpad the decrypted message using PKCS#7 padding
    plaintext = unpad(unpadded_message, 8).decode(errors='replace')

    return plaintext

# Example usage
message = input("Enter your message: ")
encrypted, iv = encrypt(message)
decrypted = decrypt(encrypted, iv)

print("Original message:", message)
print("Encrypted message:", encrypted)
print("Decrypted message:", decrypted)