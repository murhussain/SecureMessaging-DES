from Crypto.Cipher import DES, Salsa20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class FixedIVEncryptor:
  def __init__(self, key):
    self.des_key = key
    self.stream_key = get_random_bytes(16)
    self.iv_count = 0

  def encrypt(self, message):
    # Generate a unique IV for every 2 messages
    if self.iv_count % 2 == 0:
        self.iv = get_random_bytes(8)

    # Initialize the DES cipher with the provided key
    des_cipher = DES.new(self.des_key, DES.MODE_ECB)

    # Initialize the Salsa20 stream cipher with the generated key and IV
    stream_cipher = Salsa20.new(key=self.stream_key, nonce=self.iv)
    padded_message = pad(message.encode(), 8)

    # Encrypt the padded message using DES ans well as incrypting the ciphertext using the Salsa20 stream cipher
    ciphertext = des_cipher.encrypt(padded_message)
    encrypted_message = stream_cipher.encrypt(ciphertext)

    # Encode the encrypted message and IV as base64 for ASCII compatibility
    encoded_message = base64.b64encode(encrypted_message)
    encoded_iv = base64.b64encode(self.iv)

    self.iv_count += 1

    return encoded_message, encoded_iv

  def decrypt(self, encoded_message, encoded_iv):
    # Decode the encrypted message and IV from base64 as well as initializing the DES cipher with the provided key
    encrypted_message = base64.b64decode(encoded_message)
    iv = base64.b64decode(encoded_iv)
    des_cipher = DES.new(self.des_key, DES.MODE_ECB)
    stream_cipher = Salsa20.new(key=self.stream_key, nonce=iv)

    # Decrypt the encrypted message using the Salsa20 stream cipher as well as decripting the decrypted message using DES
    decrypted_message = stream_cipher.decrypt(encrypted_message)
    plaintext = unpad(des_cipher.decrypt(decrypted_message), 8).decode()

    return plaintext

class UniqueIVEncryptor:
  def __init__(self, key):
    self.des_key = key
    self.stream_key = get_random_bytes(16)

  def encrypt(self, message):
    # Generate a unique IV for each flesh encryption
    iv = get_random_bytes(8)

    # Initialize the DES cipher with the provided key and the Salsa20 stream cipher with the generated key and IV
    des_cipher = DES.new(self.des_key, DES.MODE_ECB)
    stream_cipher = Salsa20.new(key=self.stream_key, nonce=iv)

    # Pad the message to a multiple of 8 bytes using PKCS#7 padding and encrypting the padded message using DES
    padded_message = pad(message.encode(), 8)
    ciphertext = des_cipher.encrypt(padded_message)

    # Encrypt the ciphertext using the Salsa20 stream cipher
    encrypted_message = stream_cipher.encrypt(ciphertext)
    encoded_message = base64.b64encode(encrypted_message)
    encoded_iv = base64.b64encode(iv)

    return encoded_message, encoded_iv
    
  def decrypt(self, encoded_message, encoded_iv):
    # Decode the encrypted message and IV from base64 and initializing the DES cipher with the provided key
    encrypted_message = base64.b64decode(encoded_message)
    iv = base64.b64decode(encoded_iv)
    des_cipher = DES.new(self.des_key, DES.MODE_ECB)

    # Initialize the Salsa20 stream cipher with the generated key and IV, plus decrypting the encrypted message using the Salsa20 stream cipher
    stream_cipher = Salsa20.new(key=self.stream_key, nonce=iv)
    decrypted_message = stream_cipher.decrypt(encrypted_message)

    # Decrypt the decrypted message using DES
    plaintext = des_cipher.decrypt(decrypted_message)
    unpadded_plaintext = unpad(plaintext, 8)

    return unpadded_plaintext.decode()

def main():
    # Generate a random key for DES
    des_key = get_random_bytes(8)
    
    # Initializing number of runs
    num_runs = 0
    
    while True:
        print("\n╔═══════════════════════════════════════╗\n"
                "║        Please select an option:       ║\n"
                "║---------------------------------------║\n"
                "║    1. Encrypt using a fixed IV        ║\n"
                "║    2. Encrypt using a unique IV       ║\n"
                "║    3. Exit                            ║\n"
                "╚═══════════════════════════════════════╝\n")

        try:
            choice = int(input("---> "))
        except ValueError:
            print("\n╔═════════════════════════════════════════════╗\n"
                    "║            Invalid - Choice:                ║\n"
                    "║---------------------------------------------║\n"
                    "║    Invalid choice. Please enter a number!   ║\n"
                    "╚═════════════════════════════════════════════╝\n")
            continue

        if choice == 1:
          encryptor = FixedIVEncryptor(des_key)
          iv_warning_count = 0
          num_runs_fixed = 0
          
          while True:
            message = input("\n╔═══════════════════════════════════════╗\n"
                              "║            Type - Message:            ║\n"
                              "║---------------------------------------║\n"
                              "║  Enter a message to encrypt           ║\n"
                              "║  (Or 'back' to return to main menu:   ║\n"
                              "╚═══════════════════════════════════════╝\n")
            if message.lower() == "back":
              break

            encoded_message, encoded_iv = encryptor.encrypt(message)

            iv_warning_count += 1
            num_runs_fixed += 1

            print("\nRun number: --->", num_runs_fixed)
            print("User-A Encrypted message: ---> ", encoded_message)
            print("IV Used: ---> ", encoded_iv)
            decrypted_message = encryptor.decrypt(encoded_message, encoded_iv)
            print("User-B Decrypted message: ---> " + decrypted_message + "\n")

        elif choice == 2:
          encryptor = UniqueIVEncryptor(des_key)
          num_runs_unique = 0
          while True:
            message = input("\n╔═══════════════════════════════════════╗\n"
                              "║           Type - Message:             ║\n"
                              "║---------------------------------------║\n"
                              "║  Enter a message to encrypt           ║\n"
                              "║  (Or 'back' to return to main menu:   ║\n"
                              "╚═══════════════════════════════════════╝\n")
            if message.lower() == "back":
              break

            encoded_message, encoded_iv = encryptor.encrypt(message)
            num_runs_unique += 1

            print("\nRun number: --->", num_runs_unique)          
            print("User-A Encrypted message: ---> ", encoded_message)
            print("IV Used: ---> ", encoded_iv)
            decrypted_message = encryptor.decrypt(encoded_message, encoded_iv)
            print("User-B Decrypted message: ---> " + decrypted_message + "\n")
            
        elif choice == 3:
            print("\n╔═╗╔═╗╔╗╔╦ ╦  ╦═╗╔═╗╔╦╗╔═╗╔╗╔╔═╗╦═╗\n"
                    "╠═╝║ ║║║║║ ║  ╠╦╝╠═╣║║║║ ║║║║║ ║╠╦╝\n"
                    "╩  ╚═╝╝╚╝╚═╝  ╩╚═╩ ╩╩ ╩╚═╝╝╚╝╚═╝╩╚═\n")
            break

        else:
          print("\n╔═════════════════════════════════════════════╗\n"
                  "║            Invalid - Choice:                ║\n"
                  "║---------------------------------------------║\n"
                  "║    Invalid choice. Please enter a number!   ║\n"
                  "╚═════════════════════════════════════════════╝\n")
if __name__ == "__main__":
    main()