from Crypto.Cipher import Blowfish
import os

def encrypt_blowfish(input_file_path, output_file_path, key):
    try:
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)

        with open(input_file_path, 'rb') as file:
            plaintext = file.read()

        ciphertext = cipher.encrypt(plaintext)

        with open(output_file_path, 'wb') as output_file:
            output_file.write(ciphertext)

        return True
    except Exception as e:
        print("Błąd podczas szyfrowania Blowfish:", str(e))
        return False

def decrypt_blowfish(input_file_path, output_file_path, key):
    try:
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)

        with open(input_file_path, 'rb') as file:
            ciphertext = file.read()

        plaintext = cipher.decrypt(ciphertext)

        with open(output_file_path, 'wb') as output_file:
            output_file.write(plaintext)

        return True
    except Exception as e:
        print("Błąd podczas deszyfrowania Blowfish:", str(e))
        return False
