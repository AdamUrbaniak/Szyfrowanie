from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import os

def pad_des(s):
    return s + (DES.block_size - len(s) % DES.block_size) * chr(DES.block_size - len(s) % DES.block_size)

def encrypt_des(file_path):
    key = get_random_bytes(8)  # Klucz 8 bajtów dla DES
    cipher = DES.new(key, DES.MODE_ECB)
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    ciphertext = cipher.encrypt(pad_des(plaintext))
    # Zapisz zaszyfrowane dane do nowego pliku
    encrypted_file_path = file_path + ".zaszyfrowany"
    with open(encrypted_file_path, 'wb') as file:
        file.write(ciphertext)
    return key
