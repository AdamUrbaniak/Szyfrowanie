from Crypto.Cipher import DES
import os

def encrypt_des(input_file_path, output_file_path):
    try:
        key = os.urandom(8)  # Generuj losowy klucz 64-bitowy (DES używa 56 bitów do szyfrowania)
        iv = os.urandom(8)  # Generuj losowy IV (Initial Vector) 64-bitowy
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        with open(input_file_path, 'rb') as file:
            plaintext = file.read()

        # Uzupełnij tekst jawnie zgodnie z PKCS7
        block_size = DES.block_size
        padding_bytes = block_size - len(plaintext) % block_size
        plaintext += bytes([padding_bytes] * padding_bytes)

        ciphertext = cipher.encrypt(plaintext)

        # Zapisz IV i zaszyfrowany tekst do pliku
        with open(output_file_path, 'wb') as output_file:
            output_file.write(iv + ciphertext)

        return key
    except Exception as e:
        print("Błąd podczas szyfrowania DES:", str(e))
        return None

def decrypt_des(input_file_path, key):
    try:
        with open(input_file_path, 'rb') as file:
            iv = file.read(8)  # Odczytaj IV (64-bitowy)
            ciphertext = file.read()  # Odczytaj zaszyfrowany tekst

        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        # Usuń padding z tekstu jawnego zgodnie z PKCS7
        padding_bytes = plaintext[-1]
        if padding_bytes > DES.block_size:
            return None  # Nieprawidłowy padding
        plaintext = plaintext[:-padding_bytes]

        return plaintext
    except Exception as e:
        print("Błąd podczas odszyfrowywania DES:", str(e))
        return None
