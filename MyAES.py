from Crypto.Cipher import AES
import os

def encrypt_aes(input_file_path, output_file_path):
    try:
        key = os.urandom(32)  # Generuj losowy klucz 256-bitowy
        iv = os.urandom(AES.block_size)  # Generuj losowy IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(input_file_path, 'rb') as file:
            plaintext = file.read()

        # Uzupełnij tekst jawnie zgodnie z PKCS7
        block_size = AES.block_size
        padding_bytes = block_size - len(plaintext) % block_size
        plaintext += bytes([padding_bytes] * padding_bytes)

        ciphertext = cipher.encrypt(plaintext)

        # Zapisz IV i zaszyfrowany tekst do pliku
        with open(output_file_path, 'wb') as output_file:
            output_file.write(iv + ciphertext)

        return key
    except Exception as e:
        print("Błąd podczas szyfrowania AES:", str(e))
        return None

def decrypt_aes(input_file_path, key):
    try:
        with open(input_file_path, 'rb') as file:
            iv = file.read(AES.block_size)  # Odczytaj IV
            ciphertext = file.read()  # Odczytaj zaszyfrowany tekst

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        # Usuń padding z tekstu jawnego zgodnie z PKCS7
        padding_bytes = plaintext[-1]
        if padding_bytes > AES.block_size:
            return None  # Nieprawidłowy padding
        plaintext = plaintext[:-padding_bytes]

        return plaintext
    except Exception as e:
        print("Błąd podczas odszyfrowywania AES:", str(e))
        return None