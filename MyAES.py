from Crypto.Cipher import AES
import os

def encrypt_aes(input_file_path, output_file_path):
    try:
        key = os.urandom(32)  # Generuj losowy klucz 256-bitowy
        cipher = AES.new(key, AES.MODE_CBC)
        
        with open(input_file_path, 'rb') as file:
            plaintext = file.read()

        # Uzupełnij tekst jawnie zgodnie z PKCS7
        block_size = AES.block_size
        padding_bytes = block_size - len(plaintext) % block_size
        plaintext += bytes([padding_bytes] * padding_bytes)

        ciphertext = cipher.encrypt(plaintext)

        # Zapisz zaszyfrowany plik
        with open(output_file_path, 'wb') as output_file:
            output_file.write(ciphertext)

        # Zwróć klucz
        return key
    except Exception as e:
        print("Błąd podczas szyfrowania AES:", str(e))
        return None
