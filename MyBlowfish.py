from Crypto.Cipher import Blowfish
import os

def encrypt_blowfish(input_file_path, output_file_path):
    try:
        key = os.urandom(16)  # Generuj losowy klucz 128-bitowy
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)

        with open(input_file_path, 'rb') as file:
            plaintext = file.read()

        # Uzupełnij tekst jawnie zgodnie z PKCS7
        block_size = Blowfish.block_size
        padding_bytes = block_size - len(plaintext) % block_size
        plaintext += bytes([padding_bytes] * padding_bytes)

        ciphertext = cipher.encrypt(plaintext)

        # Zapisz IV i zaszyfrowany tekst do pliku
        with open(output_file_path, 'wb') as output_file:
            output_file.write(key + cipher.iv + ciphertext)  # Zapisz klucz przed IV

        return key  # Zwracaj klucz

    except Exception as e:
        print("Błąd podczas szyfrowania Blowfish:", str(e))
        return None

def decrypt_blowfish(input_file_path, key, output_file_path):
    try:
        with open(input_file_path, 'rb') as file:
            key_read = file.read(16)  # Odczytaj klucz
            iv = file.read(Blowfish.block_size)  # Odczytaj IV
            ciphertext = file.read()  # Odczytaj zaszyfrowany tekst

        cipher = Blowfish.new(key_read, Blowfish.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        # Usuń padding z tekstu jawnego zgodnie z PKCS7
        padding_bytes = plaintext[-1]
        if padding_bytes > Blowfish.block_size:
            return False  # Nieprawidłowy padding

        plaintext = plaintext[:-padding_bytes]

        with open(output_file_path, 'wb') as output_file:
            output_file.write(plaintext)

        return True  # Sukces

    except Exception as e:
        print("Błąd podczas odszyfrowywania Blowfish:", str(e))
        return False  # Odszyfrowanie nie powiodło się
