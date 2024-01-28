from Crypto.Cipher import AES
import os

def decrypt_file(input_file_path, key, output_file_path):
    try:
        cipher = AES.new(key, AES.MODE_CBC)

        with open(input_file_path, 'rb') as file:
            ciphertext = file.read()

        plaintext = cipher.decrypt(ciphertext)

        # Usuń padding z tekstu jawnego zgodnie z PKCS7
        padding_bytes = plaintext[-1]
        plaintext = plaintext[:-padding_bytes]

        # Zapisz odszyfrowane dane do pliku
        with open(output_file_path, 'wb') as output_file:
            output_file.write(plaintext)

        return True
    except Exception as e:
        print("Błąd podczas odszyfrowywania:", str(e))
        return False
