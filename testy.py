root = tk.Tk()
root.title("Bezpieczne Trzymanie Plików")
root.geometry("685x300")  # Zmodyfikowana szerokość, aby pasować do nowego układu

# Ustawienie lewego dolnego rogu
select_button = tk.Button(root, text="Wybierz plik do zaszyfrowania", command=select_file)
select_button.place(x=10, y=260)

file_label = tk.Label(root, text="Nie wybrano pliku")
file_label.place(x=10, y=235)

# Ustawienie prawego dolnego rogu
select_decrypt_button = tk.Button(root, text="Wybierz plik do odszyfrowania", command=select_decrypt_file)
select_decrypt_button.place(x=420, y=260)

decrypt_file_label = tk.Label(root, text="Nie wybrano pliku do odszyfrowania")
decrypt_file_label.place(x=420, y=235)

# Ustawienie prawej strony
key_entry_label = tk.Label(root, text="Wprowadź klucz do odszyfrowania:")
key_entry_label.place(x=250, y=10)

key_entry = tk.Entry(root, width=96)
key_entry.place(x=50, y=35)

decrypt_button = tk.Button(root, text="Odszyfruj", command=decrypt_file)
decrypt_button.place(x=610, y=260)

# Ustawienie lewej strony
encrypt_button = tk.Button(root, text="Szyfruj", command=encrypt_file)
encrypt_button.place(x=200, y=260)

key_display = tk.Text(root, height=1, width=72)
key_display.place(x=50, y=160)

copy_button = tk.Button(root, text="Kopiuj klucz", command=copy_key)
copy_button.place(x=300, y=200)

progress = ttk.Progressbar(root, orient='horizontal', length=580, mode='determinate')
progress.place(x=50, y=100)

# Ustawienie centrum
algo_label = tk.Label(root, text="Wybierz rodzaj szyfrowania:")
algo_label.place(x=250, y=235)

aes_button = tk.Button(root, text="AES", command=lambda: select_algorithm("AES"))
aes_button.place(x=270, y=260)

des_button = tk.Button(root, text="DES", command=lambda: select_algorithm("DES"))
des_button.place(x=310, y=260)

rsa_button = tk.Button(root, text="RSA", command=lambda: select_algorithm("RSA"))
rsa_button.place(x=350, y=260)

encrypt_button.config(command=encrypt_file_threaded)
decrypt_button.config(command=decrypt_file_threaded)

root.mainloop()
















def decrypt_file():
    file_path = decrypt_file_label.cget("text")
    if file_path != "Nie wybrano pliku do odszyfrowania":
        entered_key = key_entry.get().strip()

        try:
            decrypted_data = None
            dirname, filename = os.path.split(file_path)
            decrypted_file_path = os.path.join(dirname, "Odszyfrowany_" + filename.replace("Zaszyfrowany_", ""))

            if selected_algorithm == "AES":
                key = bytes.fromhex(entered_key)
                decrypted_data = AES.decrypt_aes(file_path, key)
            elif selected_algorithm == "DES":
                key = bytes.fromhex(entered_key)
                decrypted_data = DES.decrypt_des(file_path, key)
            elif selected_algorithm == "RC4":
                key = entered_key.encode()  # Klucz RC4 jest już w postaci bajtowej
                rc4_cipher = RC4.RC4(key)
                with open(file_path, 'rb') as input_file:
                    ciphertext = input_file.read()
                decrypted_data = rc4_cipher.decrypt(ciphertext)

            if decrypted_data is not None:
                with open(decrypted_file_path, 'wb') as output_file:
                    output_file.write(decrypted_data)

                decrypt_file_label.config(text="Plik odszyfrowany: " + decrypted_file_path)
            else:
                decrypt_file_label.config(text="Nieprawidłowy klucz lub uszkodzony plik")
        except ValueError:
            decrypt_file_label.config(text="Nieprawidłowy format klucza")
