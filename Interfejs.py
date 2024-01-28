import tkinter as tk
from tkinter import filedialog, ttk
import os
import MyAES as AES
import MyDES as DES
import MyBlowfish

selected_algorithm = ""  # Zmienna globalna do przechowywania wybranego algorytmu

def encrypt_file():
    file_path = file_label.cget("text")
    if file_path != "Nie wybrano pliku":
        if selected_algorithm == "AES":
            dirname, filename = os.path.split(file_path)
            encrypted_file_path = os.path.join(dirname, "Zaszyfrowany_" + filename)
            key = AES.encrypt_aes(file_path, encrypted_file_path)
            if key is not None:
                display_key = key.hex()
                key_display.delete(1.0, tk.END)
                key_display.insert(tk.END, display_key)
        elif selected_algorithm == "DES":
            dirname, filename = os.path.split(file_path)
            encrypted_file_path = os.path.join(dirname, "Zaszyfrowany_" + filename)
            key = DES.encrypt_des(file_path, encrypted_file_path)
            if key is not None:
                display_key = key.hex()
                key_display.delete(1.0, tk.END)
                key_display.insert(tk.END, display_key)
        elif selected_algorithm == "BlowFish":
            dirname, filename = os.path.split(file_path)
            encrypted_file_path = os.path.join(dirname, "Zaszyfrowany_" + filename)
            key = MyBlowfish.encrypt_blowfish(file_path, encrypted_file_path)
            if key is not None:
                display_key = key.hex()
                key_display.delete(1.0, tk.END)
                key_display.insert(tk.END, display_key)

def decrypt_file():
    file_path = decrypt_file_label.cget("text")
    if file_path != "Nie wybrano pliku do odszyfrowania":
        if selected_algorithm == "AES":
            entered_key = key_entry.get().strip()
            try:
                key = bytes.fromhex(entered_key)
                decrypted_data = AES.decrypt_aes(file_path, key)
                if decrypted_data is not None:
                    dirname, filename = os.path.split(file_path)
                    decrypted_file_path = os.path.join(dirname, "Odszyfrowany_" + filename.replace("Zaszyfrowany_", ""))

                    with open(decrypted_file_path, 'wb') as output_file:
                        output_file.write(decrypted_data)

                    decrypt_file_label.config(text="Plik odszyfrowany: " + decrypted_file_path)
                else:
                    decrypt_file_label.config(text="Nieprawidłowy klucz lub uszkodzony plik")
            except ValueError:
                decrypt_file_label.config(text="Nieprawidłowy format klucza")
        elif selected_algorithm == "DES":
            entered_key = key_entry.get().strip()
            try:
                key = bytes.fromhex(entered_key)
                decrypted_data = DES.decrypt_des(file_path, key)
                if decrypted_data is not None:
                    dirname, filename = os.path.split(file_path)
                    decrypted_file_path = os.path.join(dirname, "Odszyfrowany_" + filename.replace("Zaszyfrowany_", ""))

                    with open(decrypted_file_path, 'wb') as output_file:
                        output_file.write(decrypted_data)

                    decrypt_file_label.config(text="Plik odszyfrowany: " + decrypted_file_path)
                else:
                    decrypt_file_label.config(text="Nieprawidłowy klucz lub uszkodzony plik")
            except ValueError:
                decrypt_file_label.config(text="Nieprawidłowy format klucza")
        elif selected_algorithm == "BlowFish":
            entered_key = key_entry.get().strip()
            dirname, filename = os.path.split(file_path)
            decrypted_file_path = os.path.join(dirname, "Odszyfrowany_" + filename.replace("Zaszyfrowany_", ""))
            try:
                key = bytes.fromhex(entered_key)
                success = MyBlowfish.decrypt_blowfish(file_path, key, decrypted_file_path)
                if decrypted_data is not None:
                    dirname, filename = os.path.split(file_path)
                    decrypted_file_path = os.path.join(dirname, "Odszyfrowany_" + filename.replace("Zaszyfrowany_", ""))

                    with open(decrypted_file_path, 'wb') as output_file:
                        output_file.write(decrypted_data)

                    decrypt_file_label.config(text="Plik odszyfrowany: " + decrypted_file_path)
                else:
                    decrypt_file_label.config(text="Nieprawidłowy klucz lub uszkodzony plik")
            except ValueError:
                decrypt_file_label.config(text="Nieprawidłowy format klucza")

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_label.config(text=file_path)

def select_decrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        decrypt_file_label.config(text=file_path)

def select_algorithm(alg):
    global selected_algorithm
    selected_algorithm = alg
    aes_button.config(relief="sunken" if alg == "AES" else "raised")
    des_button.config(relief="sunken" if alg == "DES" else "raised")
    blowfish_button.config(relief="sunken" if alg == "BlowFish" else "raised")

def copy_key():
    key = key_display.get(1.0, tk.END).strip()  # Usuń dodatkowe spacje i znaki nowej linii
    root.clipboard_clear()
    root.clipboard_append(key)
    root.update()

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

# Ustawienie centrum
algo_label = tk.Label(root, text="Wybierz rodzaj szyfrowania:")
algo_label.place(x=250, y=235)

aes_button = tk.Button(root, text="AES", command=lambda: select_algorithm("AES"))
aes_button.place(x=270, y=260)

des_button = tk.Button(root, text="DES", command=lambda: select_algorithm("DES"))
des_button.place(x=310, y=260)

blowfish_button = tk.Button(root, text="BlowFish", command=lambda: select_algorithm("BlowFish"))
blowfish_button.place(x=350, y=260)

root.mainloop()