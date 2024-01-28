import tkinter as tk
from tkinter import filedialog, ttk
import MyAES as AES
import MyDES as DES
import MyRSA as RSA
import os

def encrypt_file():
    file_path = file_label.cget("text")
    if file_path != "Nie wybrano pliku":
        if selected_algorithm == "AES":
            key = AES.encrypt_aes(file_path, file_path + ".zaszyfrowany")
            if key is not None:
                display_key = key.hex()
                key_display.delete(1.0, tk.END)  # Usuń poprzedni klucz
                key_display.insert(tk.END, display_key)  # Wyświetl nowy klucz
        # ...

def decrypt_file():
    file_path = decrypt_file_label.cget("text")
    if file_path != "Nie wybrano pliku do odszyfrowania":
        if selected_algorithm == "AES":
            key = AES.decrypt_aes(file_path)
            display_key = key.hex()
            decrypted_file_path = os.path.splitext(file_path)[0]  # Usunięcie rozszerzenia ".zaszyfrowany"
            decrypted_file_path = decrypted_file_path + '.odszyfrowany'  # Dodanie rozszerzenia ".odszyfrowany"
            key_display.config(text="Klucz: " + display_key)
            decrypt_file_label.config(text="Nie wybrano pliku do odszyfrowania")
        elif selected_algorithm == "DES":
            key = DES.decrypt_des(file_path)
            display_key = key.hex()
            decrypted_file_path = os.path.splitext(file_path)[0]  # Usunięcie rozszerzenia ".zaszyfrowany"
            decrypted_file_path = decrypted_file_path + '.odszyfrowany'  # Dodanie rozszerzenia ".odszyfrowany"
            key_display.config(text="Klucz: " + display_key)
            decrypt_file_label.config(text="Nie wybrano pliku do odszyfrowania")
        elif selected_algorithm == "RSA":
            # Tutaj dodaj logikę odszyfrowywania RSA
            display_key = "RSA Key"
        else:
            key_display.config(text="Nie wybrano algorytmu szyfrowania")
            return
    else:
        key_display.config(text="Proszę wybrać plik do odszyfrowania")

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
    rsa_button.config(relief="sunken" if alg == "RSA" else "raised")

def copy_key():
    key = key_display.get(1.0, tk.END)  # Pobierz klucz z pola tekstowego
    root.clipboard_clear()  # Wyczyść schowek
    root.clipboard_append(key)  # Skopiuj klucz do schowka
    root.update()  # Zaktualizuj schowek

root = tk.Tk()
root.title("Bezpieczne Trzymanie Plików")
root.geometry("600x400")

select_button = tk.Button(root, text="Wybierz plik do zaszyfrowania", command=select_file)
select_button.pack()

file_label = tk.Label(root, text="Nie wybrano pliku")
file_label.pack()

select_decrypt_button = tk.Button(root, text="Wybierz plik do odszyfrowania", command=select_decrypt_file)
select_decrypt_button.pack()

decrypt_file_label = tk.Label(root, text="Nie wybrano pliku do odszyfrowania")
decrypt_file_label.pack()

decrypt_button = tk.Button(root, text="Odszyfruj", command=decrypt_file)
decrypt_button.pack()

progress = ttk.Progressbar(root, orient='horizontal', length=100, mode='determinate')
progress.pack()

algorithms_frame = tk.Frame(root)
algorithms_frame.pack()

selected_algorithm = None

aes_button = tk.Button(algorithms_frame, text="AES", command=lambda: select_algorithm("AES"))
aes_button.pack(side=tk.LEFT)

des_button = tk.Button(algorithms_frame, text="DES", command=lambda: select_algorithm("DES"))
des_button.pack(side=tk.LEFT)

rsa_button = tk.Button(algorithms_frame, text="RSA", command=lambda: select_algorithm("RSA"))
rsa_button.pack(side=tk.LEFT)

encrypt_button = tk.Button(root, text="Szyfruj", command=encrypt_file)
encrypt_button.pack()

key_display = tk.Text(root, height=1, width=40)
key_display.pack()

copy_button = tk.Button(root, text="Kopiuj klucz", command=copy_key)
copy_button.pack()

root.mainloop()
