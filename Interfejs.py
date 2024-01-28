import tkinter as tk
from tkinter import filedialog, ttk
import MyAES as AES
import os

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
    key = key_display.get(1.0, tk.END).strip()  # Usuń dodatkowe spacje i znaki nowej linii
    root.clipboard_clear()
    root.clipboard_append(key)
    root.update()

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

key_entry_label = tk.Label(root, text="Wprowadź klucz do odszyfrowania:")
key_entry_label.pack()

key_entry = tk.Entry(root, width=40)
key_entry.pack()

decrypt_button = tk.Button(root, text="Odszyfruj", command=decrypt_file)
decrypt_button.pack()

progress = ttk.Progressbar(root, orient='horizontal', length=100, mode='determinate')
progress.pack()

algorithms_frame = tk.Frame(root)
algorithms_frame.pack()

selected_algorithm = None

algo_label = tk.Label(root, text="Wybierz rodzaj szyfrowania:")
algo_label.pack()

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
