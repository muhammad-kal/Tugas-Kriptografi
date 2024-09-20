import tkinter
import tkinter.messagebox
import tkinter.filedialog
import customtkinter
import os
import numpy as np
import math
from numpy.linalg import inv

#Bagian Vignere Cipher 
def vigenere_encrypt(plain_text, key):
    key = key.upper()
    cipher_text = ""
    for i in range(len(plain_text)):
        if plain_text[i].isalpha():
            shift = (ord(plain_text[i].upper()) + ord(key[i % len(key)])) % 26
            cipher_char = chr(shift + 65)
            cipher_text += cipher_char
        else:
            cipher_text += plain_text[i]
    return cipher_text

def vigenere_decrypt(cipher_text, key):
    key = key.upper()
    plain_text = ""
    for i in range(len(cipher_text)):
        if cipher_text[i].isalpha():
            shift = (ord(cipher_text[i]) - ord(key[i % len(key)]) + 26) % 26
            plain_char = chr(shift + 65)
            plain_text += plain_char
        else:
            plain_text += cipher_text[i]
    return plain_text

# Function to implement Playfair Cipher
def playfair_encrypt(plain_text, key):
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    key = key.lower().replace(' ', '').replace('j', 'i')
    key_square = ''
    for letter in key + alphabet:
        if letter not in key_square:
            key_square += letter

    plain_text = plain_text.lower().replace(' ', '').replace('j', 'i')
    if len(plain_text) % 2 == 1:
        plain_text += 'x'

    digraphs = [plain_text[i:i+2] for i in range(0, len(plain_text), 2)]

    def encrypt(digraph):
        a, b = digraph
        row_a, col_a = divmod(key_square.index(a), 5)
        row_b, col_b = divmod(key_square.index(b), 5)
        if row_a == row_b:
            col_a = (col_a + 1) % 5
            col_b = (col_b + 1) % 5
        elif col_a == col_b:
            row_a = (row_a + 1) % 5
            row_b = (row_b + 1) % 5
        else:
            col_a, col_b = col_b, col_a
        return key_square[row_a*5+col_a] + key_square[row_b*5+col_b]

    result = ''.join([encrypt(digraph) for digraph in digraphs])
    return result

def playfair_decrypt(cipher_text, key):
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    key = key.lower().replace(' ', '').replace('j', 'i')
    key_square = ''
    for letter in key + alphabet:
        if letter not in key_square:
            key_square += letter

    digraphs = [cipher_text[i:i+2] for i in range(0, len(cipher_text), 2)]

    def decrypt(digraph):
        a, b = digraph
        row_a, col_a = divmod(key_square.index(a), 5)
        row_b, col_b = divmod(key_square.index(b), 5)
        if row_a == row_b:
            col_a = (col_a - 1) % 5
            col_b = (col_b - 1) % 5
        elif col_a == col_b:
            row_a = (row_a - 1) % 5
            row_b = (row_b - 1) % 5
        else:
            col_a, col_b = col_b, col_a
        return key_square[row_a*5+col_a] + key_square[row_b*5+col_b]

    result = ''.join([decrypt(digraph) for digraph in digraphs])
    return result


#buat modulo invers buat Hill Ciphernya 
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def hill_cipher_key_matrix(key, block_size):
    key_matrix = []
    for char in key:
        key_matrix.append(ord(char.upper()) % 65)
    key_matrix = np.array(key_matrix).reshape(block_size, block_size)

    #Panjang Key harus 16 untuk menyesuaikan ukuran matriks 4x4
    return key_matrix

def hill_encrypt_block(block, key_matrix, block_size):
    block_vector = [ord(char.upper()) % 65 for char in block]
    block_vector = np.dot(key_matrix, block_vector) % 26
    return ''.join(chr(int(num) + 65) for num in block_vector)

def hill_decrypt_block(block, key_matrix, block_size):
    det = int(np.round(np.linalg.det(key_matrix)))  # Determinant
    det_inv = mod_inverse(det, 26)  # Inverse mod 26
    if det_inv is None:
        raise ValueError("Matriks tidak di invert.")
    
    key_matrix_inv = inv(key_matrix) * det * det_inv % 26  # Inverse matrix mod 26
    key_matrix_inv = np.round(key_matrix_inv).astype(int) % 26
    
    block_vector = [ord(char.upper()) % 65 for char in block]
    block_vector = np.dot(key_matrix_inv, block_vector) % 26
    return ''.join(chr(int(num) + 65) for num in block_vector)

#enkripsi hill
def hill_encrypt(plain_text, key):
    plain_text = plain_text.replace(" ", "").upper()
    block_size = int(math.sqrt(len(key)))
    if block_size**2 != len(key):
        return "Panjang Key harus 16 untuk menyesuaikan ukuran matriks 4x4"
    
    # Padding dikit
    while len(plain_text) % block_size != 0:
        plain_text += "X"
    
    key_matrix = hill_cipher_key_matrix(key, block_size)
    cipher_text = ""
    
    for i in range(0, len(plain_text), block_size):
        block = plain_text[i:i+block_size]
        cipher_text += hill_encrypt_block(block, key_matrix, block_size)
    
    return cipher_text

# Hill Cipher Dekripsi
def hill_decrypt(cipher_text, key):
    cipher_text = cipher_text.replace(" ", "").upper()
    block_size = int(math.sqrt(len(key)))
    if block_size**2 != len(key):
        return "Key length must be a perfect square!"
    
    key_matrix = hill_cipher_key_matrix(key, block_size)
    plain_text = ""
    
    for i in range(0, len(cipher_text), block_size):
        block = cipher_text[i:i+block_size]
        plain_text += hill_decrypt_block(block, key_matrix, block_size)
    
    return plain_text

# main
class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # ukuran window
        self.title("Tugas Kriptografi Muhammad Haikal_4611422130")
        self.geometry(f"{1100}x{580}")

        #col-3
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        #bagian kiri
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Kriptografi GUI", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # pilihan mode
        self.cipher_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Vigenere", "Playfair", "Hill"])
        self.cipher_optionemenu.grid(row=1, column=0, padx=20, pady=10)

        #Tombol eknrip sama dekripsi
        self.encrypt_button = customtkinter.CTkButton(self.sidebar_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=2, column=0, padx=20, pady=10)

        self.decrypt_button = customtkinter.CTkButton(self.sidebar_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=3, column=0, padx=20, pady=10)

        # Input/Output teks box
        self.input_textbox = customtkinter.CTkTextbox(self, width=450, height=200)
        self.input_textbox.grid(row=0, column=1, padx=(20, 0), pady=(20, 10), sticky="nsew")
        self.input_textbox.insert("1.0", "Tulis/Upload Plainteks disini!")  # Placeholder
        self.input_textbox.bind("<FocusIn>", self.clear_placeholder)  
        self.input_textbox.bind("<FocusOut>", self.add_placeholder)   

        self.output_textbox = customtkinter.CTkTextbox(self, width=450, height=200)
        self.output_textbox.grid(row=1, column=1, padx=(20, 0), pady=(20, 10), sticky="nsew")
        self.output_textbox.insert("1.0", "Hasil Encode/Dekode")  # Placeholder
        self.output_textbox.bind("<FocusIn>", self.clear_placeholder_output)
        self.output_textbox.bind("<FocusOut>", self.add_placeholder_output)

        # 12 kunci menjadi sukses
        self.key_entry = customtkinter.CTkEntry(self, placeholder_text="Enter Key (Min 12 characters)")
        self.key_entry.grid(row=2, column=1, padx=(20, 0), pady=(10, 20), sticky="nsew")

        # File upload 
        self.upload_button = customtkinter.CTkButton(self, text="Upload File", command=self.upload_file)
        self.upload_button.grid(row=3, column=1, padx=(20, 0), pady=(10, 20), sticky="nsew")

    def clear_placeholder(self, event):
        if self.input_textbox.get("1.0", "end-1c") == "Tulis/Upload Plainteks disini!":
            self.input_textbox.delete("1.0", "end")

    def add_placeholder(self, event):
        if not self.input_textbox.get("1.0", "end-1c").strip():
            self.input_textbox.insert("1.0", "Tulis/Upload Plainteks disini!")

    def clear_placeholder_output(self, event):
        if self.output_textbox.get("1.0", "end-1c") == "Hasil Encode/Dekode":
            self.output_textbox.delete("1.0", "end")

    def add_placeholder_output(self, event):
        if not self.output_textbox.get("1.0", "end-1c").strip():
            self.output_textbox.insert("1.0", "Hasil Encode/Dekode")

    def encrypt(self):
        plain_text = self.input_textbox.get("1.0", "end-1c")
        key = self.key_entry.get()
        if len(key) < 12:
            tkinter.messagebox.showerror("Error", "Key must be at least 12 characters!")
            return
        cipher_type = self.cipher_optionemenu.get()
        if cipher_type == "Vigenere":
            cipher_text = vigenere_encrypt(plain_text, key)
        elif cipher_type == "Playfair":
            cipher_text = playfair_encrypt(plain_text, key)
        elif cipher_type == "Hill":
            cipher_text = hill_encrypt(plain_text, key)
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("1.0", cipher_text)

    def decrypt(self):
        cipher_text = self.input_textbox.get("1.0", "end-1c")
        key = self.key_entry.get()
        if len(key) < 12:
            tkinter.messagebox.showerror("Error", "Key must be at least 12 characters!")
            return
        cipher_type = self.cipher_optionemenu.get()
        if cipher_type == "Vigenere":
            plain_text = vigenere_decrypt(cipher_text, key)
        elif cipher_type == "Playfair":
            plain_text = playfair_decrypt(cipher_text, key)
        elif cipher_type == "Hill":
            plain_text = hill_decrypt(cipher_text, key)
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("1.0", plain_text)

    def upload_file(self):
        filename = tkinter.filedialog.askopenfilename(title="Select File", filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, "r") as file:
                data = file.read()
                self.input_textbox.delete("1.0", "end")
                self.input_textbox.insert("1.0", data)

if __name__ == "__main__":
    app = App()
    app.mainloop()
