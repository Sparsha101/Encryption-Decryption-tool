import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet
import os

# Create key file if it doesn't exist
def create_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as file:
            file.write(key)

# Load the key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt message
def encrypt():
    create_key()
    message = input_text.get("1.0", tk.END).strip()

    if not message:
        messagebox.showwarning("Warning", "Please enter a message to encrypt.")
        return

    key = load_key()
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted.decode())

# Decrypt message
def decrypt():
    encrypted = input_text.get("1.0", tk.END).strip()

    if not encrypted:
        messagebox.showwarning("Warning", "Please enter encrypted text.")
        return

    try:
        key = load_key()
        f = Fernet(key)
        decrypted = f.decrypt(encrypted.encode()).decode()

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)
    except Exception:
        messagebox.showerror("Error", "Decryption failed. Please check the input.")

# GUI Window
window = tk.Tk()
window.title("Message Encryptor / Decryptor")
window.geometry("500x500")

tk.Label(window, text="Enter your message:", font=("Arial", 12)).pack(pady=5)
input_text = scrolledtext.ScrolledText(window, width=60, height=6)
input_text.pack(padx=10)

tk.Button(window, text="Encrypt", command=encrypt, bg="green", fg="white", width=20).pack(pady=10)
tk.Button(window, text="Decrypt", command=decrypt, bg="blue", fg="white", width=20).pack()

tk.Label(window, text="Output:", font=("Arial", 12)).pack(pady=10)
output_text = scrolledtext.ScrolledText(window, width=60, height=6)
output_text.pack(padx=10)

window.mainloop()
