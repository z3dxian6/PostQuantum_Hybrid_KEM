import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

alice_dir = r"C:\Users\zoran\Documents\Projet_Crypto\Alice"
bob_dir = r"C:\Users\zoran\Documents\Projet_Crypto\Bob"

def load_kdf_key():
    kdf_path = os.path.join(alice_dir, "K_final.bin")
    if not os.path.exists(kdf_path):
        messagebox.showerror("Erreur", "K_final.bin introuvable. Lancez d'abord l'échange de clés.")
        return None
    with open(kdf_path, "rb") as f:
        return f.read()

def send_message(entry, chatbox):
    key = load_kdf_key()
    if key is None:
        return
    aesgcm = AESGCM(key)
    message = entry.get().encode()
    if not message:
        return
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)
    with open(os.path.join(bob_dir, "message_aesgcm_from_alice.bin"), "wb") as f:
        f.write(nonce)
        f.write(ciphertext)
    chatbox.insert(tk.END, "Moi (Alice) : " + entry.get() + "\n")
    entry.delete(0, tk.END)

def receive_message(chatbox):
    key = load_kdf_key()
    if key is None:
        return
    msg_path = os.path.join(alice_dir, "message_aesgcm_from_bob.bin")
    if not os.path.exists(msg_path):
        messagebox.showinfo("Info", "Aucun message reçu de Bob.")
        return
    with open(msg_path, "rb") as f:
        nonce = f.read(12)
        ciphertext = f.read()
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        chatbox.insert(tk.END, "Bob : " + plaintext.decode() + "\n")
        os.remove(msg_path)
    except Exception as e:
        messagebox.showerror("Erreur de déchiffrement", str(e))

def main():
    root = tk.Tk()
    root.title("Alice - Chat sécurisé")

    chatbox = scrolledtext.ScrolledText(root, width=60, height=20, state='normal')
    chatbox.pack(padx=10, pady=10)

    entry = tk.Entry(root, width=50)
    entry.pack(side=tk.LEFT, padx=(10,0), pady=(0,10), expand=True, fill=tk.X)

    send_btn = tk.Button(root, text="Envoyer à Bob", command=lambda: send_message(entry, chatbox))
    send_btn.pack(side=tk.LEFT, padx=(5,0), pady=(0,10))

    recv_btn = tk.Button(root, text="Lire message de Bob", command=lambda: receive_message(chatbox))
    recv_btn.pack(side=tk.LEFT, padx=(5,10), pady=(0,10))

    root.mainloop()

if __name__ == "__main__":
    main()
