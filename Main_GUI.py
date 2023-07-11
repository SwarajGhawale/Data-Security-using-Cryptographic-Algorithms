from tkinter import messagebox
from DES_Tables import *
from DES_Helper import *
from RC4_Helper import *
import AES
import RSA
import codecs
import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
import ast

# GUI
root = tk.Tk()
root.geometry("800x500")
root.title("Encryption/Decryption Algorithms")

tab = ttk.Notebook(root)
# separate the tabs
tab.pack(pady=10)


tab_des = Frame(tab, width=1200, height=800)
tab_aes = Frame(tab, width=1200, height=800)
tab_rc4 = Frame(tab, width=1200, height=800)
tab_rsa = Frame(tab, width=1200, height=800)

tab_des.pack(expand=1, fill='both')
tab_aes.pack(expand=1, fill='both')
tab_rc4.pack(expand=1, fill='both')
tab_rsa.pack(expand=1, fill='both')

tab.add(tab_des, text='DES')
tab.add(tab_aes, text='AES')
tab.add(tab_rc4, text='RC4')
tab.add(tab_rsa, text='RSA')


# ----------------------------------------- DES -----------------------------------------
# DES var
pt_var = tk.StringVar()
key_var = tk.StringVar()
pt = tk.StringVar()
key = tk.StringVar()
cipher_text = tk.StringVar()


def encrypt():

    # get the values from the entry boxes
    pt = plaintext_entry.get()
    key = key_entry.get()
    # radio button values
    Plain_rb = pt_var.get()
    hex_rb = key_var.get()

    if Plain_rb == "" or hex_rb == "":
        messagebox.showerror("Error", "You have to choose the type !!")

    if Plain_rb == "plain":
        ptb = str2bin(pt)
    elif Plain_rb == "hex":
        # if key can be converted to hex:
        if is_not_hex(pt):
            messagebox.showerror("Error", "You chose plaintext as HEX !!")
        ptb = hex2bin(pt)

    if hex_rb == "plain":
        keyb = str2bin(key)
    elif hex_rb == "hex":
        # if key can be converted to hex:
        if is_not_hex(key):
            messagebox.showerror("Error", "You chose key as HEX !!")
        keyb = hex2bin(key)

    if len(keyb) < 64:
        messagebox.showerror(
            "Error", "Key must be more than 64 bits (first 64 bits will be used only)")

    pt_chunks = [ptb[i:i+64] for i in range(0, len(ptb), 64)]
    if len(pt_chunks[-1]) % 64 != 0:
        pt_chunks[-1] = pt_chunks[-1].ljust(64, '0')

    cipher_text = ''
    for i in range(len(pt_chunks)):
        cipher_text += DES(pt_chunks[i], keyb,
                           result="HEX", TYPE="ENC", Report=True)

    result_output.delete(1.0, END)
    result_output.insert(INSERT, bin2hex(cipher_text))


def decrypt():

    # get the values from the entry boxes
    cipher_text = cipher_entry.get()
    key = key_entry.get()
    # radio button values
    hex_rb = key_var.get()

    if cipher_text == "":
        messagebox.showerror("Error", "You have to enter the cipher text !!")

    if hex_rb == "":
        messagebox.showerror("Error", "You have to choose key type !!")

    if hex_rb == "plain":
        keyb = str2bin(key)
    elif hex_rb == "hex":
        # if key can be converted to hex:
        if is_not_hex(key):
            messagebox.showerror(
                "Error", "You chose key as HEX !! so enter a HEX")
        keyb = hex2bin(key)

    cipher_text = hex2bin(cipher_text)

    cipher_text_chunks = [cipher_text[i:i+64]
                          for i in range(0, len(cipher_text), 64)]
    text = ''
    for i in range(len(cipher_text_chunks)):
        text += DES(cipher_text_chunks[i], keyb,
                    result="HEX", TYPE="DEC", Report=True)

    result_output.delete(1.0, END)
    if hex_rb == "plain":
        result_output.insert(INSERT, bin2str(text))
    else:
        result_output.insert(INSERT, bin2hex(text))


# Input for plaintext
plaintext_label = tk.Label(tab_des, text="Plaintext:")
plaintext_label.grid(row=0, column=0, pady=30)
plaintext_entry = tk.Entry(tab_des, width=70, textvariable=pt, xscrollcommand=True)
plaintext_entry.insert(0, "Hello world")

plaintext_entry.grid(row=0, column=1, pady=30, padx=20, ipady=10)

# Radio buttons for plaintext
Plain_rb = tk.Radiobutton(tab_des, text="Plaintext",
                          variable=pt_var, value="plain")
hex_rb = tk.Radiobutton(tab_des, text="Hex", variable=pt_var, value="hex")
Plain_rb.grid(row=0, column=2, padx=5)
hex_rb.grid(row=0, column=3)

# Input for ciphertext
cipher_label = tk.Label(tab_des, text="Cipher text:")
cipher_entry = tk.Entry(
    tab_des, width=70, textvariable=cipher_text, xscrollcommand=True)
cipher_label.grid(row=1, column=0)
cipher_entry.grid(row=1, column=1)

# Input for key
key_label = tk.Label(tab_des, text="Key:")
key_entry = tk.Entry(tab_des, width=70, textvariable=key, xscrollcommand=True)
key_entry.insert(0, "KingAzez")

key_label.grid(row=2, column=0)
key_entry.grid(row=2, column=1, pady=10, padx=20)
# Radio buttons for key
Plain_rb2 = tk.Radiobutton(tab_des, text="Plaintext",
                           variable=key_var, value="plain")
hex_rb2 = tk.Radiobutton(tab_des, text="Hex", variable=key_var, value="hex")
Plain_rb2.grid(row=2, column=2)
hex_rb2.grid(row=2, column=3)

# Output for ciphertext
result_label = tk.Label(tab_des, text="Result:")
result_output = tk.Text(tab_des, height=1, width=40,
                        font="Arial 10", bg="#FFEFE7", xscrollcommand=True)
result_label.grid(row=4, column=0)
result_output.grid(row=4, column=1, padx=20, ipady=20)

# Encrypt button
encrypt_button = tk.Button(tab_des, text="Encrypt", command=encrypt, padx=20)
encrypt_button.grid(row=5, column=1, pady=20)


# Decrypt button
decrypt_button = tk.Button(tab_des, text="Decrypt", command=decrypt, padx=20)
decrypt_button.grid(row=5, column=0, padx=20)


# ----------------------------------------- AES -----------------------------------------
# AES - DES var
aes_plain_var = tk.StringVar()
aes_cipher_var = tk.StringVar()
aes_key_var = tk.StringVar()
aes_iv_var = tk.StringVar()
aes_result_var = tk.StringVar()


def aes_encrypt():
    key = aes_key_entry.get()
    iv = aes_iv_entry.get()
    plaintext = aes_plaintext_entry.get()

    if not len(key) in [16, 24, 32]:
        messagebox.showerror(
            "Error", "Key size is wrong: make it 16, 24, or 32 characters")
    if len(iv) != 16:
        messagebox.showerror(
            "Error", "IV size is wrong: make it 16 characters")
    if plaintext == "":
        messagebox.showerror("Error", "You have to enter the plaintext !!")

    ciphertext = AES.encrypt(plaintext, key, iv)

    aes_result_output.delete(1.0, tk.END)
    aes_result_output.insert(INSERT, ciphertext)


def aes_decrypt():
    key = aes_key_entry.get()
    iv = aes_iv_entry.get()
    ciphertext = aes_ciphertext_entry.get()

    if not len(key) in [16, 24, 32]:
        messagebox.showerror(
            "Error", "Key size is wrong: make it 16, 24, or 32 characters")
    if len(iv) != 16:
        messagebox.showerror(
            "Error", "IV size is wrong: make it 16 characters")
    if ciphertext == "":
        messagebox.showerror("Error", "You have to enter the ciphertext !!")

    plaintext = AES.decrypt(ciphertext, key, iv)

    aes_result_output.delete(1.0, tk.END)
    aes_result_output.insert(INSERT, plaintext)


# Input for plaintext
aes_plaintext_label = tk.Label(tab_aes, text="Plaintext:")
aes_plaintext_entry = tk.Entry(
    tab_aes, width=80, textvariable=aes_plain_var, xscrollcommand=True)
aes_plaintext_entry.insert(0, "Hello world")
aes_plaintext_label.grid(row=0, column=0, pady=30)
aes_plaintext_entry.grid(row=0, column=1, pady=30, padx=80, ipady=10)

# Input for ciphertext
aes_ciphertext_label = tk.Label(tab_aes, text="Ciphertext:")
aes_ciphertext_entry = tk.Entry(
    tab_aes, width=80, textvariable=aes_cipher_var, xscrollcommand=True)
aes_ciphertext_label.grid(row=1, column=0, pady=30)
aes_ciphertext_entry.grid(row=1, column=1, pady=30, padx=80, ipady=10)

# Input for key
aes_key_label = tk.Label(tab_aes, text="Key:")
aes_key_entry = tk.Entry(
    tab_aes, width=70, textvariable=aes_key_var, xscrollcommand=True)
aes_key_entry.insert(0, "AhmedLookAtMeNow")
aes_key_label.grid(row=2, column=0)
aes_key_entry.grid(row=2, column=1, pady=10, padx=20)

# Input for IV
aes_iv_label = tk.Label(tab_aes, text="IV:")
aes_iv_entry = tk.Entry(
    tab_aes, width=70, textvariable=aes_iv_var, xscrollcommand=True)
aes_iv_entry.insert(0, "TurkiLookAtMeNow")
aes_iv_label.grid(row=3, column=0)
aes_iv_entry.grid(row=3, column=1, pady=10, padx=20)


# Output for ciphertext
aes_result_label = tk.Label(tab_aes, text="Result:")
aes_result_output = tk.Text(
    tab_aes, height=1, width=80, font="Arial 10", bg="#FFEFE7", xscrollcommand=True)
aes_result_label.grid(row=4, column=0)
aes_result_output.grid(row=4, column=1, padx=20, ipady=20)

# Encrypt button
aes_encrypt_button = tk.Button(
    tab_aes, text="Encrypt", command=aes_encrypt, padx=20)
aes_encrypt_button.grid(row=5, column=1, padx=20, pady=20)

# Decrypt button
aes_decrypt_button = tk.Button(
    tab_aes, text="Decrypt", command=aes_decrypt, padx=20)
aes_decrypt_button.grid(row=6, column=1, padx=20, pady=20)


# ----------------------------------------- RC4 -----------------------------------------

def submit():
    P = list(map(int, e1.get().split(" ")))
    key = list(map(int, e2.get().split(" ")))
    size = int(e3.get())

    result, report = RC4(P, key, size)
    txt.delete("1.0", tk.END)
    txt.insert(tk.END, report)
    txt_result.delete("1.0", tk.END)
    txt_result.insert(tk.END, str(result))


l1 = tk.Label(tab_rc4, text="Enter plaintext (P): ")
l1.pack()
e1 = tk.Entry(tab_rc4)
e1.insert(0, "1 2 2 2")
e1.pack()

l2 = tk.Label(tab_rc4, text="Enter key (K): ")
l2.pack()
e2 = tk.Entry(tab_rc4)
e2.insert(0, "1 2 3 6")
e2.pack()

l5 = tk.Label(tab_rc4, text="Enter key size ")
l5.pack()
e3 = tk.Entry(tab_rc4)
e3.insert(0, "8")
e3.pack()

btn = tk.Button(tab_rc4, text="Submit", command=submit)
btn.pack()

l3 = tk.Label(tab_rc4, text="Result: ")
l3.pack()
txt_result = tk.Text(tab_rc4, height=3, width=50)
txt_result.pack()

l4 = tk.Label(tab_rc4, text="Report: ")
l4.pack()
txt = tk.Text(tab_rc4, height=20, width=50)
txt.pack()


# ----------------------------------------- RSA -----------------------------------------
# RSA var
rsa_plain_var = tk.StringVar()
rsa_cipher_var = tk.StringVar()

rsa_p_var = tk.StringVar()
rsa_q_var = tk.StringVar()

rsa_Pu_var = tk.StringVar()
rsa_Pr_var = tk.StringVar()

rsa_result_var = tk.StringVar()


def rsa_encrypt():
    privateKey = ast.literal_eval(rsa_Pr_var.get())  # put private key in tuple
    publicKey = ast.literal_eval(rsa_Pu_var.get())  # put public key in tuple
    # Identical public Key and private Key, not allowed in RSA because it is asymmetric algorithm
    if publicKey == privateKey:
        messagebox.showerror(
            "Error", "Public key and Private key mustn't be identical")
        return
    rsa_result_var.set(RSA.encrypt(publicKey, rsa_plain_var.get()))


def rsa_decrypt():
    # Exciption handler for invalide inputs
    try:
        cipherText = list(map(int, rsa_cipher_var.get().split()))
    except:
        messagebox.showerror(
            "Error", "Cipher Text: Invalid input, must integers \n\n Such: 12 21 42 323 124 1234 ...")
        return

    privateKey = ast.literal_eval(rsa_Pr_var.get())  # put private key in tuple
    publicKey = ast.literal_eval(rsa_Pu_var.get())  # put public key in tuple

    # Identical public Key and private Key, not allowed in RSA because it is asymmetric algorithm
    if publicKey == privateKey:
        messagebox.showerror(
            "Error", "Public key and Private key mustn't be identical")
        return
    rsa_result_var.set(RSA.decrypt(privateKey, cipherText))


def rsa_generate_keys():
    rsa_p = rsa_p_var.get()
    rsa_q = rsa_q_var.get()

    # Cechk for invalid inputs
    if rsa_p.isdigit():
        rsa_p = int(rsa_p)
    else:
        messagebox.showerror("Error", "P Must be Integr, not letters")
        return
    if rsa_q.isdigit():
        rsa_q = int(rsa_q)
    else:
        messagebox.showerror("Error", "Q Must be Integr, not letters")
        return
    if rsa_p <= 10:
        messagebox.showerror(
            "Error", "P must be greater than 10, to avoid mathematical errors")
        return
    if rsa_q <= 10:
        messagebox.showerror(
            "Error", "Q must be greater than 10, to avoid mathematical errors")
        return
    if not (RSA.isPrime(rsa_p) and RSA.isPrime(rsa_q)):
        messagebox.showerror(
            "Error", "Both P and Q must be prime. \n\n Prime numbers such (17, 19, 23, etc)")
        return
    elif rsa_p == rsa_q:
        messagebox.showerror("Error", "P and Q cannot be identical")
        return
    # End of Check

    public, private = RSA.generate_keypair(rsa_p, rsa_q)
    rsa_Pu_var.set(str.format("(%d, %d)" % (public[0], public[1])))
    rsa_Pr_var.set(str.format("(%d, %d)" % (private[0], private[1])))


# Input for plaintext
rsa_plaintext_label = tk.Label(tab_rsa, text="Plaintext:")
rsa_plaintext_entry = tk.Entry(
    tab_rsa, width=80, textvariable=rsa_plain_var, xscrollcommand=True)
rsa_plaintext_entry.insert(0, "Hello world")

# Placing on the RSA tap
rsa_plaintext_label.grid(row=0, column=0, pady=10)
rsa_plaintext_entry.grid(row=0, column=1, pady=10, padx=80, ipady=10)

# Input for ciphertext
rsa_ciphertext_label = tk.Label(tab_rsa, text="Ciphertext:")
rsa_ciphertext_entry = tk.Entry(
    tab_rsa, width=80, textvariable=rsa_cipher_var, xscrollcommand=True)
# Placing on the RSA tap
rsa_ciphertext_label.grid(row=1, column=0, pady=10)
rsa_ciphertext_entry.grid(row=1, column=1, pady=10, padx=80, ipady=10)

# Input for p & q
rsa_p_label = tk.Label(tab_rsa, text="Enter P: ")
rsa_p_entry = tk.Entry(
    tab_rsa, width=50, textvariable=rsa_p_var, xscrollcommand=True)
rsa_p_entry.insert(0, "37")

rsa_q_label = tk.Label(tab_rsa, text="Enter Q: ")
rsa_q_entry = tk.Entry(
    tab_rsa, width=50, textvariable=rsa_q_var, xscrollcommand=True)
rsa_q_entry.insert(0, "17")

# Placing on the RSA tap
rsa_p_label.grid(row=2, column=0, pady=1)
rsa_p_entry.grid(row=2, column=1, pady=1, padx=20, ipady=0)
rsa_q_label .grid(row=3, column=0, pady=1)
rsa_q_entry.grid(row=3, column=1, pady=1, padx=20, ipady=0)

# Generate button
rsa_genrate_button = tk.Button(
    tab_rsa, text="Generate Public Key & Private Key", command=rsa_generate_keys, padx=20)
rsa_genrate_button.grid(row=4, column=1, padx=0, pady=0)

# Result of Public keys
rsa_pu_label = tk.Label(tab_rsa, text="Public Key (e, n):")
rsa_pu_entry = tk.Entry(
    tab_rsa, width=50, textvariable=rsa_Pu_var, xscrollcommand=True)
# Placing on the RSA tap
rsa_pu_label.grid(row=5, column=0, pady=1, padx=20, ipady=0)
rsa_pu_entry.grid(row=5, column=1, pady=1, padx=20, ipady=0)

# Result of Private keys
rsa_pr_label = tk.Label(tab_rsa, text="Private Key (d, n):")
rsa_pr_entry = tk.Entry(
    tab_rsa, width=50, textvariable=rsa_Pr_var, xscrollcommand=True)
# Placing on the RSA tap
rsa_pr_label.grid(row=6, column=0, pady=1, padx=20, ipady=0)
rsa_pr_entry.grid(row=6, column=1, pady=1, padx=20, ipady=0)

# Result
rsa_result_label = tk.Label(tab_rsa, text="Result: ")
rsa_result_entry = tk.Entry(
    tab_rsa, width=70, textvariable=rsa_result_var, xscrollcommand=True)
# Placing on the RSA tap
rsa_result_label.grid(row=7, column=0)
rsa_result_entry.grid(row=7, column=1, pady=10, padx=50, ipady=30)

# Encrypt button
rsa_encrypt_button = tk.Button(
    tab_rsa, text="Encrypt", command=rsa_encrypt, padx=20)
rsa_encrypt_button.grid(row=8, column=0, padx=20, pady=5)

# Decrypt button
rsa_decrypt_button = tk.Button(
    tab_rsa, text="Decrypt", command=rsa_decrypt, padx=20)
rsa_decrypt_button.grid(row=8, column=1, padx=20, pady=5)

root.mainloop()
