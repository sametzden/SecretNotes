import tkinter
from tkinter import *
from tkinter import messagebox
import base64

# window
window = Tk()
window.title = "Secret Notes"
window.minsize(width=400, height=600)

FONT = ("Verdena", 10, "bold")


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_encrypt():
    title = title_entry.get()
    message = input_text.get(index1="1.0", index2=END)
    key = key_entry.get()

    if len(message) == 0 or len(key) == 0 or len(title) == 0:
        messagebox.showinfo('Error', "Enter all info.")
    else:
        # encryption
        message_encrypted = encode(key, message)
        try:
            with open("mysecret.txt", 'a') as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", 'w') as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            key_entry.delete(0, END)
            input_text.delete('1.0', END)


def decrypt():
    message_encrypted = input_text.get('1.0', END)
    key = key_entry.get()

    if len(message_encrypted) == 0 or len(key) == 0:
        messagebox.showinfo(title="Error", message="PLease enter all info")
    else:
        try:
            decrypted_message = decode(key, message_encrypted)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error", message="please enter encrypted meseeage")


# label
label1 = Label(text="Enter your title", font=FONT)
label1.pack()
# entry
title_entry = Entry(width=30)
title_entry.pack()
# label
label2 = Label(text="Enter your secret", font=FONT)
label2.pack()
# listbox
input_text = tkinter.Text(width=40, height=20)
input_text.pack()
# label
label3 = Label(text="Enter master key", font=FONT)
label3.pack()
# entry
key_entry = Entry(width=30)
key_entry.pack()
# buttons
save_encrypt = Button(text="Save & Encrypt", command=save_encrypt, font=FONT)
save_encrypt.pack()
decrypt = Button(text="Decrypt", command=decrypt, font=FONT)
decrypt.pack()

window.mainloop()
