import tkinter as tk
import os
import binascii
import pyperclip
from tkinter import font as tkfont
from tkinter import filedialog
from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify


def StoreKeys():
    if len(PlaTxt1.get()) != 0:
        username = os.getlogin()
        private_key = RSA.generate(1024)
        public_key = private_key.publickey()
        private_pem = private_key.export_key().decode()
        public_pem = public_key.export_key().decode()
        with open(f'private_key.pem', 'w') as pr:
            pr.write(private_pem)
        with open(f'public_key.pem', 'w') as pu:
            pu.write(public_pem)
        pesan = "Your Public key and Private key are Generated In " + \
            f'C:\\Users\\{username}\\Desktop\\'
        messagebox.showinfo("File", pesan)

    else:
        messagebox.showinfo('Action', 'There is no plain text')


def ReadPrvKeys():
    val = True
    messagebox.showinfo("Clue", "Please Choose Private Key")
    while val:
        PrvPath = filedialog.askopenfilename()
        filename = os.path.basename(PrvPath)
        if filename == "private_key.pem":
            val = False
        if filename != "private_key.pem" and filename != "":
            messagebox.showinfo(
                "Warning", "Wrong file! Please input the private key!")
        if filename == "":
            break
    pr_key = RSA.import_key(open(PrvPath, 'r').read())
    return pr_key


def ReadPubKeys():
    val = True
    messagebox.showinfo("Clue", "Please Choose Public Key")
    while val:
        PubPath = filedialog.askopenfilename()
        filename = os.path.basename(PubPath)
        if filename == "public_key.pem":
            val = False
        if filename != "public_key.pem" and filename != "":
            messagebox.showinfo(
                "Warning", "Wrong file! Please input the public key!")
        if filename == "":
            break
    pu_key = RSA.import_key(open(PubPath, 'r').read())
    return pu_key


def Encryption():
    if len(PlaTxt1.get()) != 0:
        text = PlaTxt1.get()
        message = text.encode()
        pubkey = ReadPubKeys()
        cipher = PKCS1_OAEP.new(key=pubkey)
        cipher_text = cipher.encrypt(message)
        ciphertext = binascii.hexlify(cipher_text)
        CphTxt1.config(state='normal')
        CphTxt1.delete(0, END)
        CphTxt1.insert(0, ciphertext)
        CphTxt1.config(state='disabled')
    else:
        messagebox.showinfo("Warning", "There is no plain text")


def Decryption():
    try:
        if len(CphTxt2.get()) != 0:
            text = CphTxt2.get()
            unhexciph = text.encode()
            ciphertext = binascii.unhexlify(unhexciph)
            prvkey = ReadPrvKeys()
            decrypt = PKCS1_OAEP.new(key=prvkey)
            decrypted_message = decrypt.decrypt(ciphertext)
            PlaTxt2.config(state='normal')
            PlaTxt2.delete(0, END)
            PlaTxt2.insert(0, decrypted_message)
            PlaTxt2.config(state='disabled')
        else:
            messagebox.showinfo("Warning", "There is no ciphertext")

    except ValueError:
        messagebox.showinfo("Action", "Incorrect decryption key")


def CopytoClip():
    cipher = CphTxt1.get()
    if len(cipher) == 0:
        messagebox.showinfo('Action', 'Ciphertext kamu kosong')
    else:
        messagebox.showinfo("Action", "ciphertext has been copied")
        pyperclip.copy(cipher)


def paste():
    cipher = pyperclip.paste()
    CphTxt2.insert(0, cipher)


def clearAll():
    CphTxt1.config(state='normal')
    CphTxt1.delete(0, END)
    CphTxt1.config(state='disabled')
    CphTxt2.delete(0, END)
    PlaTxt1.delete(0, END)
    PlaTxt2.config(state='normal')
    PlaTxt2.delete(0, END)
    PlaTxt2.config(state='disabled')


class SimpleApp(tk.Tk):
    def __init__(self):
        global container
        tk.Tk.__init__(self)

        self.title_font = tkfont.Font(
            family='Helvetica', size=20, weight="bold", slant="italic")
        self.body_font = tkfont.Font(family='Helvetica', size=10)

        self.title("Asymmetric Encryption Decryption App")

        w = 480
        h = 350

        screenWidth = self.winfo_screenwidth()
        screenHeight = self.winfo_screenheight()

        xCoor = (screenWidth/2) - (w/2)
        yCoor = (screenHeight/2) - (h/2)

        self.geometry("%dx%d+%d+%d" % (w, h, xCoor, yCoor))

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, EncryptFrame, DecryptFrame, HelpPageEncry, HelpPageDecry, HelpPageRsa):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("StartPage")

    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()


class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        controller.resizable(False, False)

        menubar = tk.Menu(controller)
        filemenu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(
            label="Encrypt", command=lambda: controller.show_frame("EncryptFrame"))
        filemenu.add_command(
            label="Decrypt", command=lambda: controller.show_frame("DecryptFrame"))
        helpmenu = Menu(menubar, tearoff=0)
        helpmenu.add_command(
            label="What is RSA", command=lambda: controller.show_frame("HelpPageRsa"))
        helpmenu.add_command(
            label="Encryption Help", command=lambda: controller.show_frame("HelpPageEncry"))
        helpmenu.add_command(
            label="Decryption Help", command=lambda: controller.show_frame("HelpPageDecry"))
        menubar.add_cascade(label="Help", menu=helpmenu)
        controller.config(menu=menubar)

        label = tk.Label(
            self, text="RSA Encryption & Decryption Page ", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        button1 = tk.Button(self, text="Go to Encryption Page", command=lambda: controller.show_frame(
            "EncryptFrame"), height=5, width=20)
        button2 = tk.Button(self, text="Go to Decryption Page", command=lambda: controller.show_frame(
            "DecryptFrame"), height=5, width=20)
        button1.pack(side=LEFT, padx=22, pady=22)
        button2.pack(side=RIGHT, padx=22, pady=22)


class HelpPageEncry(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        title = tk.Label(self, text="Help Page RSA Encryption",
                         font=controller.title_font)
        title.pack(side="top", fill="x", pady=10)

        Frame1 = Frame(self)
        Frame1.pack(fill=X)
        step1 = Label(Frame1, text="1) Insert a string in the plain text textbox.\n2) click the generate key button to create a public and private key.\n3) You will get a notification that the public and private key is already generated \n and placed on your local computer desktop directory.\n4) After that you need to encrypt the plain text you’ve inputted before \n by clicking the encrypt button.\n5) It will ask you for the public key that already generated on your desktop, \n find public_key.pem in your desktop.\n6) After you click the public_key.pem, the plaintext now already been encrypted \n by outputting in the cipher text textbox.\n7) You can copy the cipher text by click the copy ciphertext button.\n8) You will get a notification that the cipher text already copied \nto the clipboard, and click ok", font=controller.body_font)
        step1.pack(anchor=E, fill="x")


class HelpPageDecry(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        title = tk.Label(self, text="Help Page RSA Decryption",
                         font=controller.title_font)
        title.pack(side="top", fill="x", pady=10)
        Frame1 = Frame(self)
        Frame1.pack(fill=X)
        step1 = Label(Frame1, text="1) Paste the cipher text by typing manually the cipher text \n or click the paste ciphertext button that \n you’ve copied the cipher text before at the clipboard", font=controller.body_font)
        step1.pack(anchor=E, fill="x", pady=10)
        Frame2 = Frame(self)
        Frame2.pack(fill=X)
        step2 = Label(Frame2, text="2) Click decrypt button to do the decryption process.",
                      font=controller.body_font)
        step2.pack(anchor=E, fill="x", pady=10)
        Frame3 = Frame(self)
        Frame3.pack(fill=X)
        step3 = Label(Frame3, text="3) It will open a directory window and search the private_key.pem  \n that already generated in your desktop directory.", font=controller.body_font)
        step3.pack(anchor=E, fill="x", pady=10)
        Frame4 = Frame(self)
        Frame4.pack(fill=X)
        step4 = Label(Frame4, text="4) After you select the private key, \n the text is decrypted and output in the plain text textbox.",
                      font=controller.body_font)
        step4.pack(anchor=E, fill="x", pady=10)


class HelpPageRsa(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        title = tk.Label(self, text="What is RSA?", font=controller.title_font)
        title.pack(side="top", fill="x", pady=10)
        Frame1 = Frame(self)
        Frame1.pack(fill=X)
        step1 = Label(Frame1, text="RSA stand for Rivest-Shamir-Adleman\n The RSA algorithm is the basis of a cryptosystem — a set of cryptographic \n algorithms used for specific security services or purposes — that allows \n for public key encryption and is commonly used to protect sensitive data,\n particularly when it is transmitted over an insecure network such as internet.\n \n RSA was first officially introduced in 1977 by Ron Rivest, Adi Shamir and \n Leonard Adleman of the Massachusetts Institute of Technology, while \n the invention by British mathematician Clifford Cocks of a Public Key Algorithm \n in 1973 remained secret by the GCHQ until 1997.\n \n Public key cryptography, also known as asymmetric cryptography, uses two \n different but mathematically connected keys — one private and one public. \n The public key could be exchanged with everyone, while the private key \n can be kept hidden \n \n (Rouse, 2018)", font=controller.body_font)
        step1.pack(anchor=E, fill="x", pady=10)


class EncryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        global PlaTxt1, CphTxt1
        label = tk.Label(self, text="RSA Encryption Page",
                         font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        PlaFrame = Frame(self)
        PlaFrame.pack(fill=X)
        PlaLbl = Label(PlaFrame, text="Plaintext", width=10)
        PlaLbl.pack(side=LEFT, padx=5, pady=5)
        PlaTxt1 = Entry(PlaFrame)
        PlaTxt1.pack(fill=X, padx=5, expand=True)

        PubKeyFrame = Frame(self)
        PubKeyFrame.pack(fill=X)
        KeyGenButt = tk.Button(PubKeyFrame, width=15,
                               text="Generate Key", command=StoreKeys)
        KeyGenButt.pack(fill=X, padx=5, pady=5)

        CphFrame = Frame(self)
        CphFrame.pack(fill=X)
        CphLbl = Label(CphFrame, text="Ciphertext", width=10)
        CphLbl.pack(side=LEFT, padx=5, pady=5)
        CphTxt1 = Entry(CphFrame, state='disabled')
        CphTxt1.pack(fill=X, padx=5, expand=True)

        UtilFrame = Frame(self)
        UtilFrame.pack(fill=BOTH, expand=True)
        Clear = Button(UtilFrame, text='Clear All',
                       width=30, command=clearAll, height=5)
        Clear.pack(side=LEFT, padx=5, pady=5)
        CopyButton = Button(UtilFrame, text='Copy Ciphertext',
                            width=30, command=CopytoClip, height=5)
        CopyButton.pack(side=RIGHT, padx=5, pady=5)

        ButtFrame = Frame(self)
        ButtFrame.pack(fill=BOTH, expand=True)
        SbmBtn = Button(ButtFrame, text='Encrypt', width=30,
                        bg='green', command=Encryption, height=5)
        SbmBtn.pack(side=RIGHT, padx=5, pady=5)
        DecyButton = tk.Button(ButtFrame, width=30, height=5, text="Go to the Decryption page",
                               command=lambda: controller.show_frame("DecryptFrame"), bg='red')
        DecyButton.pack(side=LEFT, padx=5, pady=5)


class DecryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        global PlaTxt2, CphTxt2
        label = tk.Label(self, text="RSA Decryption Page",
                         font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        CphFrame = Frame(self)
        CphFrame.pack(fill=X)
        CphLbl = Label(CphFrame, text="CipherText", width=10)
        CphLbl.pack(side=LEFT, padx=5, pady=5)
        CphTxt2 = Entry(CphFrame)
        CphTxt2.pack(fill=X, padx=5, expand=True)

        PlaFrame = Frame(self)
        PlaFrame.pack(fill=X)
        PlaLbl = Label(PlaFrame, text="PlainText", width=10)
        PlaLbl.pack(side=LEFT, padx=5, pady=5)
        PlaTxt2 = Entry(PlaFrame, state='disabled')
        PlaTxt2.pack(fill=X, padx=5, expand=True)

        UtilFrame = Frame(self)
        UtilFrame.pack(fill=BOTH, expand=True)
        Clear = Button(UtilFrame, text='Clear All',
                       width=30, command=clearAll, height=5)
        Clear.pack(side=LEFT, padx=5, pady=5)
        PastBtn = Button(UtilFrame, text='Paste Ciphertext',
                         width=30, command=paste, height=5)
        PastBtn.pack(side=RIGHT, padx=5, pady=5)

        ButtFrame = Frame(self)
        ButtFrame.pack(fill=BOTH, expand=True)
        SbmBtn = Button(ButtFrame, text='Decrypt', width=30,
                        bg='green', command=Decryption, height=5)
        SbmBtn.pack(side=RIGHT, padx=5, pady=5)
        EncyButton = tk.Button(ButtFrame, width=30, height=5, text="Go to the Encryption page",
                               command=lambda: controller.show_frame("EncryptFrame"), bg='red')
        EncyButton.pack(side=LEFT, padx=5, pady=5)


if __name__ == "__main__":
    app = SimpleApp()
    app.mainloop()
