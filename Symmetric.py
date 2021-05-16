import tkinter as tk
import base64
import os
import pyperclip
from tkinter import font  as tkfont
from tkinter import filedialog             
from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Function to validate the password 
def password_check(passwd):
    val = True
    if len(passwd) == 0:
        messagebox.showinfo("Warning", 'Please input a key!')
        val = False
        
    if len(passwd) < 6 : 
        messagebox.showinfo("Warning", 'Password length should be at least 6')
        val = False
    
    if not any(char.isdigit() for char in passwd):
        messagebox.showinfo("Warning", 'Password should at least have one NUMBER')
        val = False
    
    if not any(char.isupper() for char in passwd): 
        messagebox.showinfo("Warning", 'Password should have at least one uppercase letter')
        val = False

    if not any(char.islower() for char in passwd): 
        messagebox.showinfo("Warning", 'Password should have at least one lowercase letter')
        val = False

    return val

def Encryption():
    # Generate Key From Password
    password_provided = PassTxtEnc.get()
    if password_check(password_provided) and len(PlaTxt1.get()) != 0:
        key = GenerateKey(password_provided)
        # Encryption Part
        text = PlaTxt1.get()
        message = text.encode()
        f = Fernet(key)
        ciphertext = f.encrypt(message)
        CphTxt1.config(state='normal')
        CphTxt1.delete(0, END)
        CphTxt1.insert(0, ciphertext)
        CphTxt1.config(state='disabled')
    elif len(PlaTxt1.get()) == 0 : #error handling for no plain text inputted
        messagebox.showinfo("Warning", "There is no plain text")

def Decryption():
    password = PassTxtDec.get()
    if password_check(password)and len(PlaTxt1.get()) != 0:
        key = GenerateKey(password)
        text = CphTxt2.get()
        btext = text.encode()
        f = Fernet(key)
        plaintext = f.decrypt(btext)
        PlaTxt2.config(state='normal')
        PlaTxt2.delete(0, END)
        PlaTxt2.insert(0, plaintext)
        PlaTxt2.config(state='disabled')
    elif len(CphTxt2.get()) == 0 : #error handling for no plain text inputted
        messagebox.showinfo("Warning", "There is no plain text")

def GenerateKey(passwd):
    password = passwd.encode() # Convert to type bytes
    salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
    return key

def CopytoClip():
    cipher = CphTxt1.get()
    if len(cipher) == 0:
        messagebox.showinfo('Action', 'There is no ciphertext generated')
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
    PassTxtDec.delete(0, END)
    PassTxtEnc.delete(0, END)



class SimpleApp(tk.Tk):
    def __init__(self):
        global container
        tk.Tk.__init__(self)

        self.title_font = tkfont.Font(family='Helvetica', size=20, weight="bold", slant="italic")
        self.body_font = tkfont.Font(family='Helvetica', size=10)

        self.title("Symetric Encrpytion Decryption App")

        w=480
        h=350
        
        screenWidth = self.winfo_screenwidth()
        screenHeight = self.winfo_screenheight()

        xCoor = (screenWidth/2) - (w/2)
        yCoor = (screenHeight/2) - (h/2)

        self.geometry("%dx%d+%d+%d" % (w,h,xCoor, yCoor))
        

        container = tk.Frame(self)
        container.pack(side="top", fill="both",expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, EncryptFrame, DecryptFrame, HelpPageDecry, HelpPageEncry, HelpPageAes):
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

        menubar = Menu(controller)
        filemenu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="Home", command=lambda: controller.show_frame("StartPage"))
        filemenu.add_command(label="Encrypt", command=lambda: controller.show_frame("EncryptFrame"))
        filemenu.add_command(label="Decrypt", command=lambda: controller.show_frame("DecryptFrame"))
        
        helpmenu = Menu(menubar, tearoff=0)
        helpmenu.add_command(label="What is AES", command=lambda: controller.show_frame("HelpPageAes"))
        helpmenu.add_command(label="Encryption Help", command=lambda: controller.show_frame("HelpPageEncry"))
        helpmenu.add_command(label="Decryption Help", command=lambda: controller.show_frame("HelpPageDecry"))
        menubar.add_cascade(label="Help", menu=helpmenu)
        controller.config(menu=menubar)

        label = tk.Label(self, text="AES Encryption & Decryption Page", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        button1 = tk.Button(self, text="Go to Encryption Page",command=lambda: controller.show_frame("EncryptFrame"), height=5, width=20)
        button2 = tk.Button(self, text="Go to Decryption Page",command=lambda: controller.show_frame("DecryptFrame"), height=5, width=20)
        button1.pack(side=LEFT, padx=22, pady=22)
        button2.pack(side=RIGHT, padx=22, pady=22)

class HelpPageEncry(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        title = tk.Label(self, text="Help Page AES Encryption", font=controller.title_font)
        title.pack(side="top", fill="x", pady=10)
        
        Frame1 = Frame(self)
        Frame1.pack(fill=X) 
        step1 = Label(Frame1, text="1) Insert a string in the plain text textbox.", font=controller.body_font)
        step1.pack(anchor=E, fill="x", pady=10)
        Frame2 = Frame(self)
        Frame2.pack(fill=X) 
        step2 = Label(Frame2, text="2) Insert a key that have requirement that minimum 6 characters, \n  minimum 1 uppercase character, minimum 1 lowercase character, \n and minimum 1 numeric character.", font=controller.body_font)
        step2.pack(anchor=E, fill="x", pady=10)
        Frame3 = Frame(self)
        Frame3.pack(fill=X) 
        step3 = Label(Frame3, text="3) Click encrypt button to do encrypting process.", font=controller.body_font)
        step3.pack(anchor=E, fill="x", pady=10)
        Frame4 = Frame(self)
        Frame4.pack(fill=X) 
        step4 = Label(Frame4, text="4) Cipher text is generated and the output in the cipher text textbox.", font=controller.body_font)
        step4.pack(anchor=E, fill="x", pady=10)
        Frame5 = Frame(self)
        Frame5.pack(fill=X) 
        step5 = Label(Frame5, text="5) copy the cipher text by click the copy ciphertext button.", font=controller.body_font)
        step5.pack(anchor=E, fill="x", pady=10)
        Frame6 = Frame(self)
        Frame6.pack(fill=X) 
        step6 = Label(Frame6, text="6) You will get a notification that the cipher text already copied to the clipboard, \n and click ok", font=controller.body_font)
        step6.pack(anchor=E, fill="x", pady=10)

class HelpPageDecry(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        title = tk.Label(self, text="Help Page AES Decryption", font=controller.title_font)
        title.pack(side="top", fill="x", pady=10)
        Frame1 = Frame(self)
        Frame1.pack(fill=X) 
        step1 = Label(Frame1, text="1) Paste the cipher text by typing manually the cipher text \n or click the paste ciphertext button that \n you’ve copied the cipher text before at the clipboard", font=controller.body_font)
        step1.pack(anchor=E, fill="x", pady=10)
        Frame2 = Frame(self)
        Frame2.pack(fill=X) 
        step2 = Label(Frame2, text="2) Insert the key that you’ve before create for the cipher text", font=controller.body_font)
        step2.pack(anchor=E, fill="x", pady=10)
        Frame3 = Frame(self)
        Frame3.pack(fill=X) 
        step3 = Label(Frame3, text="3) Click decrypt button to do the decryption process.", font=controller.body_font)
        step3.pack(anchor=E, fill="x", pady=10)
        Frame4 = Frame(self)
        Frame4.pack(fill=X) 
        step4 = Label(Frame4, text="4) Cipher text is decrypted and output in the plaintext textbox.", font=controller.body_font)
        step4.pack(anchor=E, fill="x", pady=10)
        
class HelpPageAes(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        title = tk.Label(self, text="What is AES?", font=controller.title_font)
        title.pack(side="top", fill="x", pady=10)
        Frame1 = Frame(self)
        Frame1.pack(fill=X) 
        step1 = Label(Frame1, text="AES stand for Advance Encryption Standard,\n AES is a symmetric block cipher, which functions on data blocks of fixed size. \n The goal of AES was not only to choose a new cipher algorithm but \n also to increase both block and key size significantly compared to DES. \n AES uses 128-bit blocks while DES used 64-bit blocks. Doubling the block size \n by a factor of 264 increases the number of available partitions, \n a significant improvement over DES\n\n(Johnson,2010)", font=controller.body_font)
        
        step1.pack(anchor=E, fill="x", pady=10)
        Frame2 = Frame(self)
        Frame2.pack(fill=X) 

class EncryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        global PlaTxt1, CphTxt1, PassTxtEnc
        label = tk.Label(self, text="AES Encryption Page", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        PlaFrame = Frame(self)
        PlaFrame.pack(fill=X)
        PlaLbl = Label(PlaFrame, text="Plaintext", width=10)
        PlaLbl.pack(side=LEFT, padx=5, pady=5)
        PlaTxt1 = Entry(PlaFrame)
        PlaTxt1.pack(fill=X, padx=5, expand=True)

        PassFrame = Frame(self)
        PassFrame.pack(fill=X)
        PassLbl = Label(PassFrame, text="Key", width=10)
        PassLbl.pack(side=LEFT, padx=5, pady=5)
        PassTxtEnc = Entry(PassFrame)
        PassTxtEnc.pack(fill=X, padx=5, expand=True)

        CphFrame = Frame(self)
        CphFrame.pack(fill=X)
        CphLbl = Label(CphFrame, text="Ciphertext", width=10)
        CphLbl.pack(side=LEFT, padx=5, pady=5)
        CphTxt1 = Entry(CphFrame, state="disabled")
        CphTxt1.pack(fill=X, padx=5, expand=True)
        
        UtilFrame = Frame(self)
        UtilFrame.pack(fill=BOTH, expand=True)
        Clear = Button(UtilFrame, text='Clear All', width=30, command=clearAll, height=5)
        Clear.pack(side=LEFT, padx=5, pady=5)
        CopyButton = Button(UtilFrame, text='Copy Ciphertext', width=30, command=CopytoClip, height=5)
        CopyButton.pack(side=RIGHT, padx=5,pady=5)

        ButtFrame = Frame(self)
        ButtFrame.pack(fill=BOTH, expand=True)
        SbmBtn = Button(ButtFrame, text='Encypt', width=30, command=Encryption, bg='green', height=5)
        SbmBtn.pack(side=RIGHT, padx=5, pady=5)
        DecyButton = Button(ButtFrame, width=30, text="Go to the Decryption page",command=lambda: controller.show_frame("DecryptFrame"), bg='red', height=5)
        DecyButton.pack(side=LEFT, padx=5,pady=5)

class DecryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        global PlaTxt2, CphTxt2, PassTxtDec
        label = tk.Label(self, text="AES Decryption Page", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        CphFrame = Frame(self)
        CphFrame.pack(fill=X)
        CphLbl = Label(CphFrame, text="CipherText", width=10)
        CphLbl.pack(side=LEFT, padx=5, pady=5)
        CphTxt2 = Entry(CphFrame)
        CphTxt2.pack(fill=X, padx=5, expand=True)

        PassFrame = Frame(self)
        PassFrame.pack(fill=X)
        PassLbl = Label(PassFrame, text="Key", width=10)
        PassLbl.pack(side=LEFT, padx=5, pady=5)
        PassTxtDec = Entry(PassFrame)
        PassTxtDec.pack(fill=X, padx=5, expand=True)

        PlaFrame = Frame(self)
        PlaFrame.pack(fill=X)
        PlaLbl = Label(PlaFrame, text="PlainText", width=10)
        PlaLbl.pack(side=LEFT, padx=5, pady=5)
        PlaTxt2 = Entry(PlaFrame, state='disabled')
        PlaTxt2.pack(fill=X, padx=5, expand=True)

        UtilFrame = Frame(self)
        UtilFrame.pack(fill=BOTH, expand=True)
        Clear = Button(UtilFrame, text='Clear All', width=30, command=clearAll, height=5)
        Clear.pack(side=LEFT, padx=5, pady=5)
        PastBtn = Button(UtilFrame, text='Paste Ciphertext', width=30, command=paste, height=5)
        PastBtn.pack(side=RIGHT, padx=5, pady=5)

        ButtFrame = Frame(self)
        ButtFrame.pack(fill=BOTH, expand=True)
        SbmBtn = Button(ButtFrame, text='Decrypt', width=30, command=Decryption, bg='green', height=5)
        SbmBtn.pack(side=RIGHT, padx=5, pady=5)
        EncyButton = tk.Button(ButtFrame, width=30, text="Go to the Encryption page",command=lambda: controller.show_frame("EncryptFrame"), bg='red', height=5)
        EncyButton.pack(side=LEFT, padx=5,pady=5)

class main():
    if __name__ == "__main__":
        app = SimpleApp()
        app.mainloop()

