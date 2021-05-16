import tkinter as tk
import base64
import os
import pyperclip
from tkinter import font  as tkfont
from tkinter import filedialog             
from tkinter import *
from tkinter import messagebox


def goSymmetricPage():
    os.system('python Symmetric.py')
    
def goAsymmetricPage():
    os.system('python Asymmetric.py')

def viewMember():
     window = Tk()
     labelExample = tk.Label(window, text = "GROUP 1 COMPUTER SECURITY\nNICHOLAS (01082170001)\nDAVE JOSHUA MARCELLINO RUMENGAN (01082170043)\nFARRELL NATHANIEL (01082170002)\nGRAND MARCELL (01082170027)\nKLEMENS WIYANTO (010812170018)\nSUTEDJA THE HO PING (01082170006)")
     labelExample.pack()
     window.title("Developer Member")
     w=400
     h=115
     screenWidth = window.winfo_screenwidth()
     screenHeight = window.winfo_screenheight()
     xCoor = (screenWidth/1.25) - (w/2)
     yCoor = (screenHeight/2) - (h/2)
     window.geometry("%dx%d+%d+%d" % (w,h,xCoor, yCoor))
     


class SimpleApp(tk.Tk):
    def __init__(self):
        global container
        tk.Tk.__init__(self)

        self.title_font = tkfont.Font(family='Helvetica', size=10, weight="bold", slant="italic")
        self.body_font = tkfont.Font(family='Helvetica', size=5)

        self.title("EncryptDecryptor Application")
        
        w=400
        h=170
        
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
        for F in (StartPage, NextPage):
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

        label = tk.Label(self, text="Symmetric and Asymmetric", font=controller.title_font)
        label.pack(side="top", fill="x")
        label = tk.Label(self, text="Encryption and Decryption", font=controller.title_font)
        label.pack(side="top", fill="x")
        label = tk.Label(self, text="Group 1 Computer Security", font=controller.title_font)
        label.pack(side="top", fill="x")

        button1 = tk.Button(self, text="Enter App",command=lambda: controller.show_frame("NextPage"), height=3, width=20)
        button1.pack(side="top", padx=5, pady=5)
        button2 = tk.Button(self, text="View Developer Member",command=viewMember,height=1, width=20)
        button2.pack(side="top", padx=5, pady=5)

class NextPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        controller.resizable(False, False)
        
        label = tk.Label(self, text="Group 1 Encrypt Decrypt App", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        
        UtilFrame = Frame(self)
        UtilFrame.pack(fill=BOTH, expand=True)
        Clear = Button(UtilFrame, text='Go to Symmetric Page', width=25, command=goSymmetricPage, height=2)
        Clear.pack(side=LEFT, padx=5, pady=5)
        CopyButton = Button(UtilFrame, text='Go to Asymmetric Page', width=25,height=2, command=goAsymmetricPage)
        CopyButton.pack(side=RIGHT, padx=5,pady=5)

        ButtFrame = Frame(self)
        ButtFrame.pack(fill=BOTH, expand=True)
        SbmBtn = Button(self, text="Back to Home Page",command=lambda: controller.show_frame("StartPage"), height=2, width=25)
        SbmBtn.pack(side=BOTTOM, padx=5, pady=15)

        
        
if __name__ == "__main__":
    app = SimpleApp()
    app.mainloop()
