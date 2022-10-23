import numpy as np
import time
from tkinter import * 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import secp256k1 as ice
from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate

with open('puzzle.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)

# ============================================================================= 
# For WINNER Display
# ============================================================================= 
def popwin(WINTEXT):
    global popwin
    popwin = Toplevel()
    popwin.title("BitcoinHunter.py")
    popwin.iconbitmap('images/miz.ico')
    popwin.geometry("700x250")
    widgetwin = tkinter.Label(popwin, compound='top')
    widgetwin.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
    widgetwin['text'] = "© MIZOGG 2018 - 2022"
    widgetwin['image'] = widgetwin.miz_image_png
    widgetwin.place(x=380,y=180)
    widgetwin2 = tkinter.Label(popwin, compound='top')
    widgetwin2.miz_image_png = tkinter.PhotoImage(file='images/congratulations.gif')
    # widgetwin2['text'] = "congratulations"
    widgetwin2['image'] = widgetwin2.miz_image_png
    widgetwin2.place(x=10,y=165)
    editArea = tkst.ScrolledText(master = popwin, wrap = tkinter.WORD, width  = 70, height = 6,font=("Arial",12))
    editArea.pack(padx=10, pady=10)
    editArea.insert(tkinter.INSERT, WINTEXT)
    frame = Frame(popwin)
    frame.pack(padx=10, pady=10)

    button1 = Button(frame, text=" Close ", command=popwin.destroy)
    button1.grid(row=0, column=1)
    
# Window Class
class App(Tk):
    def __init__(self, *args,**kwargs):
        Tk.__init__(self,*args,**kwargs)
        self.n = 16 
        self.a = np.zeros((self.n, self.n))
        self.b = np.zeros((self.n, self.n))
        self.cells = {}
        self.running = True
        #Content Frame
        self.title('Hunter of Bitcoin')
        self.iconbitmap('images/miz.ico')
        self.content = ttk.Frame(self, padding=(5))
        self.content.grid(row =0, column=0, sticky=(N,S,E,W))
        self.content1 = ttk.Frame(self, padding=(5))
        self.content1.grid(row =0, column=1)
        #Cells Frame
        self.canvas = Canvas(self.content, width=500, height=500,
                borderwidth=0, highlightthickness=0,
                background='white')
        self.canvas1 = Canvas(self.content1, width=600, height=500,
                borderwidth=1, highlightthickness=1,
                background='white')
        self.canvas.grid(row=0, column=0, sticky=(N,S,E,W))
        self.canvas.bind('<Configure>', self.draw)
        self.controls = ttk.Frame(self.content, padding=(5))
        self.controls.grid(row=1, column=0, sticky=(N,S,E,W))
        self.start = ttk.Button(self.controls, text='Start',
                command=self.start_hunter)
        self.start.grid(row=0, column=0, sticky=(W))
        self.stop = ttk.Button(self.controls, text='Stop',
                command=self.stop_hunter)
        self.stop.grid(row=0, column=2, sticky=(E))
        self.random = ttk.Button(self.controls, text='random',
                command=self.randgen)
        self.random.grid(row=0, column=1, sticky=(E,W))
        #Size Configuration
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(0, weight=4)
        self.content.rowconfigure(1, weight=1)
        self.controls.columnconfigure(0,weight=1)
        self.controls.columnconfigure(1,weight=1)
        self.controls.columnconfigure(2,weight=1)
        self.controls.rowconfigure(0,weight=1)
        
        hunter_win = tkinter.Frame(self.content1, bg = '#A1A1A1')
        hunter_win.pack(fill='both', expand='yes')
        
        Binary_data = "Binary Data"
        Binarylable = tkinter.Label(hunter_win, text=Binary_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        Binarylable.pack(padx=10, pady=5)
        self.binstring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.binstring_update.pack(padx=10, pady=2)
        
        DEC_data = "Private Key Dec"
        DEClable = tkinter.Label(hunter_win, text=DEC_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        DEClable.pack(padx=10, pady=5)
        self.decstring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.decstring_update.pack(padx=10, pady=2)
        
        HEX_data = "Private Key HEX"
        HEXlable = tkinter.Label(hunter_win, text=HEX_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        HEXlable.pack(padx=10, pady=5)
        self.hexstring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.hexstring_update.pack(padx=10, pady=2)
        
        caddr_data = "Address Compressed"
        caddrlable = tkinter.Label(hunter_win, text=caddr_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        caddrlable.pack(padx=10, pady=5)
        self.caddrstring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.caddrstring_update.pack(padx=10, pady=2)
        
        wifc_data = "WIF Compressed"
        wifclable = tkinter.Label(hunter_win, text=wifc_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        wifclable.pack(padx=10, pady=5)
        self.wifcstring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.wifcstring_update.pack(padx=10, pady=2)
        
        uaddr_data = "Address Uncompressed"
        uaddrlable = tkinter.Label(hunter_win, text=uaddr_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        uaddrlable.pack(padx=10, pady=5)
        self.uaddrstring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.uaddrstring_update.pack(padx=10, pady=2)
        
        wifu_data = "WIF Uncompressed"
        wifulable = tkinter.Label(hunter_win, text=wifu_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        wifulable.pack(padx=10, pady=5)
        self.wifustring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.wifustring_update.pack(padx=10, pady=2)
        
        p2sh_data = "Address P2SH"
        p2shlable = tkinter.Label(hunter_win, text=p2sh_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        p2shlable.pack(padx=10, pady=5)
        self.p2shstring_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.p2shstring_update.pack(padx=10, pady=2)
        
        bc1_data = "Address P2WPKH"
        bc1lable = tkinter.Label(hunter_win, text=bc1_data, font=("Arial",12),bg='#A1A1A1',fg="Black")
        bc1lable.pack(padx=10, pady=5)
        self.bech32string_update = tkinter.Entry(hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",10),text="", width=80, fg="Purple")
        self.bech32string_update.pack(padx=10, pady=2)
            
    def draw(self, event=None):
        self.canvas.delete('rect')
        width = int(self.canvas.winfo_width()/self.n)
        height = int(self.canvas.winfo_height()/self.n)
        for col in range(self.n):
            for row in range(self.n):
                x1 = col*width
                x2 = x1 + width
                y1 = row*height
                y2 = y1 + height
                if self.a[row][col]==0:
                    cell = self.canvas.create_rectangle(x1, y1, x2, y2,
                            fill='white', tags='cell')
                else:
                    cell = self.canvas.create_rectangle(x1, y1, x2, y2,
                            fill='Purple', tags='cell')
                self.cells[row, col] = cell
                self.canvas.tag_bind(cell, '<Button-1>', lambda event,
                        row=row, col=col: self.click(row, col))

    def click(self, row, col):
        #Changes the value and color of a cell when is clicked
        cell = self.cells[row,col]
        color = 'white' if self.a[row, col] == 1. else 'Purple'
        if self.a[row,col] == 0:
            self.a[row, col]=1
        else:
            self.a[row,col]=0
        self.canvas.itemconfigure(cell, fill=color)
        arr = np.array(self.a)
        ts = arr.tobytes()
        binstring = np.frombuffer(ts)
        binstring = np.round(binstring.transpose()).astype(int)
        binstring = ''.join(map(str, binstring))
        binstringvar = tkinter.StringVar()
        binstringvar.set(binstring)
        self.binstring_update.config(textvariable = binstringvar, relief='flat')
        self.binstring_update.update()
        dec = int(binstring, 2)
        decstringvar = tkinter.StringVar()
        decstringvar.set(dec)
        self.decstring_update.config(textvariable = decstringvar, relief='flat')
        self.decstring_update.update()
        HEX = hex(int(binstring, 2))
        hexstringvar = tkinter.StringVar()
        hexstringvar.set(HEX)
        self.hexstring_update.config(textvariable = hexstringvar, relief='flat')
        self.hexstring_update.update()
        caddr = ice.privatekey_to_address(0, True, dec)
        caddrstringvar = tkinter.StringVar()
        caddrstringvar.set(caddr)
        self.caddrstring_update.config(textvariable = caddrstringvar, relief='flat')
        self.caddrstring_update.update()
        uaddr = ice.privatekey_to_address(0, False, dec)
        uaddrstringvar = tkinter.StringVar()
        uaddrstringvar.set(uaddr)
        self.uaddrstring_update.config(textvariable = uaddrstringvar, relief='flat')
        self.uaddrstring_update.update()
        wifc = ice.btc_pvk_to_wif(HEX)
        wifcstringvar = tkinter.StringVar()
        wifcstringvar.set(wifc)
        self.wifcstring_update.config(textvariable = wifcstringvar, relief='flat')
        self.wifcstring_update.update()
        wifu = ice.btc_pvk_to_wif(HEX, False)
        wifustringvar = tkinter.StringVar()
        wifustringvar.set(wifu)
        self.wifustring_update.config(textvariable = wifustringvar, relief='flat')
        self.wifustring_update.update()
        p2sh = ice.privatekey_to_address(1, True, dec)
        p2shstringvar = tkinter.StringVar()
        p2shstringvar.set(p2sh)
        self.p2shstring_update.config(textvariable = p2shstringvar, relief='flat')
        self.p2shstring_update.update()
        bech32 = ice.privatekey_to_address(2, True, dec)
        bech32stringvar = tkinter.StringVar()
        bech32stringvar.set(bech32)
        self.bech32string_update.config(textvariable = bech32stringvar, relief='flat')
        self.bech32string_update.update()
        if caddr in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)
        if uaddr in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)
        if p2sh in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)
        if bech32 in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Bc1: {bech32} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)


    def hunter(self):
        self.draw()
        n = self.n
        if self.running: 
            cellstogen = np.random.randint(0, int(n*n/2))
            self.b = np.zeros((n, n))
            arr = np.array(self.a)
            ts = arr.tobytes()
            binstring = np.frombuffer(ts)
            binstring = np.round(binstring.transpose()).astype(int)
            binstring = ''.join(map(str, binstring))
            binstringvar = tkinter.StringVar()
            binstringvar.set(binstring)
            self.binstring_update.config(textvariable = binstringvar, relief='flat')
            self.binstring_update.update()
            dec = int(binstring, 2)
            decstringvar = tkinter.StringVar()
            decstringvar.set(dec)
            self.decstring_update.config(textvariable = decstringvar, relief='flat')
            self.decstring_update.update()
            HEX = hex(int(binstring, 2))
            hexstringvar = tkinter.StringVar()
            hexstringvar.set(HEX)
            self.hexstring_update.config(textvariable = hexstringvar, relief='flat')
            self.hexstring_update.update()
            caddr = ice.privatekey_to_address(0, True, dec)
            caddrstringvar = tkinter.StringVar()
            caddrstringvar.set(caddr)
            self.caddrstring_update.config(textvariable = caddrstringvar, relief='flat')
            self.caddrstring_update.update()
            uaddr = ice.privatekey_to_address(0, False, dec)
            uaddrstringvar = tkinter.StringVar()
            uaddrstringvar.set(uaddr)
            self.uaddrstring_update.config(textvariable = uaddrstringvar, relief='flat')
            self.uaddrstring_update.update()
            wifc = ice.btc_pvk_to_wif(HEX)
            wifcstringvar = tkinter.StringVar()
            wifcstringvar.set(wifc)
            self.wifcstring_update.config(textvariable = wifcstringvar, relief='flat')
            self.wifcstring_update.update()
            wifu = ice.btc_pvk_to_wif(HEX, False)
            wifustringvar = tkinter.StringVar()
            wifustringvar.set(wifu)
            self.wifustring_update.config(textvariable = wifustringvar, relief='flat')
            self.wifustring_update.update()
            p2sh = ice.privatekey_to_address(1, True, dec)
            p2shstringvar = tkinter.StringVar()
            p2shstringvar.set(p2sh)
            self.p2shstring_update.config(textvariable = p2shstringvar, relief='flat')
            self.p2shstring_update.update()
            bech32 = ice.privatekey_to_address(2, True, dec)
            bech32stringvar = tkinter.StringVar()
            bech32stringvar.set(bech32)
            self.bech32string_update.config(textvariable = bech32stringvar, relief='flat')
            self.bech32string_update.update()
            if caddr in bloom_filterbtc:
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBinary Data: \n {binstring}")
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            if uaddr in bloom_filterbtc:
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu} \nBinary Data: \n {binstring}")
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            if p2sh in bloom_filterbtc:
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh} \nBinary Data: \n {binstring}")
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            if bech32 in bloom_filterbtc:
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Bc1: {bech32} \nBinary Data: \n {binstring}")
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            for cell in range(cellstogen):
                i = np.random.randint(0, n-1)
                j = np.random.randint(0, n-1)
                self.b[i,j] = 1
            self.a = self.b
            self.after(1, self.hunter)

    def start_hunter(self):
        self.running = True
        self.hunter()

    def stop_hunter(self):
        self.running = False

    def randgen(self):
        n = self.n
        cellstogen = np.random.randint(0, int(n*n/2))
        self.b = np.zeros((n, n))
        for cell in range(cellstogen):
            i = np.random.randint(0, n-1)
            j = np.random.randint(0, n-1)
            self.b[i,j] = 1
        self.a = self.b
        self.draw()
        arr = np.array(self.a)
        ts = arr.tobytes()
        binstring = np.frombuffer(ts)
        binstring = np.round(binstring.transpose()).astype(int)
        binstring = ''.join(map(str, binstring))
        binstringvar = tkinter.StringVar()
        binstringvar.set(binstring)
        self.binstring_update.config(textvariable = binstringvar, relief='flat')
        self.binstring_update.update()
        dec = int(binstring, 2)
        decstringvar = tkinter.StringVar()
        decstringvar.set(dec)
        self.decstring_update.config(textvariable = decstringvar, relief='flat')
        self.decstring_update.update()
        HEX = hex(int(binstring, 2))
        hexstringvar = tkinter.StringVar()
        hexstringvar.set(HEX)
        self.hexstring_update.config(textvariable = hexstringvar, relief='flat')
        self.hexstring_update.update()
        caddr = ice.privatekey_to_address(0, True, dec)
        caddrstringvar = tkinter.StringVar()
        caddrstringvar.set(caddr)
        self.caddrstring_update.config(textvariable = caddrstringvar, relief='flat')
        self.caddrstring_update.update()
        uaddr = ice.privatekey_to_address(0, False, dec)
        uaddrstringvar = tkinter.StringVar()
        uaddrstringvar.set(uaddr)
        self.uaddrstring_update.config(textvariable = uaddrstringvar, relief='flat')
        self.uaddrstring_update.update()
        wifc = ice.btc_pvk_to_wif(HEX)
        wifcstringvar = tkinter.StringVar()
        wifcstringvar.set(wifc)
        self.wifcstring_update.config(textvariable = wifcstringvar, relief='flat')
        self.wifcstring_update.update()
        wifu = ice.btc_pvk_to_wif(HEX, False)
        wifustringvar = tkinter.StringVar()
        wifustringvar.set(wifu)
        self.wifustring_update.config(textvariable = wifustringvar, relief='flat')
        self.wifustring_update.update()
        p2sh = ice.privatekey_to_address(1, True, dec)
        p2shstringvar = tkinter.StringVar()
        p2shstringvar.set(p2sh)
        self.p2shstring_update.config(textvariable = p2shstringvar, relief='flat')
        self.p2shstring_update.update()
        bech32 = ice.privatekey_to_address(2, True, dec)
        bech32stringvar = tkinter.StringVar()
        bech32stringvar.set(bech32)
        self.bech32string_update.config(textvariable = bech32stringvar, relief='flat')
        self.bech32string_update.update()
        if caddr in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)
        if uaddr in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)
        if p2sh in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)
        if bech32 in bloom_filterbtc:
            WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Bc1: {bech32} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(WINTEXT)
            popwin(WINTEXT)


if __name__ == '__main__':
    hunter_btc = App()
    hunter_btc.mainloop()