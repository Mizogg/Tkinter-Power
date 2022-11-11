#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 11.11.2022 https://t.me/CryptoCrackersUK
import random, sys, os
import numpy as np
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import secp256k1 as ice
from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
import psutil
with open('puzzle.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)
addr_count = len(bloom_filterbtc)  
addr_count_print = f'Total Bitcoin Addresses Loaded and Checking : {addr_count}'
def hex2bin(value):
    return bin(int(value, 16))

def hex2dec(value):
    return int(value, 16)
    
def hex2bit(value):
    length = len(bin(int(value, 16)))
    length -=2
    return length

# ============================================================================= 
# For Menu
# ============================================================================= 
def donothing():
   x = 0

def openweb():
   x = webbrowser.open("https://mizogg.co.uk")
   
def opentelegram():
   x = webbrowser.open("https://t.me/CryptoCrackersUK")

information = ('''
            Look for Bitcoin with tkinter and python in GUI.
                        16x16Hunter
                    Made By Mizogg.co.uk
                        Version = 1.1
                        
                Visualize own HEX not working
            Toplevel needs fixing after single click
                    MUCH TODO more to add
''')
  
class App:
    def __init__(self):
        self.is_active = False
        self.in_tick = False
        self.cols = 16
        self.rows = 16
        self.size = 30
        self.grid = []
        self.initial_state = []
        self.tick_count = 0
        self.off_cells = 0
        self.on_cells = 0
        self.tick_delay = 0 #in ms
        self.seed_ratio = 33
    # ============================================================================= 
    # For WINNER Display
    # ============================================================================= 
    def popwin(self):
        self.popwin = Toplevel()
        self.popwin.title("BitcoinHunter 16x16.py")
        self.popwin.iconbitmap('images/miz.ico')
        self.popwin.geometry("700x250")
        widgetwin = tkinter.Label(self.popwin, compound='top')
        widgetwin.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        widgetwin['text'] = "© MIZOGG 2018 - 2022"
        widgetwin['image'] = widgetwin.miz_image_png
        widgetwin.place(x=380,y=180)
        widgetwin2 = tkinter.Label(self.popwin, compound='top')
        widgetwin2.miz_image_png = tkinter.PhotoImage(file='images/congratulations.gif')
        widgetwin2['image'] = widgetwin2.miz_image_png
        widgetwin2.place(x=10,y=165)
        editArea = tkst.ScrolledText(master = self.popwin, wrap = tkinter.WORD, width  = 70, height = 6,font=("Arial",12))
        editArea.pack(padx=10, pady=10)
        editArea.insert(tkinter.INSERT, self.WINTEXT)
        frame = Frame(self.popwin)
        frame.pack(padx=10, pady=10)
        button1 = Button(frame, text=" Close ", command=self.popwin.destroy)
        button1.grid(row=0, column=1)
            
    def btc_hunter(self):
        arr = np.array(self.grid)
        binstring = ''.join(''.join(map(str, l)) for l in arr)
        self.binstringvar = tkinter.StringVar()
        self.binstringvar.set(binstring)
        self.binstring_update.config(textvariable = self.binstringvar, relief='flat')
        self.binstring_update.update()
        
        dec = int(binstring, 2)
        self.decstringvar = tkinter.StringVar()
        self.decstringvar.set(dec)
        self.decstring_update.config(textvariable = self.decstringvar, relief='flat')
        self.decstring_update.update()
        
        HEX = hex(int(binstring, 2))
        self.hexstringvar = tkinter.StringVar()
        self.hexstringvar.set(HEX)
        self.hexstring_update.config(textvariable = self.hexstringvar, relief='flat')
        self.hexstring_update.update()

        caddr = ice.privatekey_to_address(0, True, dec)
        uaddr = ice.privatekey_to_address(0, False, dec)
        HEX = "%064x" % dec
        wifc = ice.btc_pvk_to_wif(HEX)
        wifu = ice.btc_pvk_to_wif(HEX, False)
        
        self.caddrstringvar = tkinter.StringVar()
        self.caddrstringvar.set(caddr)
        self.caddrstring_update.config(textvariable = self.caddrstringvar, relief='flat')
        self.caddrstring_update.update()
        
        self.wifcstringvar = tkinter.StringVar()
        self.wifcstringvar.set(wifc)
        self.wifcstring_update.config(textvariable = self.wifcstringvar, relief='flat')
        self.wifcstring_update.update()
        
        self.uaddrstringvar = tkinter.StringVar()
        self.uaddrstringvar.set(uaddr)
        self.uaddrstring_update.config(textvariable = self.uaddrstringvar, relief='flat')
        self.uaddrstring_update.update()
        
        self.wifustringvar = tkinter.StringVar()
        self.wifustringvar.set(wifu)
        self.wifustring_update.config(textvariable = self.wifustringvar, relief='flat')
        self.wifustring_update.update()
        
        p2sh = ice.privatekey_to_address(1, True, dec)
        self.p2shstringvar = tkinter.StringVar()
        self.p2shstringvar.set(p2sh)
        self.p2shstring_update.config(textvariable = self.p2shstringvar, relief='flat')
        self.p2shstring_update.update()
        bech32 = ice.privatekey_to_address(2, True, dec)
        self.bech32stringvar = tkinter.StringVar()
        self.bech32stringvar.set(bech32)
        self.bech32string_update.config(textvariable = self.bech32stringvar, relief='flat')
        self.bech32string_update.update()
        if caddr in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(self.WINTEXT)
            self.popwin()
        if uaddr in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(self.WINTEXT)
            self.popwin()
        if p2sh in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(self.WINTEXT)
            self.popwin()
        if bech32 in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Bc1: {bech32} \nBinary Data: \n {binstring}")
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(self.WINTEXT)
            self.popwin()

    def cpu_met(self):
        self.cpu_use = psutil.cpu_percent()
        self.cpu_label.config(text='Total CPU {}%'.format(self.cpu_use))
        self.cpu_label.after(1000,self.cpu_met)
        self.ram_use = psutil.virtual_memory()[2]
        self.ram_label.config(text='RAM memory % used {}%'.format(self.ram_use))

    def init_tk(self):
        self.BH16x16 = Tk()
        self.BH16x16.title('BitcoinHunter 16x16.py')
        self.BH16x16.iconbitmap('images/miz.ico')
        self.BH16x16.geometry("1160x680")
        self.BH16x16.menubar = Menu(self.BH16x16)
        self.BH16x16.filemenu = Menu(self.BH16x16.menubar, tearoff=0)
        self.BH16x16.filemenu.add_separator()
        self.BH16x16.filemenu.add_command(label="Exit", command=self.BH16x16.quit)
        self.BH16x16.menubar.add_cascade(label="File", menu=self.BH16x16.filemenu)
        self.BH16x16.helpmenu = Menu(self.BH16x16.menubar, tearoff=0)
        self.BH16x16.helpmenu.add_command(label="Help Telegram Group", command=opentelegram)
        self.BH16x16.helpmenu.add_command(label="Mizogg Website", command=openweb)
        self.BH16x16.helpmenu.add_command(label="About BitcoinHunter", command=self.startpop)
        self.BH16x16.menubar.add_cascade(label="Help", menu=self.BH16x16.helpmenu)
        self.BH16x16.config(menu=self.BH16x16.menubar)
        self.my_notebook = ttk.Notebook(self.BH16x16)
        self.my_notebook.pack(pady=5)
        self.main_frame = Frame(self.my_notebook, width=1140, height=660)
        self.about_frame = Frame(self.my_notebook, width=840, height=620)
        self.main_frame.pack(fill="both", expand=1)
        self.about_frame.pack(fill="both", expand=1)
        self.my_notebook.add(self.main_frame, text=" 16x16Hunter ")
        self.my_notebook.add(self.about_frame, text="About 16x16Hunter")
        self.canvas = Canvas(self.main_frame)
        self.canvas.grid(row=0, columnspan=6, padx=5, pady=3)
        self.canvas.bind('<Button-1>', self.canvas_click)
        self.content1 = Frame(self.main_frame, padding=(3))
        self.content1.grid(row =0, column=7)
        self.lbl_edt_seed_ratio = Label(self.main_frame, text='Seed Ratio % start On ')
        self.lbl_edt_seed_ratio.grid(row=1, column=0, sticky=E)
        self.edt_seed_ratio = tkinter.Entry(self.main_frame, width=4, fg='red')
        self.edt_seed_ratio.insert(0, str(self.seed_ratio))
        self.edt_seed_ratio.grid(row=1, column=1, sticky=W)
        self.btn_seed = tkinter.Button(self.main_frame, text='Seed', command=self.seed, fg='purple')
        self.btn_seed.grid(row=1, column=2)
        self.btn_clear = tkinter.Button(self.main_frame, text='Clear', command=self.clear_canvas, fg='red')
        self.btn_clear.grid(row=1, column=3)
        self.btn_start_stop = tkinter.Button(self.main_frame, text='Start', command=self.start_stop, fg='green')
        self.btn_start_stop.grid(row=1, column=4)
        self.btn_tick = tkinter.Button(self.main_frame, text='>>', command=self.tick, fg='orange')
        self.btn_tick.grid(row=1, column=5)
        self.on_cell_color = 'purple'
        self.off_cell_color = '#FFFFFF'
        self.grid_color = '#808080'
        '''input_win = tkinter.Frame(self.content1, bg = '#A1A1A1')
        input_win.pack(fill='both', expand='yes')
        self._txt_inputhex = tkinter.Entry(input_win, width=56, font=("Arial",10))
        self._txt_inputhex.insert(0, '1')
        self._txt_inputhex.pack(padx=10, pady=3)
        self._txt_inputhex.focus()
        self._btc_bin = tkinter.Button(input_win, text="Visualize You Own Private Key", font=("Arial",10), command=self.evt_btc_hex)
        self._btc_bin.pack(padx=10, pady=3)'''
        self.hunter_win = tkinter.Frame(self.content1, bg = '#A1A1A1')
        self.hunter_win.pack(fill='both', expand='yes')
        Binary_data = "Binary Data"
        Binarylable = tkinter.Label(self.hunter_win, text=Binary_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        Binarylable.pack(padx=10, pady=3)
        self.binstring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.binstring_update.pack(padx=10, pady=2)
        DEC_data = "Private Key Dec"
        DEClable = tkinter.Label(self.hunter_win, text=DEC_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        DEClable.pack(padx=10, pady=3)
        self.decstring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.decstring_update.pack(padx=10, pady=2)
        HEX_data = "Private Key HEX"
        HEXlable = tkinter.Label(self.hunter_win, text=HEX_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        HEXlable.pack(padx=10, pady=3)
        self.hexstring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.hexstring_update.pack(padx=10, pady=2)
        caddr_data = "Address Compressed"
        caddrlable = tkinter.Label(self.hunter_win, text=caddr_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        caddrlable.pack(padx=10, pady=3)
        self.caddrstring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.caddrstring_update.pack(padx=10, pady=2)
        wifc_data = "WIF Compressed"
        wifclable = tkinter.Label(self.hunter_win, text=wifc_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        wifclable.pack(padx=10, pady=3)
        self.wifcstring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.wifcstring_update.pack(padx=10, pady=2)
        uaddr_data = "Address Uncompressed"
        uaddrlable = tkinter.Label(self.hunter_win, text=uaddr_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        uaddrlable.pack(padx=10, pady=3)
        self.uaddrstring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.uaddrstring_update.pack(padx=10, pady=2)
        wifu_data = "WIF Uncompressed"
        wifulable = tkinter.Label(self.hunter_win, text=wifu_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        wifulable.pack(padx=10, pady=3)
        self.wifustring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.wifustring_update.pack(padx=10, pady=2)
        p2sh_data = "Address P2SH"
        p2shlable = tkinter.Label(self.hunter_win, text=p2sh_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        p2shlable.pack(padx=10, pady=3)
        self.p2shstring_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.p2shstring_update.pack(padx=10, pady=2)
        bc1_data = "Address P2WPKH"
        bc1lable = tkinter.Label(self.hunter_win, text=bc1_data, font=("Arial",10),bg='#A1A1A1',fg="Black")
        bc1lable.pack(padx=10, pady=3)
        self.bech32string_update = tkinter.Entry(self.hunter_win, state='readonly', bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.bech32string_update.pack(padx=10, pady=2)
        self.t123 = tkinter.Label(self.BH16x16, text=addr_count_print,font=("Arial",14),bg="#F0F0F0",fg="purple")
        self.t123.place(x=540,y=580)
        self.lbl_tickno = tkinter.Label(self.hunter_win, text='Total Private Keys Scanned : 0', font=("Arial",10),bg='#A1A1A1',fg="Purple")
        self.lbl_tickno.pack(padx=3, pady=3)
        self.lbl_totalno = tkinter.Label(self.hunter_win, text='Total Addresses Scanned : 0', font=("Arial",10),bg='#A1A1A1',fg="Purple")
        self.lbl_totalno.pack(padx=3, pady=3)
        self.cpu_label = tkinter.Label(self.BH16x16,font = ('calibri', 14, 'bold'), background = '#F0F0F0', foreground = 'red')
        self.cpu_label.place(x=600,y=620)
        self.ram_label = tkinter.Label(self.BH16x16,font = ('calibri', 14, 'bold'), background = '#F0F0F0', foreground = 'red')
        self.ram_label.place(x=800,y=620)
        widget = tkinter.Label(self.BH16x16, compound='top')
        widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        widget['text'] = "© MIZOGG 2018 - 2022"
        widget['image'] = widget.miz_image_png
        widget.place(x=5,y=590)
        self.cpu_met()
        # =============================================================================
        # about_frame
        # =============================================================================
        about16 = tkinter.Frame(master = self.about_frame, bg = '#F0F0F0')
        about16.pack(fill='both', expand='yes')
        editArea = tkst.ScrolledText(master = about16, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        editArea.insert(tkinter.INSERT, information)
        
    def init_grid(self):
        self.grid = [[0 for x in range(self.cols)] for y in range(self.rows)]

    def start(self):
        self.init_grid()
        self.init_tk()
        self.clear_canvas()
        self.BH16x16.mainloop()
        
    def canvas_click(self, e):
        cl = int(e.x // self.size)
        rw = int(e.y // self.size)
        if self.is_active is False:
            if self.grid[rw][cl]:
                self.grid[rw][cl] = 0
                color = self.off_cell_color
                self.on_cells -= 1
                self.off_cells += 1
            else:
                self.grid[rw][cl] = 1
                color = self.on_cell_color
                self.on_cells += 1
                self.off_cells -= 1
            self.put_rect(rw, cl, color)
            self.update_labels()
            self.btc_hunter()
            if self.on_cells:
                self.btn_start_stop.config(state=NORMAL)
                self.btn_tick.config(state=NORMAL)
            else:
                self.btn_start_stop.config(state=DISABLED)
                self.btn_tick.config(state=DISABLED)

    def put_rect(self, rw, cl, color):
        x1 = cl * self.size
        y1 = rw * self.size
        x2 = x1 + self.size
        y2 = y1 + self.size
        self.canvas.create_rectangle(x1, y1, x2, y2, fill=color, outline=self.grid_color, tags='cell')

    def update_canvas(self):
        self.off_cells = 0
        self.on_cells = 0
        self.canvas.delete('all')
        for rw in range(self.rows):
            for cl in range(self.cols):
                if self.grid[rw][cl]:
                    color = self.on_cell_color
                    self.on_cells += 1
                else:
                    color = self.off_cell_color
                    self.off_cells += 1
                self.put_rect(rw, cl, color)
        self.update_labels()
        self.btc_hunter()

    def clear_canvas(self):
        self.size = 30
        self.seed_ratio = int(self.edt_seed_ratio.get())
        self.tick_count = 0
        self.addr_count = 0
        self.init_grid()
        self.canvas.config(width=self.cols*self.size, height=self.rows*self.size)
        self.update_canvas()
        self.btn_start_stop.config(state=DISABLED)
        self.btn_tick.config(state=DISABLED)

    def seed(self):
        self.clear_canvas()
        for rw in range(self.rows):
            for cl in range(self.cols):
                seed_chance = random.randint(1, 100)
                if seed_chance <= self.seed_ratio:
                    self.grid[rw][cl] = 1
                else:
                    self.grid[rw][cl] = 0
        self.update_canvas()
        self.btn_start_stop.config(state=NORMAL)
        self.btn_tick.config(state=NORMAL)

    def start_stop(self):
        if self.is_active:
            self.is_active = False
            self.btn_start_stop.config(text='Start')
            self.btn_tick.config(state=NORMAL)
            self.btn_seed.config(state=NORMAL)
            self.btn_clear.config(state=NORMAL)
        else:
            self.tick_delay = 0
            self.is_active = True
            self.BH16x16.after(self.tick_delay, self.tick)
            self.btn_start_stop.config(text='Stop')
            self.btn_tick.config(state=DISABLED)
            self.btn_seed.config(state=DISABLED)
            self.btn_clear.config(state=DISABLED)
            
    '''def evt_btc_hex(self):
        hex_value = self._txt_inputhex.get().strip().replace(" ", "")
        bin_value = hex2bin(hex_value).strip().replace("0b", "")
        dec_value = hex2dec(hex_value)
        bit_value = hex2bit(hex_value)
        self.clear_canvas()
        for rw in range(self.rows):
            for cl in range(self.cols):
                seed_chance = random.randint(1, 100)
                if seed_chance <= self.seed_ratio:
                    self.grid[rw][cl] = 1
                else:
                    self.grid[rw][cl] = 0
        self.update_canvas()
        self.btn_start_stop.config(state=NORMAL)
        self.btn_tick.config(state=NORMAL)
        print (bin_value)'''

    def update_labels(self):
        self.lbl_tickno.config(text='Total Private Keys Scanned : %d' %(self.tick_count))
        self.lbl_totalno.config(text='Total Addresses Scanned : %d' %(self.addr_count))
        
    def tick(self):
        if self.in_tick:
            return
        self.in_tick = True
        self.on_cells = 0
        self.off_cells = 0
        self.canvas.delete('all')
        for rw in range(self.rows):
            for cl in range(self.cols):
                seed_chance = random.randint(1, 100)
                if seed_chance <= self.seed_ratio:
                    self.grid[rw][cl] = 1
                else:
                    self.grid[rw][cl] = 0
        self.update_canvas()
        self.in_tick = False
        self.tick_count += 1
        self.addr_count += 4
        self.update_labels()
        if self.is_active:
            self.BH16x16.after(self.tick_delay, self.tick)
    
    def startpop(self):
        self.pop = Toplevel()
        self.pop.title("16x16.py")
        self.pop.iconbitmap('images/miz.ico')
        self.pop.geometry("700x250")
        widget = tkinter.Label(self.pop, compound='top')
        widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        widget['text'] = "© MIZOGG 2018 - 2022"
        widget['image'] = widget.miz_image_png
        widget.place(x=220,y=180)
        label = Label(self.pop, text='Welcome to 16x16.py...... \n\n Made By Mizogg.co.uk \n\n Version 1.1 08/11/22')
        label.pack(pady=10)
        Label(self.pop, text= "This window will get closed after 2 seconds...", font=('Helvetica 8 bold')).pack(pady=10)
        frame = Frame(self.pop)
        frame.pack(pady=10)
        button1 = Button(frame, text=" Close ",
        command=self.CLOSEWINDOW)
        button1.grid(row=0, column=1)
        self.pop.after(2000,lambda:self.pop.destroy())
    
    def CLOSEWINDOW(self):
        self.pop.destroy()

if __name__ == '__main__':
    hunter_16x16 = App()
    hunter_16x16.start()
