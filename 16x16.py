import random
import numpy as np
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
from bit import *
from bit.format import bytes_to_wif
from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate

with open('puzzle.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)

# ============================================================================= 
# For WINNER Display
# ============================================================================= 
def popwin(WINTEXT):
    global popwin
    popwin = Toplevel()
    popwin.title("BitcoinHunter 16x16.py")
    popwin.iconbitmap('images/miz.ico')
    popwin.geometry("700x250")
    widgetwin = tkinter.Label(popwin, compound='top')
    widgetwin.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
    widgetwin['text'] = "© MIZOGG 2018 - 2022"
    widgetwin['image'] = widgetwin.miz_image_png
    widgetwin.place(x=380,y=180)
    widgetwin2 = tkinter.Label(popwin, compound='top')
    widgetwin2.miz_image_png = tkinter.PhotoImage(file='images/congratulations.gif')
    widgetwin2['image'] = widgetwin2.miz_image_png
    widgetwin2.place(x=10,y=165)
    editArea = tkst.ScrolledText(master = popwin, wrap = tkinter.WORD, width  = 70, height = 6,font=("Arial",12))
    editArea.pack(padx=10, pady=10)
    editArea.insert(tkinter.INSERT, WINTEXT)
    frame = Frame(popwin)
    frame.pack(padx=10, pady=10)

    button1 = Button(frame, text=" Close ", command=popwin.destroy)
    button1.grid(row=0, column=1)
        
def btc_hunter(self):
    arr = np.array(self.grid)
    binstring = ''.join(''.join(map(str, l)) for l in arr)
    self.binstringvar = tkinter.StringVar()
    self.binstringvar.set(binstring)
    self.binstring_update.config(textvariable = self.binstringvar, relief='flat')
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

    key = Key.from_int(dec)
    wifu = bytes_to_wif(key.to_bytes(), compressed=False) # Uncompressed WIF
    wifc = bytes_to_wif(key.to_bytes(), compressed=True) # Compressed WIF
    key1 = Key(wifu)
    caddr = key.address
    uaddr = key1.address
    
    caddrstringvar = tkinter.StringVar()
    caddrstringvar.set(caddr)
    self.caddrstring_update.config(textvariable = caddrstringvar, relief='flat')
    self.caddrstring_update.update()
    
    wifcstringvar = tkinter.StringVar()
    wifcstringvar.set(wifc)
    self.wifcstring_update.config(textvariable = wifcstringvar, relief='flat')
    self.wifcstring_update.update()
    
    uaddrstringvar = tkinter.StringVar()
    uaddrstringvar.set(uaddr)
    self.uaddrstring_update.config(textvariable = uaddrstringvar, relief='flat')
    self.uaddrstring_update.update()
    
    wifustringvar = tkinter.StringVar()
    wifustringvar.set(wifu)
    self.wifustring_update.config(textvariable = wifustringvar, relief='flat')
    self.wifustring_update.update()
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
        
class Hunter:
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

    def init_tk(self):
        self.root = Tk()
        self.root.title('BitcoinHunter 16x16.py')
        self.root.iconbitmap('images/miz.ico')
        self.canvas = Canvas(self.root)
        self.canvas.grid(row=0, columnspan=6)
        self.canvas.bind('<Button-1>', self.canvas_click)
        
        self.content1 = Frame(self.root, padding=(5))
        self.content1.grid(row =0, column=6)
        
        self.lbl_edt_seed_ratio = Label(self.root, text='Seed Ratio % start On ')
        self.lbl_edt_seed_ratio.grid(row=1, column=0, sticky=E)

        self.edt_seed_ratio = Entry(self.root, width=4)
        self.edt_seed_ratio.insert(0, str(self.seed_ratio))
        self.edt_seed_ratio.grid(row=1, column=1, sticky=W)

        self.btn_seed = Button(self.root, text='Seed', command=self.seed)
        self.btn_seed.grid(row=1, column=2)

        self.btn_clear = Button(self.root, text='Clear', command=self.clear_canvas)
        self.btn_clear.grid(row=1, column=3)

        self.btn_start_stop = Button(self.root, text='Start', command=self.start_stop)
        self.btn_start_stop.grid(row=1, column=4)

        self.btn_tick = Button(self.root, text='>>', command=self.tick)
        self.btn_tick.grid(row=1, column=5)

        self.lbl_tickno = Label(self.root, text='Total Scanned :0')
        self.lbl_tickno.grid(row=1, column=6)

        self.on_cell_color = 'purple'
        self.off_cell_color = '#FFFFFF'
        self.grid_color = '#808080'
        
        self.canvas1 = Canvas(self.content1, width=600, height=600,
                borderwidth=1, highlightthickness=1,
                background='white')
                
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

    def init_grid(self):
        self.grid = [[0 for x in range(self.cols)] for y in range(self.rows)]

    def start(self):
        self.init_grid()
        self.init_tk()
        self.clear_canvas()
        self.root.mainloop()
        
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
            if self.on_cells:
                self.btn_start_stop.config(state=NORMAL)
                self.btn_tick.config(state=NORMAL)
            else:
                self.btn_start_stop.config(state=DISABLED)
                self.btn_tick.config(state=DISABLED)
        btc_hunter(self)

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

    def clear_canvas(self):
        self.size = 30
        self.seed_ratio = int(self.edt_seed_ratio.get())
        self.tick_count = 0
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
        btc_hunter(self)
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
            self.root.after(self.tick_delay, self.tick)
            self.btn_start_stop.config(text='Stop')
            self.btn_tick.config(state=DISABLED)
            self.btn_seed.config(state=DISABLED)
            self.btn_clear.config(state=DISABLED)

    def update_labels(self):
        self.lbl_tickno.config(text='Total Scanned : %d' %(self.tick_count))
        
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
        btc_hunter(self)
        self.in_tick = False
        self.tick_count += 1
        self.update_labels()
        if self.is_active:
            self.root.after(self.tick_delay, self.tick)


if __name__ == '__main__':
    hunter = Hunter()
    hunter.start()
