import random, sys, os
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import psutil
import webbrowser
from bloomfilter import BloomFilter
import numpy as np
import secp256k1 as ice

def openweb():
   x = webbrowser.open("https://mizogg.co.uk")
   
def opentelegram():
   x = webbrowser.open("https://t.me/CryptoCrackersUK")

with open('btc.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)
    
def countadd():
    addr_count = len(bloom_filterbtc)
    addr_count_print = (f'Total BTC Addresses Loaded and Checking : {addr_count}')
    return addr_count_print
    
information16x16 = ('''
                        16x16Hunter
                    Made By Mizogg.co.uk
            Added Visualize Your own Private Key

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
        self.tick_delay = 0
        self.seed_ratio = 33
        self.jump_forward_timer = None
        self.jump_backward_timer = None

    def cpu_met(self):
        self.cpu_use = psutil.cpu_percent()
        self.cpu_label.config(text='Total CPU {} %'.format(self.cpu_use))
        self.cpu_label.after(1000,self.cpu_met)
        self.ram_use = psutil.virtual_memory()[2]
        self.ram_label.config(text='RAM Used {} %'.format(self.ram_use))
        ram_free = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
        self.ram_free = str(ram_free)[:4]
        self.ram_free_label.config(text='RAM Free {} %'.format(self.ram_free))

    def init_tk(self):
        self.BH16x16 = Tk()
        self.BH16x16.title('BitcoinHunter 16x16.py')
        self.BH16x16.geometry("1260x760")
        self.BH16x16.menubar = Menu(self.BH16x16)
        self.BH16x16.filemenu = Menu(self.BH16x16.menubar, tearoff=0)
        self.BH16x16.filemenu.add_separator()
        self.BH16x16.filemenu.add_command(label="Exit", command=self.BH16x16.quit)
        self.BH16x16.menubar.add_cascade(label="File", menu=self.BH16x16.filemenu)
        self.BH16x16.helpmenu = Menu(self.BH16x16.menubar, tearoff=0)
        self.BH16x16.helpmenu.add_command(label="Help Telegram Group", command=opentelegram)
        self.BH16x16.helpmenu.add_command(label="Mizogg Website", command=openweb)
        self.BH16x16.helpmenu.add_command(label="About Bit16x16", command='')
        self.BH16x16.menubar.add_cascade(label="Help", menu=self.BH16x16.helpmenu)
        self.BH16x16.config(menu=self.BH16x16.menubar)
        self.jump_increments = [1, 100, 1000, 10000, 100000, 1000000, 10000000]
        self.jump_increment_var = StringVar(self.BH16x16)
        self.jump_increment_var.set(self.jump_increments[0])
        self.my_notebook = ttk.Notebook(self.BH16x16)
        self.my_notebook.pack(pady=5)
        self.main_frame = Frame(self.my_notebook, width=1040, height=740)
        self.about_frame = Frame(self.my_notebook, width=840, height=720)
        self.main_frame.pack(fill="both", expand=1)
        self.about_frame.pack(fill="both", expand=1)
        self.my_notebook.add(self.main_frame, text=" 16x16Hunter ")
        self.my_notebook.add(self.about_frame, text="About 16x16Hunter")
        self.canvas = Canvas(self.main_frame)
        self.canvas.grid(row=0, columnspan=7, padx=3, pady=3)
        self.canvas.bind('<Button-1>', self.canvas_click)
        widget_Logo = "BitcoinHunter 16x16.py "
        self.widget_Logo = tkinter.Label(self.BH16x16, compound='top', text =widget_Logo, font=("Arial",16),bg="#F0F0F0",fg="purple").place(x=60,y=50)
        widget_text = "mizogg.co.uk © MIZOGG 2018 - 2023"
        self.widget_text = tkinter.Label(self.BH16x16, compound='top', text =widget_text, font=("Arial",12),bg="#F0F0F0",fg="red").place(x=340,y=50)
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

        self.hunter_win = tkinter.Frame(self.main_frame, bg='#A1A1A1')
        self.hunter_win.grid(row=0, column=8)

        self.Binarylable = tkinter.Label(self.hunter_win, text="Binary Data", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.Binarylable.pack(padx=10, pady=3)

        self.binstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.binstring_update.pack(padx=10, pady=2)

        self.DEClable = tkinter.Label(self.hunter_win, text="Private Key Dec", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.DEClable.pack(padx=10, pady=3)

        self.decstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.decstring_update.pack(padx=10, pady=2)

        self.HEXlable = tkinter.Label(self.hunter_win, text="Private Key HEX", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.HEXlable.pack(padx=10, pady=3)

        self.hexstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.hexstring_update.pack(padx=10, pady=2)

        self.caddrlable = tkinter.Label(self.hunter_win, text="Address Compressed", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.caddrlable.pack(padx=10, pady=3)

        self.caddrstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.caddrstring_update.pack(padx=10, pady=2)

        self.wifclable = tkinter.Label(self.hunter_win, text="WIF Compressed", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.wifclable.pack(padx=10, pady=3)

        self.wifcstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.wifcstring_update.pack(padx=10, pady=2)

        self.uaddrlable = tkinter.Label(self.hunter_win, text="Address Uncompressed", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.uaddrlable.pack(padx=10, pady=3)

        self.uaddrstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.uaddrstring_update.pack(padx=10, pady=2)

        self.wifulable = tkinter.Label(self.hunter_win, text="WIF Uncompressed", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.wifulable.pack(padx=10, pady=3)

        self.wifustring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.wifustring_update.pack(padx=10, pady=2)

        self.p2shlable = tkinter.Label(self.hunter_win, text="Address P2SH", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.p2shlable.pack(padx=10, pady=3)

        self.p2shstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.p2shstring_update.pack(padx=10, pady=2)

        self.bc1lable = tkinter.Label(self.hunter_win, text="Address P2WPKH", font=("Arial", 10), bg='#A1A1A1', fg="Black")
        self.bc1lable.pack(padx=10, pady=3)

        self.bech32string_update = tkinter.Label(self.hunter_win, bg="#F0F0F0", font=("Arial", 9), text="", width=80, fg="Purple")
        self.bech32string_update.pack(padx=10, pady=2)

        self.addcount = tkinter.Label(self.BH16x16, text=countadd(), font=("Arial", 14), bg="#F0F0F0", fg="purple")
        self.addcount.place(x=680, y=650)

        self.lbl_tickno = tkinter.Label(self.hunter_win, text='Total Private Keys Scanned : 0', font=("Arial", 10), bg='#A1A1A1', fg="Purple")
        self.lbl_tickno.pack(padx=3, pady=3)

        self.lbl_totalno = tkinter.Label(self.hunter_win, text='Total Addresses Scanned : 0', font=("Arial", 10), bg='#A1A1A1', fg="Purple")
        self.lbl_totalno.pack(padx=3, pady=3)

        self.cpu_label = tkinter.Label(self.BH16x16, font=('calibri', 14, 'bold'), bg='#F0F0F0', fg='red')
        self.cpu_label.place(x=680, y=700)

        self.ram_label = tkinter.Label(self.BH16x16, font=('calibri', 14, 'bold'), bg='#F0F0F0', fg='red')
        self.ram_label.place(x=840, y=700)

        self.ram_free_label = tkinter.Label(self.BH16x16, font=('calibri', 14, 'bold'), bg='#F0F0F0', fg='red')
        self.ram_free_label.place(x=1000, y=700)

        input_win = tkinter.Frame(self.hunter_win, bg='#A1A1A1')
        input_win.pack(fill='both', expand='yes')
        self._txt_inputhex = tkinter.Entry(input_win, width=56, font=("Arial", 10))
        self._txt_inputhex.insert(0, '2ffffffffffffffff')
        self._txt_inputhex.pack(padx=10, pady=3)
        self._txt_inputhex.focus()
        self._btc_bin = tkinter.Button(input_win, text="Visualize Your Own Private Key", font=("Arial", 10), command=self.update_grid)
        self._btc_bin.pack(padx=10, pady=3)
        self.cpu_met()

        self.about16 = tkinter.Frame(master=self.about_frame, bg='#F0F0F0')
        self.about16.pack(fill='both', expand='yes')

        self.editArea16 = tkst.ScrolledText(master=self.about16, wrap=tkinter.WORD, width=40, height=16, font=("Arial", 12))
        self.editArea16.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        self.editArea16.insert(tkinter.INSERT, information16x16)

        self.jump_increment_combobox = Combobox(self.main_frame, textvariable=self.jump_increment_var, values=self.jump_increments)
        self.jump_increment_combobox.grid(row=2, column=0, sticky=E)

        self.jump_forward_active = False
        self.btn_start_jump_forward = tkinter.Button(self.main_frame, text='Start Jump Forward', command=self.start_jump_forward, fg='purple')
        self.btn_start_jump_forward.grid(row=2, column=2)

        self.btn_stop_jump_forward = tkinter.Button(self.main_frame, text='Stop Jump Forward', command=self.stop_jump_forward, fg='red')
        self.btn_stop_jump_forward.grid(row=2, column=3)

        self.jump_backward_active = False
        self.btn_start_jump_backward = tkinter.Button(self.main_frame, text='Start Jump Backward', command=self.start_jump_backward, fg='purple')
        self.btn_start_jump_backward.grid(row=3, column=2)

        self.btn_stop_jump_backward = tkinter.Button(self.main_frame, text='Stop Jump Backward', command=self.stop_jump_backward, fg='red')
        self.btn_stop_jump_backward.grid(row=3, column=3)

        self.BH16x16.protocol("WM_DELETE_WINDOW", self.CLOSEWINDOW)


    def start_jump_forward(self):
        self.jump_forward_active = True
        self.jump_forward()

    def stop_jump_forward(self):
        self.jump_forward_active = False

    def start_jump_backward(self):
        self.jump_backward_active = True
        self.jump_backward()

    def stop_jump_backward(self):
        self.jump_backward_active = False

    def jump_forward(self):
        selected_increment = int(self.jump_increment_var.get())
        hex_value = self._txt_inputhex.get()
        int_value = int(hex_value, 16)
        while self.jump_forward_active:
            int_value += selected_increment
            self.seed_inc(int_value)
            
    def jump_backward(self):
        selected_increment = int(self.jump_increment_var.get())
        hex_value = self._txt_inputhex.get()
        int_value = int(hex_value, 16)
        while self.jump_backward_active:
            int_value -= selected_increment
            self.seed_inc(int_value)
        
    def seed_inc(self, int_value):
        if self.in_tick:
            return
        self.in_tick = True
        self.on_cells = 0
        self.off_cells = 0
        self.canvas.delete('all')
        binstring = "{0:b}".format(int_value)
        binstring = binstring.rjust(self.rows * self.cols, "0")
        for i in range(self.rows):
            self.grid[i] = [int(binstring[j]) for j in range(i * self.cols, (i + 1) * self.cols)]
            for rw in range(self.rows):
                for cl in range(self.cols):
                    if self.grid[rw][cl]:
                        color = self.on_cell_color
                        self.on_cells += 1
                    else:
                        color = self.off_cell_color
                        self.off_cells += 1
                    self.put_rect(rw, cl, color)
        self.update_canvas()
        self.in_tick = False
        self.tick_count += 1
        self.addr_count += 3
        self.update_labels()
        self.btc_hunter()
        if self.is_active:
            self.BH16x16.after(self.tick_delay, self.tick)
    
    def btc_hunter(self):
        arr = np.array(self.grid)
        binstring = ''.join(''.join(map(str, l)) for l in arr)
        self.binstring_update.config(text = binstring)
        self.binstring_update.update()
        dec = int(binstring, 2)
        self.decstring_update.config(text = dec)
        self.decstring_update.update()
        HEX = hex(int(binstring, 2))
        self.hexstring_update.config(text = HEX)
        self.hexstring_update.update()
        caddr = ice.privatekey_to_address(0, True, dec)
        uaddr = ice.privatekey_to_address(0, False, dec)
        HEX = "%064x" % dec
        wifc = ice.btc_pvk_to_wif(HEX)
        wifu = ice.btc_pvk_to_wif(HEX, False)
        self.caddrstring_update.config(text = caddr)
        self.caddrstring_update.update()
        self.wifcstring_update.config(text = wifc)
        self.wifcstring_update.update()
        self.uaddrstring_update.config(text = uaddr)
        self.uaddrstring_update.update()
        self.wifustring_update.config(text = wifu)
        self.wifustring_update.update()
        p2sh = ice.privatekey_to_address(1, True, dec)
        self.p2shstring_update.config(text = p2sh)
        self.p2shstring_update.update()
        bech32 = ice.privatekey_to_address(2, True, dec)
        self.bech32string_update.config(text = bech32)
        self.bech32string_update.update()
        if caddr in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBinary Data: \n {binstring} \n")
            with open("foundcaddr.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            
        if uaddr in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu} \nBinary Data: \n {binstring} \n")
            with open("found.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            
        if p2sh in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh} \nBinary Data: \n {binstring} \n")
            with open("found.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            
        if bech32 in bloom_filterbtc:
            self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Bc1: {bech32} \nBinary Data: \n {binstring} \n")
            with open("found.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            
    def init_grid(self):
        self.grid = [[0 for x in range(self.cols)] for y in range(self.rows)]

    def start(self):
        self.init_grid()
        self.init_tk()
        self.clear_canvas()
        self.BH16x16.mainloop()
        self.BH16x16.destroy()
        
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
        self.btc_hunter()
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
            
    def update_grid(self):
        hex_value = self._txt_inputhex.get()
        try:
            int_value = int(hex_value, 16)
            binstring = "{0:b}".format(int_value)
            binstring = binstring.rjust(self.rows * self.cols, "0")
            for i in range(self.rows):
                self.grid[i] = [int(binstring[j]) for j in range(i * self.cols, (i + 1) * self.cols)]
                for rw in range(self.rows):
                    for cl in range(self.cols):
                        if self.grid[rw][cl]:
                            color = self.on_cell_color
                            self.on_cells += 1
                        else:
                            color = self.off_cell_color
                            self.off_cells += 1
                        self.put_rect(rw, cl, color)
            self.btc_hunter()
        except ValueError:
            tkinter.messagebox.showerror("Invalid Hex Value", "Please enter a valid hexadecimal value")

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
        self.addr_count += 3
        self.update_labels()
        self.btc_hunter()

        if self.is_active:
            self.BH16x16.after(self.tick_delay, self.tick)

    def popwinner(self):
        self.popwin = Toplevel()
        self.popwin.title("BitcoinHunter 16x16.py")
        self.popwin.geometry("700x250")
        self.widget_text = tkinter.Label(self.popwin, compound='top')
        self.widget_text['text'] = "© MIZOGG 2018 - 2023"
        self.widget_text.place(x=380,y=180)
        self.widgetwin2pop = tkinter.Label(self.popwin, compound='top')
        self.widgetwin2pop['text'] = "!!!! CONGRATULATIONS !!!!!"
        self.widgetwin2pop.place(x=10,y=165)
        self.editAreapop = tkst.ScrolledText(master = self.popwin, wrap = tkinter.WORD, width  = 70, height = 6,font=("Arial",12))
        self.editAreapop.pack(padx=10, pady=10)
        self.editAreapop.insert(tkinter.INSERT, self.WINTEXT)
        self.framewinpop = Frame(self.popwin)
        self.framewinpop.pack(padx=10, pady=10)
        self.buttonwinpop = Button(self.framewinpop, text=" Close ", command=self.popwin.destroy)
        self.buttonwinpop.grid(row=0, column=1)
    
    def CLOSEWINDOW(self):
        self.BH16x16.destroy()
        self.BH16x16 = None

if __name__ == '__main__':
    hunter_16x16 = App()
    hunter_16x16.start()