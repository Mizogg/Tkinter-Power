#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 25.08.2023 https://t.me/CryptoCrackersUK
import random, sys, os
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import mizlib as MIZ
import psutil

information16x16 = ('''
            Look for Bitcoin with tkinter and python in GUI.
 
 16x16Hunter is a simple implementation of a cellular automaton, inspired by the classic game of Life. 
 Each cell has two states, on and off, and the state of each cell is determined by the states of its eight neighboring cells according to a set of rules.
 By setting the initial state of the cells and then letting the automaton run, complex patterns and behavior can emerge.
 
 In this implementation, you canedit the grid by clicking on cells to toggle their state, or by using the options in the Grid Options frame.
 You can start, pause, and step through the automaton using the Play Options frame. 
 You can adjust the speed of the automaton using the Speed frame, and set the initial seed of the random generator using the Random Seed frame. 
 You can also set the rules of the automaton using the Rule frame. 
 The Info frame displays information about the current state of the automaton, including the current tick,
 the number of on and off cells, and the binary, decimal, and hexadecimal representations of the current state.
 
 In addition, you can enter a hexadecimal value in the Enter hex value field and click the Update grid button to set the grid to the corresponding state. 
 This can be useful for exploring specific patterns or behavior.
 
 16x16Hunter was developed by Mizogg as a fun and educational project. The code is available on [GitHub/https://github.com/Mizogg/Tkinter-Power] for anyone to use or modify. If you have any questions or suggestions, feel free to contact me at [https://t.me/CryptoCrackersUK]. 
            
            Check out more of my programs.[Website/https://mizogg/.co.uk]
 
 
                        16x16Hunter
                    Made By Mizogg.co.uk
            Added Visualize Your own Private Key
                    
                    
                        Version = 1.2
                Top Level Fixed CPU and Ram added

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
        #self.BH16x16.iconbitmap('images/miz.ico')
        self.BH16x16.geometry("1260x760")
        self.BH16x16.menubar = Menu(self.BH16x16)
        self.BH16x16.filemenu = Menu(self.BH16x16.menubar, tearoff=0)
        self.BH16x16.filemenu.add_separator()
        self.BH16x16.filemenu.add_command(label="Exit", command=self.BH16x16.quit)
        self.BH16x16.menubar.add_cascade(label="File", menu=self.BH16x16.filemenu)
        self.BH16x16.helpmenu = Menu(self.BH16x16.menubar, tearoff=0)
        self.BH16x16.helpmenu.add_command(label="Help Telegram Group", command=MIZ.opentelegram)
        self.BH16x16.helpmenu.add_command(label="Mizogg Website", command=MIZ.openweb)
        self.BH16x16.helpmenu.add_command(label="About Bit16x16", command=self.startpop)
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
        self.canvas.grid(row=0, columnspan=6, padx=5, pady=3)
        self.canvas.bind('<Button-1>', self.canvas_click)
        self.content1 = Frame(self.main_frame, padding=(3))
        self.content1.grid(row =0, column=7)
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
        self.hunter_win = tkinter.Frame(self.content1, bg = '#A1A1A1')
        self.hunter_win.pack(fill='both', expand='yes')
        self.Binary_data = "Binary Data"
        self.Binarylable = tkinter.Label(self.hunter_win, text=self.Binary_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.binstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.binstring_update.pack(padx=10, pady=2)
        self.DEC_data = "Private Key Dec"
        self.DEClable = tkinter.Label(self.hunter_win, text=self.DEC_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.decstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.decstring_update.pack(padx=10, pady=2)
        self.HEX_data = "Private Key HEX"
        self.HEXlable = tkinter.Label(self.hunter_win, text=self.HEX_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.hexstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.hexstring_update.pack(padx=10, pady=2)
        self.caddr_data = "Address Compressed"
        self.caddrlable = tkinter.Label(self.hunter_win, text=self.caddr_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.caddrstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.caddrstring_update.pack(padx=10, pady=2)
        self.wifc_data = "WIF Compressed"
        self.wifclable = tkinter.Label(self.hunter_win, text=self.wifc_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.wifcstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.wifcstring_update.pack(padx=10, pady=2)
        self.uaddr_data = "Address Uncompressed"
        self.uaddrlable = tkinter.Label(self.hunter_win, text=self.uaddr_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.uaddrstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.uaddrstring_update.pack(padx=10, pady=2)
        self.wifu_data = "WIF Uncompressed"
        self.wifulable = tkinter.Label(self.hunter_win, text=self.wifu_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.wifustring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.wifustring_update.pack(padx=10, pady=2)
        self.p2sh_data = "Address P2SH"
        self.p2shlable = tkinter.Label(self.hunter_win, text=self.p2sh_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.p2shstring_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.p2shstring_update.pack(padx=10, pady=2)
        self.bc1_data = "Address P2WPKH"
        self.bc1lable = tkinter.Label(self.hunter_win, text=self.bc1_data, font=("Arial",10),bg='#A1A1A1',fg="Black").pack(padx=10, pady=3)
        self.bech32string_update = tkinter.Label(self.hunter_win, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Purple")
        self.bech32string_update.pack(padx=10, pady=2)
        self.addcount = tkinter.Label(self.BH16x16, text=MIZ.countadd(), font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=540,y=680)
        self.lbl_tickno = tkinter.Label(self.hunter_win, text='Total Private Keys Scanned : 0', font=("Arial",10),bg='#A1A1A1',fg="Purple")
        self.lbl_tickno.pack(padx=3, pady=3)
        self.lbl_totalno = tkinter.Label(self.hunter_win, text='Total Addresses Scanned : 0', font=("Arial",10),bg='#A1A1A1',fg="Purple")
        self.lbl_totalno.pack(padx=3, pady=3)
        self.cpu_label = tkinter.Label(self.BH16x16,font = ('calibri', 14, 'bold'), bg= '#F0F0F0', fg= 'red')
        self.cpu_label.place(x=580,y=720)
        self.ram_label = tkinter.Label(self.BH16x16,font = ('calibri', 14, 'bold'), bg= '#F0F0F0', fg= 'red')
        self.ram_label.place(x=740,y=720)
        self.ram_free_label = tkinter.Label(self.BH16x16,font = ('calibri', 14, 'bold'), bg= '#F0F0F0', fg= 'red')
        self.ram_free_label.place(x=900,y=720)
        input_win = tkinter.Frame(self.hunter_win, bg = '#A1A1A1')
        input_win.pack(fill='both', expand='yes')
        self._txt_inputhex = tkinter.Entry(input_win, width=56, font=("Arial",10))
        self._txt_inputhex.insert(0, '1')
        self._txt_inputhex.pack(padx=10, pady=3)
        self._txt_inputhex.focus()
        self._btc_bin = tkinter.Button(input_win, text="Visualize You Own Private Key", font=("Arial",10), command=self.update_grid)
        self._btc_bin.pack(padx=10, pady=3)
        self.cpu_met()
        # =============================================================================
        # about_frame
        # =============================================================================
        self.about16 = tkinter.Frame(master = self.about_frame, bg = '#F0F0F0')
        self.about16.pack(fill='both', expand='yes')
        self.editArea16 = tkst.ScrolledText(master = self.about16, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        self.editArea16.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        self.editArea16.insert(tkinter.INSERT, information16x16)
        
        self.jump_increment_combobox = Combobox(self.main_frame, textvariable=self.jump_increment_var, values=self.jump_increments)
        self.jump_increment_combobox.grid(row=2, column=0, sticky=E)
        self.jump_forward_active = False
        self.btn_start_jump_forward = tkinter.Button(self.main_frame, text='Start Jump Forward', command=self.start_jump_forward, fg='purple')
        self.btn_start_jump_forward.grid(row=3, column=1)
        self.btn_stop_jump_forward = tkinter.Button(self.main_frame, text='Stop Jump Forward', command=self.stop_jump_forward, fg='red')
        self.btn_stop_jump_forward.grid(row=3, column=2)

        self.jump_backward_active = False
        self.btn_start_jump_backward = tkinter.Button(self.main_frame, text='Start Jump Backward', command=self.start_jump_backward, fg='purple')
        self.btn_start_jump_backward.grid(row=4, column=1)
        self.btn_stop_jump_backward = tkinter.Button(self.main_frame, text='Stop Jump Backward', command=self.stop_jump_backward, fg='red')
        self.btn_stop_jump_backward.grid(row=4, column=2)
        

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

    
    #######    
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
        MIZ.btc_hunter(self)
        if self.is_active:
            self.BH16x16.after(self.tick_delay, self.tick)
        
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
            MIZ.btc_hunter(self)
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
        MIZ.btc_hunter(self)
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
            MIZ.btc_hunter(self)
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
        MIZ.btc_hunter(self)

        if self.is_active:
            self.BH16x16.after(self.tick_delay, self.tick)

    def popwinner(self):
        self.popwin = Toplevel()
        self.popwin.title("BitcoinHunter 16x16.py")
        #self.popwin.iconbitmap('images/miz.ico')
        self.popwin.geometry("700x250")
        self.widgetwinpop = tkinter.Label(self.popwin, compound='top')
        self.widgetwinpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetwinpop['text'] = "© MIZOGG 2018 - 2022"
        self.widgetwinpop['image'] = self.widgetwinpop.miz_image_png
        self.widgetwinpop.place(x=380,y=180)
        self.widgetwin2pop = tkinter.Label(self.popwin, compound='top')
        self.widgetwin2pop.miz_image_png = tkinter.PhotoImage(file='images/congratulations.gif')
        self.widgetwin2pop['image'] = self.widgetwin2pop.miz_image_png
        self.widgetwin2pop.place(x=10,y=165)
        self.editAreapop = tkst.ScrolledText(master = self.popwin, wrap = tkinter.WORD, width  = 70, height = 6,font=("Arial",12))
        self.editAreapop.pack(padx=10, pady=10)
        self.editAreapop.insert(tkinter.INSERT, self.WINTEXT)
        self.framewinpop = Frame(self.popwin)
        self.framewinpop.pack(padx=10, pady=10)
        self.buttonwinpop = Button(self.framewinpop, text=" Close ", command=self.popwin.destroy)
        self.buttonwinpop.grid(row=0, column=1)
        
    def startpop(self):
        self.pop = Toplevel()
        self.pop.title("16x16.py")
        #self.pop.iconbitmap('images/miz.ico')
        self.pop.geometry("700x250")
        self.widgetpop = tkinter.Label(self.pop, compound='top')
        self.widgetpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetpop['text'] = "© MIZOGG 2018 - 2022"
        self.widgetpop['image'] = self.widgetpop.miz_image_png
        self.widgetpop.place(x=220,y=180)
        self.label = tkinter.Label(self.pop, text='Welcome to 16x16.py...... \n\n Made By Mizogg.co.uk \n\n Version 1.3 02/01/23').pack(pady=10)
        self.label1 = tkinter.Label(self.pop, text= "This window will get closed after 2 seconds...", font=('Helvetica 8 bold')).pack(pady=10)
        self.framepop = Frame(self.pop)
        self.framepop.pack(pady=10)
        self.buttonpop = Button(self.framepop, text=" Close ", command=self.CLOSEWINDOW)
        self.buttonpop.grid(row=0, column=1)
        self.pop.after(2000,lambda:self.pop.destroy())
    
    def CLOSEWINDOW(self):
        self.pop.destroy()

if __name__ == '__main__':
    hunter_16x16 = App()
    hunter_16x16.start()
