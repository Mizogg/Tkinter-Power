#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 20.11.2022 https://t.me/CryptoCrackersUK
from tkinter import * 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
from time import strftime, sleep
import random, sys, os
import string
import psutil
import mizlib as MIZ
import math
def RandomInteger(minN, maxN):
    return random.randrange(minN, maxN)
    
def random_word_results(self, mnem):
    global total, totaladd
    wordvar = tkinter.StringVar()
    wordvar.set(mnem)
    wordvartext = tkinter.StringVar()
    wordvartext1 = MIZ.rwonline(self, mnem)
    wordvartext.set(wordvartext1)
    self.word_update.config(textvariable = wordvar, relief='flat')
    self.word_update1.config(textvariable = wordvartext, relief='flat')
    self.word_update1.update()
    self.word_update.update()
    total+=1
    totaladd+=1
    self.totalC.config(text = f'{total}')
    self.totalA.config(text = f'{totaladd}')
# ============================================================================= 
information = ('''
https://en.wikipedia.org/wiki/Bitcoin

Bitcoin (Abbreviation: BTC; sign: ₿) is a decentralized digital currency that can be transferred 
on the peer-to-peer bitcoin network.Bitcoin transactions are verified by network nodes through 
cryptography and recorded in a public distributed ledger called a blockchain. 
The cryptocurrency was invented in 2008 by an unknown person or group of people using the name Satoshi Nakamoto.

The currency began use in 2009, when its implementation was released as open-source software.

Bitcoin has been described as an economic bubble by at least eight Nobel Memorial Prize in Economic Sciences recipients.

The word bitcoin was defined in a white paper published on 31 October 2008. 
It is a compound of the words bit and coin. No uniform convention for bitcoin capitalization exists; 
some sources use Bitcoin, capitalized, to refer to the technology and network and bitcoin, lowercase, 
for the unit of account.[15] The Wall Street Journal, The Chronicle of Higher Education, 
and the Oxford English Dictionary advocate the use of lowercase bitcoin in all cases.

The legality of bitcoin varies by region. Nine countries have fully banned bitcoin use, 
while a further fifteen have implicitly banned it. A few governments have used bitcoin in some capacity. 
El Salvador has adopted Bitcoin as legal tender, although use by merchants remains low. 
Ukraine has accepted cryptocurrency donations to fund the resistance to the 2022 Russian invasion. 
Iran has used bitcoin to bypass sanctions.

The unit of account of the bitcoin system is the bitcoin. Currency codes for representing bitcoin are BTC and XBT.
Its Unicode character is ₿. One bitcoin is divisible to eight decimal places. 
Units for smaller amounts of bitcoin are the millibitcoin (mBTC), equal to 1⁄1000 bitcoin, and the satoshi (sat), 
which is the smallest possible division, and named in homage to bitcoin's creator, representing 1⁄100000000 (one hundred millionth) bitcoin.
 100,000 satoshis are one mBTC.
''')

creditsinfo = ('''
                Look for Bitcoin with tkinter and python in GUI.
                        Made By Mizogg.co.uk
                    Version = 1.9 (1087 Lines of code)
                        NEW CALCULATOR  added 
                    
                    Version = 1.8 (1422 Lines of code) 
                New features added to Brain Wallet Generator
                    New features added to Bitcoin Generator

                            Version = 1.7
                New Conversion BITS to HEX DEC Binary
                Plus and Minus Ranges in conversion
                Updates to brain and Words auto start input
            Input start and stop Decimal main Bitcoin Generator
        1 Brain word from list TODO make stop function on 1 Brain

                    Version = 1.6 (1654 Lines of code) 
                    16x16Hunter speed improvements
                Other Fixes and code reduced in size
                    removed Puzzle Tab and block game
                        
                            Version = 1.5
                        16x16Hunter added Offline

                            Version = 1.4
                            Pop Up boxes

                            Version = 1.3
                        Mnemonic added NEW Feature
                    Added Random Button To Convertor Tab
            Added Start and Stop to Brain Wallet also Added Input screen
                        Puzzle page Updated

                Version = 1.2 (3100 Lines of code) 
                    Added Brain Online and Oflline
                        Added Conversion Tools
                        Added Atomic Wallet API
                Big Thanks TO @Clintsoff and CryptoCrackers
            More Information and help please check links in menu help !!!
''')

# Database Load and Files
mylist = []
 
with open('files/words.txt', newline='', encoding='utf-8') as f:
    for line in f:
        mylist.append(line.strip())
startdec = 1
stopdec = 115792089237316195423570985008687907852837564279074904382605163141518161494336
totaladd = total = found =0
run = run1 = run2 = True

class MainWindow():
    def __init__(self):
        self.found = found
        self.run = run
        self.fact = 1
        def start2():
           global run2
           run2= True
        def stop2():
           global run2
           run2= False
        #  Mnemonic Program Main
        def word_results_online(rnds):
            global total, totaladd
            mnem = MIZ.create_valid_mnemonics(strength=int(rnds))
            wordvar = tkinter.StringVar()
            wordvar.set(mnem)
            wordvartext = tkinter.StringVar()
            wordvartext1 = MIZ.rwonline(self, mnem)
            wordvartext.set(wordvartext1)
            self.word_update.config(textvariable = wordvar, relief='flat')
            self.word_update1.config(textvariable = wordvartext, relief='flat')
            self.word_update.update()
            self.word_update1.update()
            total+=1
            totaladd+=1
            self.totalC.config(text = f'{total}')
            self.totalA.config(text = f'{totaladd}')
        
        def Random_word_online():
            while run2:
                rnds = '16'
                word_results_online(rnds)
                
        def Random_word_online1():
            while run2:
                rnds = '32'
                word_results_online(rnds)
                
        def Random_word_online2():
            while run2:
                rnds = '64'
                word_results_online(rnds)
                
        def Random_word_online3():
            while run2:
                rnds = '96'
                word_results_online(rnds)
                
        def Random_word_online4():
            while run2:
                rnds = '128'
                word_results_online(rnds)
                
        def Random_word_online5():
            while run2:
                rnds = '160'
                word_results_online(rnds)
                
        def Random_word_online6():
            while run2:
                rnds = '192'
                word_results_online(rnds)
                
        def Random_word_online7():
            while run2:
                rnds = '224'
                word_results_online(rnds)
                
        def Random_word_online8():
            while run2:
                rnds = '256'
                word_results_online(rnds)

        def word_results_offline(rnds):
            global total, totaladd
            mnem = MIZ.create_valid_mnemonics(strength=int(rnds))
            wordvar = tkinter.StringVar()
            wordvar.set(mnem)
            wordvartext = tkinter.StringVar()
            wordvartext1 = MIZ.rwoffline(self, mnem)
            wordvartext.set(wordvartext1)
            self.word_update.config(textvariable = wordvar, relief='flat')
            self.word_update1.config(textvariable = wordvartext, relief='flat')
            self.word_update.update()
            self.word_update1.update()
            total+=1
            totaladd+=3
            self.totalC.config(text = f'{total}')
            self.totalA.config(text = f'{totaladd}')

        def Random_word_offline():
            while run2:
                rnds = '16'
                word_results_offline(rnds)

        def Random_word_offline1():
            while run2:
                rnds = '32'
                word_results_offline(rnds)

        def Random_word_offline2():
            while run2:
                rnds = '64'
                word_results_offline(rnds)

        def Random_word_offline3():
            while run2:
                rnds = '96'
                word_results_offline(rnds)

        def Random_word_offline4():
            while run2:
                rnds = '128'
                word_results_offline(rnds)

        def Random_word_offline5():
            while run2:
                rnds = '160'
                word_results_offline(rnds)

        def Random_word_offline6():
            while run2:
                rnds = '192'
                word_results_offline(rnds)

        def Random_word_offline7():
            while run2:
                rnds = '224'
                word_results_offline(rnds)

        def Random_word_offline8():
            while run2:
                rnds = '256'
                word_results_offline(rnds)
        #  Main Window Program Menu Bar
        self._window = tkinter.Tk()
        self._window.title("BitHunter.py @ Mizogg.co.uk")
        self._window.iconbitmap('images/miz.ico')
        self._window.config(bg="black")
        self._window.geometry("860x660")
        self._window.resizable(False, False)
        self._window.menubar = Menu(self._window)
        self._window.filemenu = Menu(self._window.menubar, tearoff=0)
        # self._window.filemenu.add_command(label="New", command=MIZ.donothing)
        # self._window.filemenu.add_command(label="Edit", command=MIZ.donothing)
        # self._window.filemenu.add_command(label="Save", command=MIZ.donothing)
        self._window.filemenu.add_separator()
        self._window.filemenu.add_command(label="Exit", command=self._window.quit)
        self._window.menubar.add_cascade(label="File", menu=self._window.filemenu)
        self._window.helpmenu = Menu(self._window.menubar, tearoff=0)
        self._window.helpmenu.add_command(label="Help Telegram Group", command=MIZ.opentelegram)
        self._window.helpmenu.add_command(label="Mizogg Website", command=MIZ.openweb)
        self._window.helpmenu.add_command(label="About BitHunter", command=self.startpop)
        self._window.menubar.add_cascade(label="Help", menu=self._window.helpmenu)
        self._window.config(menu=self._window.menubar)
        self.my_notebook = ttk.Notebook(self._window)
        self.my_notebook.pack(pady=5)
        self.main_frame = Frame(self.my_notebook, width=840, height=620)
        self.bitcoin_frame = Frame(self.my_notebook, width=840, height=620)
        self.brain_frame = Frame(self.my_notebook, width=840, height=620)
        self.word_frame = Frame(self.my_notebook, width=840, height=620)
        self.about_frame = Frame(self.my_notebook, width=840, height=620)
        self.credits_frame = Frame(self.my_notebook, width=840, height=620)
        self.windowcal = Frame(self.my_notebook, width=840, height=620)
        self.main_frame.pack(fill="both", expand=1)
        self.bitcoin_frame.pack(fill="both", expand=1)
        self.brain_frame.pack(fill="both", expand=1)
        self.word_frame.pack(fill="both", expand=1)
        self.about_frame.pack(fill="both", expand=1)
        self.credits_frame.pack(fill="both", expand=1)
        self.windowcal.pack(fill="both", expand=1)
        self.my_notebook.add(self.bitcoin_frame, text="Bitcoin Hunting")
        self.my_notebook.add(self.main_frame, text="Conversion Tools ")
        self.my_notebook.add(self.windowcal, text="Calulator")
        self.my_notebook.add(self.brain_frame, text="Brain Hunting")
        self.my_notebook.add(self.word_frame, text="Mnemonic Hunting")
        self.my_notebook.add(self.about_frame, text="About Bitcoin")
        self.my_notebook.add(self.credits_frame, text="Credits")
        # Calulator Tab
        self.text_valuecal = tkinter.StringVar()
        self.textoperator = tkinter.StringVar()
        self.textoperator2 = tkinter.StringVar()
        self.plus = tkinter.Button(self.windowcal,text="+",width=4,font=("arial",15,"bold"),fg="purple",bg="#F0F0F0", activebackground="#F0F0F0", command=lambda : self.opr("+"), relief=RAISED, bd=3).place(x=470,y=110)
        self.subs = tkinter.Button(self.windowcal, text="-", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("-"), relief=RAISED, bd=3).place(x=470, y=170)
        self.mul = tkinter.Button(self.windowcal, text="X", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("X"), relief=RAISED, bd=3).place(x=545, y=110)
        self.div = tkinter.Button(self.windowcal, text="/", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("/"), relief=RAISED, bd=3).place(x=545, y=170)
        self.rad = tkinter.Button(self.windowcal, text="Radian", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Radian"), relief=RAISED, bd=3).place(x=690, y=260)
        self.reci = tkinter.Button(self.windowcal, text="1/x", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Reciprocal"), relief=RAISED, bd=3).place(x=230, y=260)
        self.sqr = tkinter.Button(self.windowcal, text="X^2", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Square"), relief=RAISED, bd=3).place(x=367, y=260)
        self.cube = tkinter.Button(self.windowcal, text="X^3", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Cube"), relief=RAISED, bd=3).place(x=367, y=310)
        self.equal = tkinter.Button(self.windowcal, text="=", width=11, font=("arial", 18, "bold"), fg="green",bg="#F0F0F0", activebackground="#F0F0F0",command=self.evaluation_opr, relief=RAISED, bd=3, ).place(x=640, y=130)
        self.braincal = tkinter.Button(self.windowcal, text="Sum to Brain Wallet", width=16, font=("arial", 12, "bold"), fg="green",bg="#F0F0F0", activebackground="#F0F0F0",command=self.Random_brain_cal, relief=RAISED, bd=3, ).place(x=630, y=195)
        self.clear = tkinter.Button(self.windowcal, text="Information", width=11, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="purple",bg="#F0F0F0",command=self.informationcal, relief=RAISED, bd=3).place(x=680, y=90)
        self.sqrt = tkinter.Button(self.windowcal, text="Square root", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Square root"), relief=RAISED, bd=3).place(x=432, y=260)
        self.cubert = tkinter.Button(self.windowcal, text="Cube root", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Cube root"), relief=RAISED, bd=3).place(x=432, y=310)
        self.log2 = tkinter.Button(self.windowcal, text="log2", width=8, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("log2"), relief=RAISED, bd=3).place(x=580, y=260)
        self.log10 = tkinter.Button(self.windowcal, text="log10", width=8, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("log10"), relief=RAISED, bd=3).place(x=580, y=310)
        self.exponent = tkinter.Button(self.windowcal, text="e^x", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Exponent"), relief=RAISED, bd=3).place(x=300, y=260)
        self.power = tkinter.Button(self.windowcal, text="X^Y", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("x^y"), relief=RAISED, bd=3).place(x=300, y=310)
        self.factorial = tkinter.Button(self.windowcal, text="n!", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Factorial"), relief=RAISED, bd=3).place(x=15, y=310)
        self.mod = tkinter.Button(self.windowcal, text="Modulus", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("Modulus"), relief=RAISED, bd=3).place(x=690, y=310)
        self.reset = tkinter.Button(self.windowcal, text="Reset", width=5, font=("arial", 13, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=self.reset_now, relief=RAISED, bd=3).place(x=520, y=218)
        self.sin = tkinter.Button(self.windowcal, text="sin", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("sin"), relief=RAISED, bd=3).place(x=90 ,y=310)
        self.cos = tkinter.Button(self.windowcal, text="cos", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("cos"), relief=RAISED, bd=3).place(x=15, y=260)
        self.tan = tkinter.Button(self.windowcal, text="tan", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("tan"), relief=RAISED, bd=3).place(x=90, y=260)
        self.cot = tkinter.Button(self.windowcal, text="cot", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("cot"), relief=RAISED, bd=3).place(x=160, y=260)
        self.lcm = tkinter.Button(self.windowcal, text="LCM", width=4, font=("arial", 15, "bold"), bg="#F0F0F0", fg="purple", activebackground="#F0F0F0",command=lambda : self.opr("lcm"), relief=RAISED, bd=3).place(x=160, y=310)
        self.hcf = tkinter.Button(self.windowcal, text="HCF", width=4, font=("arial", 15, "bold"), bg="#F0F0F0", fg="purple", activebackground="#F0F0F0",command=lambda : self.opr("hcf"), relief=RAISED, bd=3).place(x=230, y=310)
        self.result_name = tkinter.Label(self.windowcal, text="Result: ", width=8, font=("arial", 16, "bold", "italic"),fg="black",bg="#F0F0F0").place(x=340, y=360)
        self.result = tkinter.Entry(self.windowcal,font=("Helvetica",20,"bold","italic"),textvar=self.text_valuecal, bd=5, width=52, relief=SUNKEN, disabledbackground="white", foreground="purple")
        self.result.place(x=10,y=390)
        tkinter.Label(self.windowcal, text="Number 1 ",width=8, font=("arial", 15, "bold","italic"),bg="#F0F0F0",fg="black").place(x=10, y=115)
        self.number1 = tkinter.Entry(self.windowcal,width=24,bg="#3d3d3d",font=("arial",16,"bold","italic"), insertbackground="gold",fg="gold",bd=3,relief=SUNKEN)
        self.number1.place(x=130,y=115)
        self.number1.focus()
        tkinter.Label(self.windowcal, text="Number 2 ", width=8, font=("arial", 16, "bold", "italic"),fg="black", bg="#F0F0F0").place(x=10, y=195)
        self.number2 = tkinter.Entry(self.windowcal, width=24, bg="#3d3d3d", font=("arial", 16, "bold", "italic"), insertbackground="gold",fg="gold", relief=SUNKEN, bd=4)
        self.number2.place(x=130, y=195)
        self.operator_name = tkinter.Label(self.windowcal, text="Operation ", width=12, font=("arial", 16, "bold", "italic"), bg="#F0F0F0", fg="#d96b6b").place(x=10, y=155)
        self.operator = tkinter.Entry(self.windowcal, width=12, font=("arial", 16, "bold", "italic"), disabledbackground="#3d3d3d",disabledforeground="gold",state="disable",textvar=self.textoperator,bd=5,relief=SUNKEN)
        self.operator.place(x=250, y=155)
        self.brain_updatecal1 = tkinter.Label(self.windowcal, bg="#F0F0F0",font=("Arial",10),text="")
        self.brain_updatecal1.place(x=160,y=440)
        #  Main Tab
        self.labeltype = tkinter.Label(self.main_frame, text=" Type \n Data \n Here ", font=("Consolas", 16)).place(x=5,y=70)
        self._txt_input = tkinter.Entry(self.main_frame, width=56, font=("Consolas", 16))
        self._txt_input.insert(0, '10101')
        self._txt_input.place(x=80,y=100)
        self._txt_input.focus()
        self._btc_bin = tkinter.Button(self.main_frame, text="Bin", font=("Consolas", 16), command=self.evt_btc_bin).place(x=300,y=150)
        self._btc_dec = tkinter.Button(self.main_frame, text="Dec", font=("Consolas", 16), command=self.evt_btc_dec).place(x=360,y=150)
        self._btc_bit = tkinter.Button(self.main_frame, text="Bits", font=("Consolas", 16), command=self.evt_btc_bit).place(x=480,y=150)
        self._btc_hex = tkinter.Button(self.main_frame, text="Hex", font=("Consolas", 16), command=self.evt_btc_hex).place(x=420,y=150)
        self._rd_dec = tkinter.Button(self.main_frame, text="Random", font=("Consolas", 16), command=self.evt_rd_dec).place(x=15,y=150)
        self._jump_input = tkinter.Entry(self.main_frame, width=4, font=("Consolas", 16), fg='red')
        self._jump_input.insert(0, '1')
        self._jump_input.place(x=170,y=150)
        self._jump_input.focus()
        self._jump1_dec = tkinter.Button(self.main_frame, text=" + ", font=("Consolas", 16), command=self.evt_jump1_dec, fg='green').place(x=230,y=150)
        self._jump_dec = tkinter.Button(self.main_frame, text=" - ", font=("Consolas", 16), command=self.evt_jump_rm1_dec, fg='red').place(x=110,y=150)
        self.labeladdr = tkinter.Label(self.main_frame, text=" When Searching for adress \n it will generate \n a random private key \n this will not match the address ", font=("Arial", 8), fg='red').place(x=670,y=135)
        self._bt_ip = tkinter.Button(self.main_frame, text="Address", font=("Consolas", 16), command=self.evt_btc_add).place(x=570,y=150)
        self.labelbin = tkinter.Label(self.main_frame, text="  Binary ", font=("Consolas", 16)).place(x=5,y=200)
        self._stringvar_bin = tkinter.StringVar()
        self.txt_outputbin = tkinter.Entry(self.main_frame, textvariable=self._stringvar_bin, width=56, font=("Consolas", 16))
        self.txt_outputbin.place(x=130,y=200)
        self.labelbits = tkinter.Label(self.main_frame, text="  Bits ", font=("Consolas", 16)).place(x=730,y=240)
        self._stringvar_bit = tkinter.StringVar()
        self.txt_outputbit = tkinter.Entry(self.main_frame, textvariable=self._stringvar_bit, width=5, font=("Consolas", 16))
        self.txt_outputbit.place(x=745,y=280)
        self.labeldec = tkinter.Label(self.main_frame, text=" Decimal ", font=("Consolas", 16)).place(x=5,y=240)
        self._stringvar_dec = tkinter.StringVar()
        self.txt_outputdec = tkinter.Entry(self.main_frame, textvariable=self._stringvar_dec, width=50, font=("Consolas", 16))
        self.txt_outputdec.place(x=130,y=240)
        self.labelhex = tkinter.Label(self.main_frame, text="Hexadecimal ", font=("Consolas", 16)).place(x=2,y=280)
        self._stringvar_hex = tkinter.StringVar()
        self.txt_outputhex = tkinter.Entry(self.main_frame, textvariable=self._stringvar_hex, width=48, font=("Consolas", 16))
        self.txt_outputhex.place(x=150,y=280)
        self.labelbtca = tkinter.Label(self.main_frame, text=" BTC Address ", font=("Consolas", 16)).place(x=300,y=310)
        self._stringvar_addr = tkinter.StringVar()
        self.txt_outputaddr = tkinter.Label(self.main_frame, textvariable=self._stringvar_addr, font=("Arial", 12))
        self.txt_outputaddr.place(x=20,y=350)
        #  Widgets
        self.widget = tkinter.Label(self._window, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=590,y=30)
        self.widgetsnake = tkinter.Button(self._window, text= "BTC Snake Game ",font=("Arial",10),bg="purple", command= MIZ.opensnake).place(x=30,y=590)
        self.widgetHunter = tkinter.Button(self._window, text= "16x16 BTC Hunter ",font=("Arial",10),bg="gold", command= MIZ.hunter16x16).place(x=690,y=590)
        self.lbl = tkinter.Label(self._window, font = ('calibri', 28, 'bold'), background = '#F0F0F0', foreground = 'purple')
        self.lbl.place(x=10,y=30)
        self.cpu_label = tkinter.Label(self._window,font = ('calibri', 14, 'bold'), background = '#F0F0F0', foreground = 'red')
        self.cpu_label.place(x=190,y=590)
        self.ram_label = tkinter.Label(self._window,font = ('calibri', 14, 'bold'), background = '#F0F0F0', foreground = 'red')
        self.ram_label.place(x=330,y=590)
        self.ram_free_label = tkinter.Label(self._window,font = ('calibri', 14, 'bold'), bg= '#F0F0F0', fg= 'red')
        self.ram_free_label.place(x=490,y=590)
        self.tpk = tkinter.Label(self._window, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=240,y=30)
        self.totalC = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",12),text="")
        self.totalC.place(x=380,y=30)
        self.totaladd = tkinter.Label(self._window, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=240,y=50)
        self.totalA = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",12),text="")
        self.totalA.place(x=380,y=50)
        self.addcount = tkinter.Label(self._window, text=MIZ.countadd(),font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=80,y=80)
        # about_frame
        self.about1 = tkinter.Frame(master = self.about_frame, bg = '#F0F0F0')
        self.about1.pack(fill='both', expand='yes')
        self.pricelable_data = f"Todays Bitcoin Price £ {MIZ.price()} "
        self.pricelable = tkinter.Label(master = self.about1, text=self.pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple")
        self.pricelable.place(x=90, y=530)
        self.editArea = tkst.ScrolledText(master = self.about1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        self.editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        self.editArea.insert(tkinter.INSERT, information)
        # credits_frame
        self.credits1 = tkinter.Frame(master = self.credits_frame, bg = '#F0F0F0')
        self.credits1.pack(fill='both', expand='yes')
        self.pricelable_data = f"Todays Bitcoin Price £ {MIZ.price()} "
        self.pricelable = tkinter.Label(master = self.credits1, text=self.pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple")
        self.pricelable.place(x=90, y=530)
        self.editArea = tkst.ScrolledText(master = self.credits1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        self.editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        self.editArea.insert(tkinter.INSERT, creditsinfo)
        # brain_frame
        self.totalbw = tkinter.Label(self.brain_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=680,y=70)
        self.foundbw = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbw.place(x=740,y=120)
        self.brain_update = tkinter.Entry(self.brain_frame, state='readonly', bg="#F0F0F0",font=("Arial",12),text="", width=80, fg="Red")
        self.brain_update.place(x=30,y=310)
        self.brain_update1 = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",14),text="")
        self.brain_update1.place(x=60,y=350)
        self.start1= tkinter.Button(self.brain_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= self.start, fg='green').place(x=690,y=180)
        self.stop1= tkinter.Button(self.brain_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= self.stop, fg='red').place(x=750,y=180)
        self.labelbrain = tkinter.Label(self.brain_frame, text="Brain \nWords ", font=("Arial",13)).place(x=5,y=75)
        self._txt_inputbrain = tkinter.Entry(self.brain_frame, width=36, font=("Consolas", 16))
        self._txt_inputbrain.insert(0, 'how much wood could a woodchuck chuck if a woodchuck could chuck wood')
        self._txt_inputbrain.place(x=80,y=80)
        self._txt_inputbrain.focus()
        self._txt_brain_ammount = tkinter.Entry(self.brain_frame, width=4, font=("Consolas", 16), fg="red")
        self._txt_brain_ammount.insert(0, '1')
        self._txt_brain_ammount.place(x=130,y=150)
        self._txt_brain_ammount.focus()
        self._txt_brain_total = tkinter.Entry(self.brain_frame, width=4, font=("Consolas", 16), fg="red")
        self._txt_brain_total.insert(0, '12')
        self._txt_brain_total.place(x=130,y=200)
        self._txt_brain_total.focus()
        self._btc_bin = tkinter.Button(self.brain_frame, text="Enter", font=("Consolas", 16), command=self.Random_brain_single).place(x=545,y=75)
        self.titleb = tkinter.Label(self.brain_frame, text="Brain Wallet Words ",font=("Arial",16),bg="#F0F0F0",fg="Black").place(x=380,y=260)
        self.titleerror = tkinter.Label(self.brain_frame, text="!!! Error to be Fixed !!! \n 1 Word from list \n Not stopping  Error !!! ",font=("Arial",8),bg="#F0F0F0",fg="red").place(x=200,y=230)
        self.titlemax = tkinter.Label(self.brain_frame, text="!!! MAX 25 -26 !!!",font=("Arial",12),bg="#F0F0F0",fg="red").place(x=25,y=230)
        self.title1 = tkinter.Label(self.brain_frame, text="Brain Wallet \n Random Generator \n Online & Offline \n Pick Ammount \n to Generate",font=("Arial",8),bg="#F0F0F0",fg="Black").place(x=15,y=150)
        self.my_button = tkinter.Button(self.brain_frame, text= "1 Word List (On-Line) ",font=("Arial",10),bg="#ee6b6e", command= self.Random_brain_online1).place(x=200,y=150)
        self.my_button = tkinter.Button(self.brain_frame, text= "Brain Words (On-Line) ",font=("Arial",10),bg="#A3E4A7", command= self.Random_brain_online).place(x=350,y=150)
        self.my_button = tkinter.Button(self.brain_frame, text= "Brain String (On-Line) ",font=("Arial",10),bg="#F3E4C8", command= self.Random_brain_online2).place(x=510,y=150)
        self.my_button = tkinter.Button(self.brain_frame, text= "1 Word List (Off-Line) ",font=("Arial",10),bg="#ee6b6e", command= self.Random_brain_offline1).place(x=200,y=200)
        self.my_button = tkinter.Button(self.brain_frame, text= "Brain Words (Off-Line) ",font=("Arial",10),bg="#A3E4A7", command= self.Random_brain_offline).place(x=350,y=200)
        self.my_button = tkinter.Button(self.brain_frame, text= "Brain String (Off-Line) ",font=("Arial",10),bg="#F3E4C8", command= self.Random_brain_offline2).place(x=510,y=200)
        # bitcoin_frame
        self.bwg = tkinter.Label(self.bitcoin_frame, text="Bitcoin Wallet Generator ",font=("Arial",20),bg="#F0F0F0",fg="Black").place(x=180,y=100)
        self.bfr = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.bfr.place(x=20,y=280)
        self.labelstart = tkinter.Label(self.bitcoin_frame, text="Start \nDec ", font=("Arial",13)).place(x=5,y=140)
        self._txt_inputstart = tkinter.Entry(self.bitcoin_frame, width=50, font=("Consolas", 16))
        self._txt_inputstart.insert(0, '1')
        self._txt_inputstart.place(x=65,y=145)
        self._txt_inputstart.focus()
        self.labelstop = tkinter.Label(self.bitcoin_frame, text="Stop \nDec ", font=("Arial",13)).place(x=5,y= 180)
        self._txt_inputstop = tkinter.Entry(self.bitcoin_frame, width=50, font=("Consolas", 16))
        self._txt_inputstop.insert(0, stopdec)
        self._txt_inputstop.place(x=65,y=185)
        self._txt_inputstop.focus()
        self.labelmag = tkinter.Label(self.bitcoin_frame, text="Jump \nMag ", font=("Arial",13)).place(x=640,y= 220)
        self._txt_inputmag = tkinter.Entry(self.bitcoin_frame, width=8, font=("Consolas", 16))
        self._txt_inputmag.insert(0, '1')
        self._txt_inputmag.place(x=690,y=225)
        self._txt_inputmag.focus()
        self.r1 = tkinter.Button(self.bitcoin_frame, text=" Generate Random  ",font=("Arial",13),bg="#A3E4D7",command=self.Random_Bruteforce_Speed).place(x=60,y=220)
        self.s1 = tkinter.Button(self.bitcoin_frame, text=" Sequential Start-Stop",font=("Arial",13),bg="#B3B4D7",command=self.Sequential_Bruteforce_speed).place(x=240,y=220)
        self.sb1 = tkinter.Button(self.bitcoin_frame, text=" Backward Stop-Start ",font=("Arial",13),bg="#C3C4D7",command=self.Sequential_Bruteforce_speed_back).place(x=430,y=220)
        self.start= tkinter.Button(self.bitcoin_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= self.start, fg='green').place(x=690,y=180)
        self.stop= tkinter.Button(self.bitcoin_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= self.stop, fg='red').place(x=750,y=180)
        self.totalbtc = tkinter.Label(self.bitcoin_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=680,y=70)
        self.foundbtc = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbtc.place(x=740,y=120)
        self.pricelable_data = f"Todays Bitcoin Price £ {MIZ.price()} "
        self.pricelable = tkinter.Label(self.bitcoin_frame, text=self.pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=90, y=530)
        # word_frame
        self.totalw = tkinter.Label(self.word_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=680,y=70)
        self.foundword = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundword.place(x=740,y=120)
        self.word_update = tkinter.Entry(self.word_frame, state='readonly', bg="#F0F0F0",font=("Arial",12),text="", width=80,fg="Red")
        self.word_update.place(x=30,y=280)
        self.word_update1 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",11),text="")
        self.word_update1.place(x=20,y=300)
        self.start2= tkinter.Button(self.word_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start2, fg='green').place(x=690,y=180)
        self.stop2= tkinter.Button(self.word_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop2, fg='red').place(x=750,y=180)
        self.labelword = tkinter.Label(self.word_frame, text="Mnemonic", font=("Arial",13)).place(x=5,y=75)
        self._txt_inputword = tkinter.Entry(self.word_frame, width=36, font=("Consolas", 16))
        self._txt_inputword.insert(0, 'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon')
        self._txt_inputword.place(x=90,y=80)
        self._txt_inputword.focus()
        self._word_bin = tkinter.Button(self.word_frame, text="Enter", font=("Consolas", 16), command=self.Random_word_single).place(x=545,y=75)
        self.titlem = tkinter.Label(self.word_frame, text="Mnemonic Words ",font=("Arial",16),bg="#F0F0F0",fg="Black").place(x=380,y=250)
        self.titlem1 = tkinter.Label(self.word_frame, text="Random Mnemonic Wallet Generator Online Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=60,y=130)
        self.titlem2 = tkinter.Label(self.word_frame, text="Random Mnemonic Wallet Generator Offline Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=60,y=190)
        self.my_buttonword = tkinter.Button(self.word_frame, text="Random Single", font=("Arial",10),bg="#A3E4A7", command=self.Random_word_random).place(x=690,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "1 Word ",font=("Arial",10),bg="#A3E4A7", command= Random_word_online).place(x=40,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "3 Words ",font=("Arial",10),bg="#A3E4B7", command= Random_word_online1).place(x=100,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "6 Words ",font=("Arial",10),bg="#A3E4C7", command= Random_word_online2).place(x=167,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "9 Words ",font=("Arial",10),bg="#A3E4D7", command= Random_word_online3).place(x=234,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "12 Words ",font=("Arial",10),bg="#A3E4E7", command= Random_word_online4).place(x=301,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "15 Words ",font=("Arial",10),bg="#A3E4F7", command= Random_word_online5).place(x=374,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "18 Words ",font=("Arial",10),bg="#F3E4A8", command= Random_word_online6).place(x=447,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "21 Words ",font=("Arial",10),bg="#F3E4B8", command= Random_word_online7).place(x=520,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "24 Words ",font=("Arial",10),bg="#F3E4C8", command= Random_word_online8).place(x=593,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "1 Word ",font=("Arial",10),bg="#A3E4A7", command= Random_word_offline).place(x=40,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "3 Words ",font=("Arial",10),bg="#A3E4B7", command= Random_word_offline1).place(x=100,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "6 Words ",font=("Arial",10),bg="#A3E4C7", command= Random_word_offline2).place(x=167,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "9 Words ",font=("Arial",10),bg="#A3E4D7", command= Random_word_offline3).place(x=234,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "12 Words ",font=("Arial",10),bg="#A3E4E7", command= Random_word_offline4).place(x=301,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "15 Words ",font=("Arial",10),bg="#A3E4F7", command= Random_word_offline5).place(x=374,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "18 Words ",font=("Arial",10),bg="#F3E4A8", command= Random_word_offline6).place(x=447,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "21 Words ",font=("Arial",10),bg="#F3E4B8", command= Random_word_offline7).place(x=520,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "24 Words ",font=("Arial",10),bg="#F3E4C8", command= Random_word_offline8).place(x=593,y=220)

    def reset_now(self):
        self.textoperator.set(" ")
        self.text_valuecal.set(" ")

    def informationcal(self):
        self.windowcal_informationcal = Toplevel()
        self.windowcal_informationcal.title("Information")
        self.windowcal_informationcal.geometry("540x440")
        self.windowcal_informationcal.iconbitmap('images/miz.ico')
        self.windowcal_informationcal.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.windowcal_informationcal, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=150,y=300)
        infocal = '''
 1.Write number and select operator at first, then click on equal(=) sign.
 
 2.For single digit operation(e.g. rad,exponent,Reciprocal(1/x),
 square,cube,square root,cube root,log,factorial(n!),exponent etc.)
 
 only write number input in the 'Number1' but not write
 input in 'Number2' .After that select favourable operator and go.
 
 3.For single no. operation,if there is present two no. in 'Number1'
 and 'Number2', only input number in 'Number1' will taken.
 '''
        tkinter.Label(self.windowcal_informationcal,fg="black",font=("arial",11,"bold","italic"),text=infocal, bg="#F0F0F0").place(x=5,y=15)
        self.windowcal_informationcal.mainloop()

    def opr(self,work):
        self.work = work
        self.textoperator.set(self.work)

    def evaluation_opr(self):
        self.n1 = (self.number1.get())
        self.n2 = (self.number2.get())
        self.work_done = self.textoperator.get()
        if self.work_done=="+":
            try:
                result_take = eval(self.n1)+eval(self.n2)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="-":
            try:
               result_take = eval(self.n1)-eval(self.n2)
               self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="X":
            try:
                result_take = eval(self.n1)*eval(self.n2)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="/":
            try:
                result_take = eval(self.n1)/eval(self.n2)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except ZeroDivisionError:
                self.text_valuecal.set("Can not divide by zero")
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()

        elif self.work_done=="Reciprocal":
            try:
                result_take = round(1.0/eval(self.n1),2)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except ZeroDivisionError:
                self.text_valuecal.set("Can not divide by zero")
            except:
                tkinter.messagebox.showerror("Input Error","Please write number in the right position.Please read the informationcal carefully")
                self.informationcal()
                self.reset_now()

        elif self.work_done=="Square":
            try:
                result_take = eval(self.n1) ** 2.0
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="Cube":
            try:
               result_take = eval(self.n1) ** 3.0
               self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="Square root":
            try:
                result_take = eval(self.n1)**0.5
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "Cube root":
            try:
                result_take = round(eval(self.n1)**(1/3),2)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()

        elif self.work_done == "Exponent":
            try:
                result_take = math.exp(eval(self.n1))
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="x^y":
            try:
                result_take = eval(self.n1) ** eval(self.n2)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="Factorial":
            try:
                for i in range(1,eval(self.n1)+1):
                    self.fact= self.fact * i
                self.text_valuecal.set(int(self.fact)) if int(self.fact) == self.fact else self.text_valuecal.set(self.fact)

                self.fact=1
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="lcm":
            try:
                if eval(self.n1)>eval(self.n2):
                    result_take = (eval(self.n1)*eval(self.n2))/math.gcd(eval(self.n1),eval(self.n2))
                    self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
                else:
                    result_take = (eval(self.n2)*eval(self.n1))/math.gcd(eval(self.n2),eval(self.n1))
                    self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done=="hcf":
            try:
                if eval(self.n1) > eval(self.n2):
                    result_take = math.gcd(eval(self.n1),eval(self.n2))
                    self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
                else:
                    result_take = math.gcd(eval(self.n2), eval(self.n1))
                    self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "log2":
            try:
                result_take = math.log2(eval(self.n1))
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "log10":
            try:
                result_take = math.log10(eval(self.n1))
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "Modulus":
            try:
                result_take = eval(self.n1)%eval(self.n2)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "Radian":
            try:
                self.text_valuecal.set(round(math.radians(eval(self.n1)),3))
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "sin":
            try:
                result_take = round(math.sin(math.radians(eval(self.n1))),1)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "cos":
            try:
                result_take = round(math.cos(math.radians(eval(self.n1))),1)
                self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "tan":
            try:
                if eval(self.n1) == 90:
                    self.text_valuecal.set("Infinite")
                else:
                    result_take = round(math.tan(math.radians(eval(self.n1))),1)
                    self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        elif self.work_done == "cot":
            try:
                if eval(self.n1) == 0:
                    self.text_valuecal.set("Infinite")
                else:
                    result_take = round(1/(math.tan(math.radians(eval(self.n1)))),1)
                    self.text_valuecal.set(int(result_take)) if int(result_take) == result_take else self.text_valuecal.set(result_take)
            except:
                tkinter.messagebox.showerror("Error","Something error in input.please check it.")
                self.informationcal()
                self.reset_now()
        else:
            tkinter.messagebox.showerror("Error","Please read the informationcal carefully at first.")
            self.informationcal()
            self.reset_now()
        self.number1.focus()
        
    def start(self):
        self.run= True

    def stop(self):
        self.run= False
    #  Brute Program Main
    def brute_results(self, dec):
        global total, totaladd
        scantext = MIZ.brute_btc(self, dec)
        self.bfr.config(text = scantext)
        self.bfr.update()
        total+=1
        totaladd+=3
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def Random_Bruteforce_Speed(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        while self.run:
            dec =int(RandomInteger(int(startdec), int(stopdec)))
            self.brute_results(dec)

    def Sequential_Bruteforce_speed(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        mag = self._txt_inputmag.get().strip().replace(" ", "")
        while self.run:
            dec = int(startdec)
            if dec == int(stopdec):
                self.stop()
            else:
                self.brute_results(dec)
                startdec = int(startdec) + int(mag)
    
    def Sequential_Bruteforce_speed_back(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        mag = self._txt_inputmag.get().strip().replace(" ", "")
        while self.run:
            dec = int(stopdec)
            if dec == int(startdec):
                self.stop()
            else:
                self.brute_results(dec)
                stopdec = int(stopdec) - int(mag)

    #  Brain Program Main
    def brain_results_online(self, passphrase):
        global total, totaladd
        brainvar = tkinter.StringVar()
        brainvar.set(passphrase)
        brainvartext = tkinter.StringVar()
        brainvartext1 = MIZ.rbonline(self, passphrase)
        brainvartext.set(brainvartext1)
        self.brain_update.config(textvariable = brainvar, relief='flat')
        self.brain_update1.config(textvariable = brainvartext, relief='flat')
        self.brain_update.update()
        self.brain_update1.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
    
    def Random_brain_cal(self):
        passphrase = self.result.get().strip()
        global total, totaladd
        brainvartextcal = tkinter.StringVar()
        brainvartextcal1 = brainvartextca1 = MIZ.rbonline(self, passphrase)
        brainvartextcal.set(brainvartextcal1)
        self.brain_updatecal1.config(textvariable = brainvartextcal, relief='flat')
        self.brain_updatecal1.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
        
    def Random_brain_single(self):
        passphrase = self._txt_inputbrain.get().strip()
        global total, totaladd
        brainvar = tkinter.StringVar()
        brainvar.set(passphrase)
        brainvartext = tkinter.StringVar()
        brainvartext1 = brainvartext1 = MIZ.rbonline(self, passphrase)
        brainvartext.set(brainvartext1)
        self.brain_update.config(textvariable = brainvar, relief='flat')
        self.brain_update1.config(textvariable = brainvartext, relief='flat')
        self.brain_update.update()
        self.brain_update1.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
        
    def Random_brain_online(self):
        while self.run:
            start_amm = self._txt_brain_ammount.get().strip().replace(" ", "")
            stop_amm = self._txt_brain_total.get().strip().replace(" ", "")
            passphrase = ' '.join(random.sample(mylist, random.randint(int(start_amm), int(stop_amm))))
            self.brain_results_online(passphrase)
    
    def Random_brain_online1(self):
        for i in range(0,len(mylist)):
            passphrase = mylist[i]
            self.brain_results_online(passphrase)
    
    def Random_brain_online2(self):
        start_amm = self._txt_brain_ammount.get().strip().replace(" ", "")
        stop_amm = self._txt_brain_total.get().strip().replace(" ", "")
        while self.run:
            words = random.randrange(int(start_amm), int(stop_amm))
            passphrase = ''.join(random.sample(string.ascii_lowercase, words))
            self.brain_results_online(passphrase)

    def brain_results_offline(self, passphrase):
        global total, totaladd
        brainvar = tkinter.StringVar()
        brainvar.set(passphrase)
        brainvartext = tkinter.StringVar()
        brainvartext1 = MIZ.rboffline(self, passphrase)
        brainvartext.set(brainvartext1)
        self.brain_update.config(textvariable = brainvar, relief='flat')
        self.brain_update1.config(textvariable = brainvartext, relief='flat')
        self.brain_update.update()
        self.brain_update1.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def Random_brain_offline(self):
        start_amm = self._txt_brain_ammount.get().strip().replace(" ", "")
        stop_amm = self._txt_brain_total.get().strip().replace(" ", "")
        while self.run:
            passphrase = ' '.join(random.sample(mylist, random.randint(int(start_amm), int(stop_amm))))
            self.brain_results_offline(passphrase)
            
    def Random_brain_offline1(self):
        for i in range(0,len(mylist)):
            passphrase = mylist[i]
            self.brain_results_offline(passphrase)
    
    def Random_brain_offline2(self):
        start_amm = self._txt_brain_ammount.get().strip().replace(" ", "")
        stop_amm = self._txt_brain_total.get().strip().replace(" ", "")
        while self.run:
            words = random.randrange(int(start_amm), int(stop_amm))
            passphrase = ''.join(random.sample(string.ascii_lowercase, words))
            self.brain_results_offline(passphrase)
                
    def popwinner(self):
        self.popwin = Toplevel()
        self.popwin.title("BitHunter.py")
        self.popwin.iconbitmap('images/miz.ico')
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
        self.popwin.after(2000,lambda:self.popwin.destroy())

    def startpop(self):
        self.pop = Toplevel()
        self.pop.title("BitHunter.py")
        self.pop.iconbitmap('images/miz.ico')
        self.pop.geometry("700x250")
        self.widgetpop = tkinter.Label(self.pop, compound='top')
        self.widgetpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetpop['text'] = "© MIZOGG 2018 - 2022"
        self.widgetpop['image'] = self.widgetpop.miz_image_png
        self.widgetpop.place(x=220,y=180)
        self.label = tkinter.Label(self.pop, text='Welcome to BitHunter...... \n\n Made By Mizogg.co.uk \n\n Version 1.9 20/11/22').pack(pady=10)
        self.label1 = tkinter.Label(self.pop, text= "This window will get closed after 3 seconds...", font=('Helvetica 8 bold')).pack(pady=10)
        self.framepop = Frame(self.pop)
        self.framepop.pack(pady=10)
        self.buttonpop = Button(self.framepop, text=" Close ", command=self.CLOSEWINDOW)
        self.buttonpop.grid(row=0, column=1)
        self.pop.after(3000,lambda:self.pop.destroy())
        
    def CLOSEWINDOW(self):
        self.pop.destroy()

    def cpu_met(self):
        self.cpu_use = psutil.cpu_percent()
        self.cpu_label.config(text='Total CPU {} %'.format(self.cpu_use))
        self.cpu_label.after(1000,self.cpu_met)
        self.ram_use = psutil.virtual_memory()[2]
        self.ram_label.config(text='RAM Used {} %'.format(self.ram_use))
        ram_free = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
        self.ram_free = str(ram_free)[:4]
        self.ram_free_label.config(text='RAM Free {} %'.format(self.ram_free))
        
    def time(self):
        self.stringtime = strftime('%H:%M:%S %p')
        self.lbl.config(text = self.stringtime)
        self.lbl.after(1000, self.time)
        
    def Random_word_single(self):
        mnem = self._txt_inputword.get()
        random_word_results(self, mnem)
        
    def Random_word_random(self):
        lenght= ('128','256')
        rnds = random.choice(lenght)
        mnem = MIZ.create_valid_mnemonics(strength=int(rnds))
        random_word_results(self, mnem)
    
    def evt_btc_bin(self):
        try:
            bin_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = MIZ.bin2dec(bin_value)
            hex_value = MIZ.bin2hex(bin_value)
            bit_value = MIZ.bin2bit(bin_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception:
            tkinter.messagebox.showerror("Error", "Invalid Binary conversion")
            print(ex, file=sys.stderr)
            
    def evt_btc_bit(self):
        try:
            bit_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = MIZ.bit2bin(bit_value)
            dec_value = MIZ.bit2dec(bit_value)
            hex_value = MIZ.bit2hex(bit_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception:
            tkinter.messagebox.showerror("Error", "Invalid Bits conversion")
            print(ex, file=sys.stderr)
    
    def evt_btc_dec(self):
        try:
            dec_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = MIZ.dec2bin(dec_value)
            hex_value = MIZ.dec2hex(dec_value)
            bit_value = MIZ.dec2bit(dec_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
            
    def evt_rd_dec(self):
        try:
            dec_value = int(RandomInteger(startdec, stopdec))
            bin_value = MIZ.dec2bin(dec_value)
            hex_value = MIZ.dec2hex(dec_value)
            bit_value = MIZ.dec2bit(dec_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
    
    def evt_jump1_dec(self):
        try:
            dec_value = int(self.txt_outputdec.get().strip().replace(" ", ""))
            dec_value += int(self._jump_input.get().strip().replace(" ", ""))
            bin_value = MIZ.dec2bin(dec_value)
            hex_value = MIZ.dec2hex(dec_value)
            bit_value = MIZ.dec2bit(dec_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
            
    def evt_jump_rm1_dec(self):
        try:
            dec_value = int(self.txt_outputdec.get().strip().replace(" ", ""))
            dec_value -= int(self._jump_input.get().strip().replace(" ", ""))
            bin_value = MIZ.dec2bin(dec_value)
            hex_value = MIZ.dec2hex(dec_value)
            bit_value = MIZ.dec2bit(dec_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr) 
            
    def evt_btc_hex(self):
        try:
            hex_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = MIZ.hex2bin(hex_value)
            dec_value = MIZ.hex2dec(hex_value)
            bit_value = MIZ.hex2bit(hex_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Hexadecimal conversion")
            print(ex, file=sys.stderr)
    
    def evt_btc_add(self):
        try:
            btc_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = int(RandomInteger(startdec, stopdec))
            bin_value = MIZ.dec2bin(dec_value)
            hex_value = MIZ.dec2hex(dec_value)
            bit_value = MIZ.dec2bit(dec_value)
            btc_value = MIZ.addr2int(btc_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Address conversion")
            print(ex, file=sys.stderr)
    
    def _set_values(self, bin_value, dec_value, hex_value, bit_value, btc_value):
        if not bin_value.startswith("0b"):
            bin_value = "0b" + bin_value
        if not hex_value.startswith("0x"):
            hex_value = "0x" + hex_value
        self._stringvar_bin.set(bin_value)
        self._stringvar_bit.set(bit_value)
        self._stringvar_dec.set(dec_value)
        self._stringvar_hex.set(hex_value)
        self._stringvar_addr.set(btc_value)

    def mainloop(self):
        self.startpop()
        self.cpu_met()
        self.time()
        self.main_frame.mainloop()

if __name__ == "__main__":
    win = MainWindow()
    win.mainloop()
