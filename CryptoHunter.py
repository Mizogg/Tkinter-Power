#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 12.06.2023 https://t.me/CryptoCrackersUK
from tkinter import * 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
from signal import signal, SIGINT
from datetime import datetime
from time import strftime, sleep
import mizlib as MIZ
import mizinfo as MIZINFO 
import traceback 
import threading
import binascii
import hashlib
import logging
import string
import math
import random
import socket
import time
import json
import sys
import os
try:
    import psutil
    import requests 
    
except ImportError:
    import subprocess
    subprocess.check_call(["python", '-m', 'pip', 'install', 'psutil'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'requests'])
    import psutil
    import requests     

########### Mining Program ########### (WORK IN PROGRESS) 
sock = None

def timer() :
    tcx = datetime.now().time()
    return tcx
    
def handler(signal_received , frame) :
    MIZ.fShutdown = True
    close_error = f'[  {timer()}  ] Terminating Miner, Please Wait..'
    tkinter.messagebox.showerror("Error", close_error)

def logg(msg) :
    logging.basicConfig(level = logging.INFO , filename = "miner.log" ,
                        format = '%(asctime)s %(message)s')
    logging.info(msg)

def get_current_block_height() :
    r = requests.get('https://blockchain.info/latestblock')
    return int(r.json()['height'])

def check_for_shutdown(t) :
    n = t.n
    if MIZ.fShutdown :
        if n != -1 :
            MIZ.listfThreadRunning[n] = False
            t.exit = True

class ExitedThread(threading.Thread) :
    def __init__(self , arg , n) :
        super(ExitedThread , self).__init__()
        self.exit = False
        self.arg = arg
        self.n = n

    def run(self) :
        self.thread_handler(self.arg , self.n)
        pass

    def thread_handler(self , arg , n) :
        while True :
            check_for_shutdown(self)
            if self.exit :
                break
            MIZ.listfThreadRunning[n] = True
            try :
                self.thread_handler2(arg)
            except Exception as e :
                logg("ThreadHandler()")
                print('[' , timer() , '] ThreadHandler()')
                logg(e)
                print(e)
            MIZ.listfThreadRunning[n] = False

            time.sleep(2)
            pass

    def thread_handler2(self , arg) :
        raise NotImplementedError("must impl this func")

    def check_self_shutdown(self) :
        check_for_shutdown(self)

    def try_exit(self) :
        self.exit = True
        MIZ.listfThreadRunning[self.n] = False
        pass

def bitcoin_miner(t , restarted = False) :
    if restarted :
        logg('\n[*] Bitcoin Miner restarted')
        print('[' , timer() , '] [*] Bitcoin Miner Restarted')
        time.sleep(5)
    target = (MIZ.nbits[2 :] + '00' * (int(MIZ.nbits[:2] , 16) - 3)).zfill(64)
    extranonce2 = hex(random.randint(0 , 2 ** 32 - 1))[2 :].zfill(2 * MIZ.extranonce2_size)  # create random
    coinbase = MIZ.coinb1 + MIZ.extranonce1 + extranonce2 + MIZ.coinb2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()
    merkle_root = coinbase_hash_bin
    for h in MIZ.merkle_branch :
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()
    merkle_root = binascii.hexlify(merkle_root).decode()
    merkle_root = ''.join([merkle_root[i] + merkle_root[i + 1] for i in range(0 , len(merkle_root) , 2)][: :-1])
    work_on = get_current_block_height()
    MIZ.nHeightDiff[work_on + 1] = 0
    _diff = int("00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" , 16)
    logg('[*] Working to solve block with height {}'.format(work_on + 1))
    print('[' , timer() , '] [*] Working to solve block with height {}'.format(work_on + 1))
    #scantext3 = f'[  {timer()}  ]  [*] Working to solve block with height {work_on + 1}'
    #logg(scantext3)
    #self.mine_label3.config(text = scantext3)
    #self.mine_label3.update()
    while True :
        t.check_self_shutdown()
        if t.exit :
            break
        if MIZ.prevhash != MIZ.updatedPrevHash :
            logg('[*] New block {} detected on network '.format(MIZ.prevhash))
            print('[' , timer() , '] [*] New block {} detected on network '.format(MIZ.prevhash))
            logg('[*] Best difficulty will trying to solve block {} was {}'.format(work_on + 1 , MIZ.nHeightDiff[work_on + 1]))
            print('[' , timer() , '] [*] Best difficulty will trying to solve block  {} was {}'.format(work_on + 1 , MIZ.nHeightDiff[work_on + 1]))
            MIZ.updatedPrevHash = MIZ.prevhash
            bitcoin_miner(t , restarted = True)
            print('[' , timer() , '] Bitcoin Miner Restart Now...')
            continue

        nonce = hex(random.randint(0 , 2 ** 32 - 1))[2 :].zfill(8)
        blockheader = MIZ.version + MIZ.prevhash + merkle_root + MIZ.ntime + MIZ.nbits + nonce + \
                      '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
        hash = hashlib.sha256(hashlib.sha256(binascii.unhexlify(blockheader)).digest()).digest()
        hash = binascii.hexlify(hash).decode()

        if hash.startswith('0000000') :
            logg('[*] New hash: {} for block {}'.format(hash , work_on + 1))
            print('[' , timer() , '] [*] New hash:  {} for block {}'.format(hash , work_on + 1))
            print('[' , timer() , '] Hash:' , str(hash))
        this_hash = int(hash , 16)
        print(this_hash, end='\r')
        difficulty = _diff / this_hash
        if MIZ.nHeightDiff[work_on + 1] < difficulty :
            MIZ.nHeightDiff[work_on + 1] = difficulty

        if hash < target :
            logg('[*] Block {} solved.'.format(work_on + 1))
            print('[' , timer() , '][*] Block {} solved.'.format(work_on + 1))
            logg('[*] Block hash: {}'.format(hash))
            print('[' , timer() , '][*] Block hash: {}'.format(hash))
            logg('[*] Blockheader: {}'.format(blockheader))
            print('[*] Blockheader: {}'.format(blockheader))
            payload = bytes('{"params": ["' + address + '", "' + MIZ.job_id + '", "' + MIZ.extranonce2 \
                            + '", "' + MIZ.ntime + '", "' + nonce + '"], "id": 1, "method": "mining.submit"}\n' ,
                            'utf-8')
            logg('[*] Payload: {}'.format(payload))
            print('[' , timer() , '][*] Payload: {}'.format(payload))
            sock.sendall(payload)
            ret = sock.recv(1024)
            logg('[*] Pool response: {}'.format(ret))
            print('[' , timer() , '][*] Pool Response: {}'.format(ret))
            return True

def block_listener(t) :
    sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    sock.connect(('solo.ckpool.org' , 3333))
    sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": []}\n')
    lines = sock.recv(1024).decode().split('\n')
    response = json.loads(lines[0])
    MIZ.sub_details , MIZ.extranonce1 , MIZ.extranonce2_size = response['result']
    sock.sendall(b'{"params": ["' + address.encode() + b'", "password"], "id": 2, "method": "mining.authorize"}\n')
    response = b''
    while response.count(b'\n') < 4 and not (b'mining.notify' in response) : response += sock.recv(1024)

    responses = [json.loads(res) for res in response.decode().split('\n') if
                 len(res.strip()) > 0 and 'mining.notify' in res]
    MIZ.job_id , MIZ.prevhash , MIZ.coinb1 , MIZ.coinb2 , MIZ.merkle_branch , MIZ.version , MIZ.nbits , MIZ.ntime , MIZ.clean_jobs = \
        responses[0]['params']
    MIZ.updatedPrevHash = MIZ.prevhash
    while True :
        t.check_self_shutdown()
        if t.exit :
            break
        response = b''
        while response.count(b'\n') < 4 and not (b'mining.notify' in response) : response += sock.recv(1024)
        responses = [json.loads(res) for res in response.decode().split('\n') if
                     len(res.strip()) > 0 and 'mining.notify' in res]

        if responses[0]['params'][1] != MIZ.prevhash :
            MIZ.job_id , MIZ.prevhash , MIZ.coinb1 , MIZ.coinb2 , MIZ.merkle_branch , MIZ.version , MIZ.nbits , MIZ.ntime , MIZ.clean_jobs = \
                responses[0]['params']

class CoinMinerThread(ExitedThread) :
    def __init__(self , arg = None) :
        super(CoinMinerThread , self).__init__(arg , n = 0)

    def thread_handler2(self , arg) :
        self.thread_bitcoin_miner(arg)

    def thread_bitcoin_miner(self , arg) :
        MIZ.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try :
            ret = bitcoin_miner(self)
            logg("[" , timer() , "] [*] Miner returned %s\n\n" % "true" if ret else "false")
            print("[*] Miner returned %s\n\n" % "true" if ret else "false")
        except Exception as e :
            logg("[*] Miner()")
            print("[" , timer() , "][*] Miner()")
            logg(e)
            traceback.print_exc()
        MIZ.listfThreadRunning[self.n] = False

    pass

class NewSubscribeThread(ExitedThread) :
    def __init__(self , arg = None) :
        super(NewSubscribeThread , self).__init__(arg , n = 1)

    def thread_handler2(self , arg) :
        self.thread_new_block(arg)

    def thread_new_block(self , arg) :
        MIZ.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try :
            ret = block_listener(self)
        except Exception as e :
            logg("[*] Subscribe thread()")
            print("[" , timer() , "][*] Subscribe thread()")
            logg(e)
            traceback.print_exc()
        MIZ.listfThreadRunning[self.n] = False

    pass
    
def RandomInteger(minN, maxN):
    return random.randrange(minN, maxN)

########### Database Load and Files ###########
mylist = []
 
with open('files/words.txt', newline='', encoding='utf-8') as f:
    for line in f:
        mylist.append(line.strip())
startdec = 1
stopdec = 115792089237316195423570985008687907852837564279074904382605163141518161494336
totaladd = total = found =0
run = run1=  run2 = run3 = True
########### THE MAIN PROGRAM BITCOIN HUNTER ###########
class MainWindow():
    def __init__(self):
        self.found = found
        self.run = run
        self.fact = 1
        def start1():
           global run1
           run1= True
        def stop1():
           global run1
           run1= False
        def start2():
           global run2
           run2= True
        def stop2():
           global run2
           run2= False
        def start3():
           global run3
           run3= True
        def stop3():
           global run3
           run3= False
        ###########  Main Window Program Menu Bar ###########
        self._window = tkinter.Tk()
        self._window.title("CryptoHunter.py @ Mizogg.co.uk")
        self._window.iconbitmap('images/miz.ico')
        self._window.config(bg="black")
        self._window.geometry("900x720")
        self._window.resizable(False, False)
        self._window.menubar = Menu(self._window)
        self._window.filemenu = Menu(self._window.menubar, tearoff=0)
        self._window.filemenu.add_separator()
        self._window.filemenu.add_command(label="Exit", command=self._window.quit)
        self._window.menubar.add_cascade(label="File", menu=self._window.filemenu)
        self._window.helpmenu = Menu(self._window.menubar, tearoff=0)
        self._window.helpmenu.add_command(label="Help Telegram Group", command=MIZ.opentelegram)
        self._window.helpmenu.add_command(label="Mizogg Website", command=MIZ.openweb)
        self._window.helpmenu.add_command(label="About CrytpoHunter", command=self.startpop)
        self._window.menubar.add_cascade(label="Help", menu=self._window.helpmenu)
        self._window.config(menu=self._window.menubar)
        self.my_notebook = ttk.Notebook(self._window)
        self.my_notebook.pack(pady=5)
        self.main_frame = Frame(self.my_notebook, width=880, height=700)
        self.crypto_frame = Frame(self.my_notebook, width=880, height=700)
        self.page_frame = Frame(self.my_notebook, width=880, height=700)
        self.hex_frame = Frame(self.my_notebook, width=880, height=700)
        self.brain_frame = Frame(self.my_notebook, width=880, height=700)
        self.word_frame = Frame(self.my_notebook, width=880, height=700)
        self.mine_frame = Frame(self.my_notebook, width=880, height=700)
        self.about_frame = Frame(self.my_notebook, width=880, height=700)
        self.windowcal = Frame(self.my_notebook, width=880, height=700)
        self.recovery_frame = Frame(self.my_notebook, width=880, height=700)
        self.main_frame.pack(fill="both", expand=1)
        self.crypto_frame.pack(fill="both", expand=1)
        self.page_frame.pack(fill="both", expand=1)
        self.hex_frame.pack(fill="both", expand=1)
        self.brain_frame.pack(fill="both", expand=1)
        self.word_frame.pack(fill="both", expand=1)
        self.mine_frame.pack(fill="both", expand=1)
        self.about_frame.pack(fill="both", expand=1)
        self.windowcal.pack(fill="both", expand=1)
        self.recovery_frame.pack(fill="both", expand=1)
        ########### TAB ORDER ###########
        self.my_notebook.add(self.crypto_frame, text="CryptoHunter")
        self.my_notebook.add(self.page_frame, text="KEYS")
        self.my_notebook.add(self.hex_frame, text="Rotation5Bit")
        self.my_notebook.add(self.recovery_frame, text="Recovery Tool")
        self.my_notebook.add(self.main_frame, text="Conversion Tool")
        self.my_notebook.add(self.windowcal, text="Calulator")
        self.my_notebook.add(self.brain_frame, text="Brain Wallet")
        self.my_notebook.add(self.word_frame, text="Mnemonic Words")
        self.my_notebook.add(self.mine_frame, text="BTC Mining")
        self.my_notebook.add(self.about_frame, text="About")
        ########### Calulator Tab ###########
        self.text_valuecal = tkinter.StringVar()
        self.textoperator = tkinter.StringVar()
        self.textoperator2 = tkinter.StringVar()
        self.plus = tkinter.Button(self.windowcal,text="+",width=4,font=("arial",15,"bold"),fg="purple",bg="#F0F0F0", activebackground="#F0F0F0", command=lambda : self.opr("+"), relief=RAISED, bd=3).place(x=530,y=110)
        self.subs = tkinter.Button(self.windowcal, text="-", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("-"), relief=RAISED, bd=3).place(x=530, y=170)
        self.mul = tkinter.Button(self.windowcal, text="X", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("X"), relief=RAISED, bd=3).place(x=605, y=110)
        self.div = tkinter.Button(self.windowcal, text="/", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("/"), relief=RAISED, bd=3).place(x=605, y=170)
        self.rad = tkinter.Button(self.windowcal, text="Radian", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Radian"), relief=RAISED, bd=3).place(x=690, y=260)
        self.reci = tkinter.Button(self.windowcal, text="1/x", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Reciprocal"), relief=RAISED, bd=3).place(x=230, y=260)
        self.sqr = tkinter.Button(self.windowcal, text="X^2", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Square"), relief=RAISED, bd=3).place(x=367, y=260)
        self.cube = tkinter.Button(self.windowcal, text="X^3", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Cube"), relief=RAISED, bd=3).place(x=367, y=310)
        self.equal = tkinter.Button(self.windowcal, text="=", width=11, font=("arial", 18, "bold"), fg="green",bg="#F0F0F0", activebackground="#F0F0F0",command=self.evaluation_opr, relief=RAISED, bd=3, ).place(x=690, y=130)
        self.braincal = tkinter.Button(self.windowcal, text="Sum to Brain Wallet", width=16, font=("arial", 12, "bold"), fg="green",bg="#F0F0F0", activebackground="#F0F0F0",command=self.Random_brain_cal, relief=RAISED, bd=3, ).place(x=690, y=195)
        self.get_infoCAL = tkinter.Button(self.windowcal, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationcal, relief=RAISED, bd=3).place(x=710, y=535)
        self.sqrt = tkinter.Button(self.windowcal, text="Square root", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Square root"), relief=RAISED, bd=3).place(x=432, y=260)
        self.cubert = tkinter.Button(self.windowcal, text="Cube root", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Cube root"), relief=RAISED, bd=3).place(x=432, y=310)
        self.log2 = tkinter.Button(self.windowcal, text="log2", width=8, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("log2"), relief=RAISED, bd=3).place(x=580, y=260)
        self.log10 = tkinter.Button(self.windowcal, text="log10", width=8, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("log10"), relief=RAISED, bd=3).place(x=580, y=310)
        self.exponent = tkinter.Button(self.windowcal, text="e^x", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Exponent"), relief=RAISED, bd=3).place(x=300, y=260)
        self.power = tkinter.Button(self.windowcal, text="X^Y", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("x^y"), relief=RAISED, bd=3).place(x=300, y=310)
        self.factorial = tkinter.Button(self.windowcal, text="n!", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda : self.opr("Factorial"), relief=RAISED, bd=3).place(x=15, y=310)
        self.mod = tkinter.Button(self.windowcal, text="Modulus", width=11, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("Modulus"), relief=RAISED, bd=3).place(x=690, y=310)
        self.reset = tkinter.Button(self.windowcal, text="Reset", width=5, font=("arial", 13, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=self.reset_now, relief=RAISED, bd=3).place(x=575, y=218)
        self.sin = tkinter.Button(self.windowcal, text="sin", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("sin"), relief=RAISED, bd=3).place(x=90 ,y=310)
        self.cos = tkinter.Button(self.windowcal, text="cos", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("cos"), relief=RAISED, bd=3).place(x=15, y=260)
        self.tan = tkinter.Button(self.windowcal, text="tan", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("tan"), relief=RAISED, bd=3).place(x=90, y=260)
        self.cot = tkinter.Button(self.windowcal, text="cot", width=4, font=("arial", 15, "bold"), fg="purple",bg="#F0F0F0", activebackground="#F0F0F0",command=lambda: self.opr("cot"), relief=RAISED, bd=3).place(x=160, y=260)
        self.lcm = tkinter.Button(self.windowcal, text="LCM", width=4, font=("arial", 15, "bold"), bg="#F0F0F0", fg="purple", activebackground="#F0F0F0",command=lambda : self.opr("lcm"), relief=RAISED, bd=3).place(x=160, y=310)
        self.hcf = tkinter.Button(self.windowcal, text="HCF", width=4, font=("arial", 15, "bold"), bg="#F0F0F0", fg="purple", activebackground="#F0F0F0",command=lambda : self.opr("hcf"), relief=RAISED, bd=3).place(x=230, y=310)
        self.result_name = tkinter.Label(self.windowcal, text="Result: ", width=8, font=("arial", 16, "bold", "italic"),fg="black",bg="#F0F0F0").place(x=340, y=360)
        self.result = tkinter.Entry(self.windowcal,font=("Helvetica",20,"bold","italic"),textvar=self.text_valuecal, bd=5, width=56, relief=SUNKEN, disabledbackground="white", foreground="purple")
        self.result.place(x=10,y=390)
        tkinter.Label(self.windowcal, text="Number 1 ",width=8, font=("arial", 15, "bold","italic"),bg="#F0F0F0",fg="black").place(x=10, y=115)
        self.number1 = tkinter.Entry(self.windowcal,width=31,bg="#3d3d3d",font=("arial",16,"bold","italic"), insertbackground="gold",fg="gold",bd=3,relief=SUNKEN)
        self.number1.place(x=130,y=115)
        self.number1.focus()
        tkinter.Label(self.windowcal, text="Number 2 ", width=8, font=("arial", 16, "bold", "italic"),fg="black", bg="#F0F0F0").place(x=10, y=195)
        self.number2 = tkinter.Entry(self.windowcal, width=31, bg="#3d3d3d", font=("arial", 16, "bold", "italic"), insertbackground="gold",fg="gold", relief=SUNKEN, bd=4)
        self.number2.place(x=130, y=195)
        self.operator_name = tkinter.Label(self.windowcal, text="Operation ", width=12, font=("arial", 16, "bold", "italic"), bg="#F0F0F0", fg="#d96b6b").place(x=10, y=155)
        self.operator = tkinter.Entry(self.windowcal, width=12, font=("arial", 16, "bold", "italic"), disabledbackground="#3d3d3d",disabledforeground="gold",state="disable",textvar=self.textoperator,bd=5,relief=SUNKEN)
        self.operator.place(x=250, y=155)
        self.brain_updatecal1 = tkinter.Label(self.windowcal, bg="#F0F0F0",font=("Arial",10),text="")
        self.brain_updatecal1.place(x=160,y=440)
        ###########  Main Tab ###########
        self.labeltype = tkinter.Label(self.main_frame, text=" Type \n Data \n Here ", font=("Consolas", 16)).place(x=5,y=70)
        self._txt_input = tkinter.Entry(self.main_frame, width=60, font=("Consolas", 16))
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
        self.labeladdr = tkinter.Label(self.main_frame, text=" When Searching for adress \n it will generate \n a random private key \n this will not match the address ", font=("Arial", 8), fg='red').place(x=700,y=135)
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
        ###########  Widgets ###########
        self.widget = tkinter.Label(self._window, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2023"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=590,y=30)
        self.widgetsnake = tkinter.Button(self._window, text= "BTC Snake Game ",font=("Arial",10),bg="purple", command= MIZ.opensnake).place(x=30,y=650)
        self.widgetHunter = tkinter.Button(self._window, text= "16x16 BTC Hunter ",font=("Arial",10),bg="gold", command= MIZ.hunter16x16).place(x=750,y=650)
        self.lbl = tkinter.Label(self._window, font = ('calibri', 28, 'bold'), background = '#F0F0F0', foreground = 'purple')
        self.lbl.place(x=10,y=30)
        self.cpu_label = tkinter.Label(self._window,font = ('calibri', 14, 'bold'), background = '#F0F0F0', foreground = 'red')
        self.cpu_label.place(x=190,y=650)
        self.ram_label = tkinter.Label(self._window,font = ('calibri', 14, 'bold'), background = '#F0F0F0', foreground = 'red')
        self.ram_label.place(x=330,y=650)
        self.ram_free_label = tkinter.Label(self._window,font = ('calibri', 14, 'bold'), bg= '#F0F0F0', fg= 'red')
        self.ram_free_label.place(x=490,y=650)
        self.tpk = tkinter.Label(self._window, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=240,y=30)
        self.totalC = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",12),text="")
        self.totalC.place(x=380,y=30)
        self.totaladd = tkinter.Label(self._window, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=240,y=50)
        self.totalA = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",12),text="")
        self.totalA.place(x=380,y=50)
        self.addcount = tkinter.Label(self._window, text=MIZ.countadd(),font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=80,y=80)
        self.pricelable_data = f"Todays Bitcoin Price £ {MIZ.price()} "
        self.pricelable = tkinter.Label(self._window, text=self.pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=90, y=610)
        ########### about_frame ###########
        self.about1 = tkinter.Frame(master = self.about_frame, bg = '#F0F0F0')
        self.about1.pack(fill='both', expand='yes')
        self.editArea = tkst.ScrolledText(master = self.about1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        self.editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        self.editArea.insert(tkinter.INSERT, MIZINFO.information)
        ########### brain_frame ###########
        self.totalbw = tkinter.Label(self.brain_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=690,y=70)
        self.foundbw = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbw.place(x=750,y=120)
        self.brain_update = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",12),text="", width=80, fg="Red")
        self.brain_update.place(x=30,y=310)
        self.brain_update1 = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",14),text="")
        self.brain_update1.place(x=60,y=350)
        self.start1= tkinter.Button(self.brain_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= self.start, fg='green').place(x=700,y=180)
        self.stop1= tkinter.Button(self.brain_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= self.stop, fg='red').place(x=760,y=180)
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
        self.get_infoBRAIN = tkinter.Button(self.brain_frame, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationBRAIN, relief=RAISED, bd=3).place(x=710, y=535)
        ########### crypto_frame ###########
        self.bwg = tkinter.Label(self.crypto_frame, text="Crypto Wallet Generator ",font=("Arial",20),bg="#F0F0F0",fg="Black").place(x=180,y=100)
        self.bfr = tkinter.Label(self.crypto_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.bfr.place(x=20,y=300)
        self.labelstart = tkinter.Label(self.crypto_frame, text="Start \nDec ", font=("Arial",13)).place(x=5,y=140)
        self._txt_inputstart = tkinter.Entry(self.crypto_frame, width=50, font=("Consolas", 16))
        self._txt_inputstart.insert(0, '1')
        self._txt_inputstart.place(x=65,y=145)
        self._txt_inputstart.focus()
        self.labelstop = tkinter.Label(self.crypto_frame, text="Stop \nDec ", font=("Arial",13)).place(x=5,y= 180)
        self._txt_inputstop = tkinter.Entry(self.crypto_frame, width=50, font=("Consolas", 16))
        self._txt_inputstop.insert(0, stopdec)
        self._txt_inputstop.place(x=65,y=185)
        self._txt_inputstop.focus()
        self.labelmag = tkinter.Label(self.crypto_frame, text="Jump \nMag ", font=("Arial",13)).place(x=660,y= 220)
        self._txt_inputmag = tkinter.Entry(self.crypto_frame, width=8, font=("Consolas", 16))
        self._txt_inputmag.insert(0, '1')
        self._txt_inputmag.place(x=710,y=225)
        self._txt_inputmag.focus()
        self.r1 = tkinter.Button(self.crypto_frame, text=" Off-Line Random ",font=("Arial",13),bg="#A3E4D7",command=self.Random_Bruteforce_Speed).place(x=15,y=220)
        self.bal1 = tkinter.Button(self.crypto_frame, text=" On-line Random  ",font=("Arial",13),bg="#A3E4D7",command=self.Random_Bruteforce_Speed_online).place(x=15,y=260)
        self.s1 = tkinter.Button(self.crypto_frame, text=" Off-Line Sequential Start-Stop",font=("Arial",13),bg="#B3B4D7",command=self.Sequential_Bruteforce_speed).place(x=170,y=220)
        self.bals1 = tkinter.Button(self.crypto_frame, text=" On-Line Sequential Start-Stop",font=("Arial",13),bg="#B3B4D7",command=self.Sequential_Bruteforce_speed_online).place(x=170,y=260)
        self.sb1 = tkinter.Button(self.crypto_frame, text=" Off-Line Backward Stop-Start ",font=("Arial",13),bg="#C3C4D7",command=self.Sequential_Bruteforce_speed_back).place(x=415,y=220)
        self.balsb1 = tkinter.Button(self.crypto_frame, text=" On-Line Backward Stop-Start ",font=("Arial",13),bg="#C3C4D7",command=self.Sequential_Bruteforce_speed_back_online).place(x=415,y=260)
        self.start= tkinter.Button(self.crypto_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= self.start, fg='green').place(x=700,y=180)
        self.stop= tkinter.Button(self.crypto_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= self.stop, fg='red').place(x=760,y=180)
        self.totalbtc = tkinter.Label(self.crypto_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=690,y=70)
        self.foundbtc = tkinter.Label(self.crypto_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbtc.place(x=750,y=120)
        self.get_infoMAIN = tkinter.Button(self.crypto_frame, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationMAIN, relief=RAISED, bd=3).place(x=710, y=535)
        ########### page_frame ###########
        self.bwgpage = tkinter.Label(self.page_frame, text="Bitcoin&ETH Wallet Generator Based on Keys.lol 128 Private Keys per page",font=("Arial",17),bg="#F0F0F0",fg="Black").place(x=20,y=100)
        self.page_brute = tkinter.Label(self.page_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.page_brute.place(x=20,y=280)
        self.labelstart = tkinter.Label(self.page_frame, text="Start \n Page ", font=("Arial",13)).place(x=5,y=140)
        self._txt_inputstartpage = tkinter.Entry(self.page_frame, width=50, font=("Consolas", 16))
        self._txt_inputstartpage.insert(0, '1')
        self._txt_inputstartpage.place(x=65,y=145)
        self._txt_inputstartpage.focus()
        self.labelstoppage = tkinter.Label(self.page_frame, text="Stop \n Page ", font=("Arial",13)).place(x=5,y= 180)
        self._txt_inputstoppage = tkinter.Entry(self.page_frame, width=50, font=("Consolas", 16))
        self._txt_inputstoppage.insert(0, '904625697166532776746648320380374280100293470930272690489102837043110636675')
        self._txt_inputstoppage.place(x=65,y=185)
        self._txt_inputstoppage.focus()
        self.labelmagpage = tkinter.Label(self.page_frame, text="Jump \nMag ", font=("Arial",13)).place(x=660,y= 220)
        self._txt_inputmagpage = tkinter.Entry(self.page_frame, width=8, font=("Consolas", 16))
        self._txt_inputmagpage.insert(0, '1')
        self._txt_inputmagpage.place(x=710,y=225)
        self._txt_inputmagpage.focus()
        self.r1page = tkinter.Button(self.page_frame, text=" Generate Random  ",font=("Arial",13),bg="#A3E4D7",command=self.Random_Bruteforce_Speed_page).place(x=60,y=220)
        self.s1page = tkinter.Button(self.page_frame, text=" Sequential Start-Stop",font=("Arial",13),bg="#B3B4D7",command=self.Sequential_Bruteforce_speed_page).place(x=240,y=220)
        self.sb1page = tkinter.Button(self.page_frame, text=" Backward Stop-Start ",font=("Arial",13),bg="#C3C4D7",command=self.Sequential_Bruteforce_speed_back_page).place(x=430,y=220)
        self.startpage= tkinter.Button(self.page_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start1, fg='green').place(x=700,y=180)
        self.stoppage= tkinter.Button(self.page_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop1, fg='red').place(x=760,y=180)
        self.totalbtc_page = tkinter.Label(self.page_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=690,y=70)
        self.foundbtc_page = tkinter.Label(self.page_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbtc_page.place(x=750,y=120)
        self.get_infoPAGE = tkinter.Button(self.page_frame, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationPAGE, relief=RAISED, bd=3).place(x=710, y=535)
        ########### word_frame ###########
        self.totalw = tkinter.Label(self.word_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=690,y=70)
        self.foundword = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundword.place(x=750,y=120)
        self.word_update = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",12),text="", width=80,fg="Red")
        self.word_update.place(x=30,y=280)
        self.word_update1 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",11),text="")
        self.word_update1.place(x=20,y=300)
        self.start2= tkinter.Button(self.word_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start2, fg='green').place(x=700,y=180)
        self.stop2= tkinter.Button(self.word_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop2, fg='red').place(x=760,y=180)
        self.labelword = tkinter.Label(self.word_frame, text="Mnemonic", font=("Arial",13)).place(x=5,y=75)
        self._txt_inputword = tkinter.Entry(self.word_frame, width=36, font=("Consolas", 16))
        self._txt_inputword.insert(0, 'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon')
        self._txt_inputword.place(x=90,y=80)
        self._txt_inputword.focus()
        self._word_bin = tkinter.Button(self.word_frame, text="Enter", font=("Consolas", 16), command=self.Random_word_single).place(x=545,y=75)
        self.titlem = tkinter.Label(self.word_frame, text="Mnemonic Words ",font=("Arial",16),bg="#F0F0F0",fg="Black").place(x=380,y=250)
        self.titlem1 = tkinter.Label(self.word_frame, text="Random Mnemonic Wallet Generator Online Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=60,y=130)
        self.titlem2 = tkinter.Label(self.word_frame, text="Random Mnemonic Wallet Generator Offline Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=60,y=190)
        self.my_buttonword = tkinter.Button(self.word_frame, text="Random Single", font=("Arial",11),bg="#A3B4A7", command=self.Random_word_random).place(x=700,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "1 Word ",font=("Arial",10),bg="#A3E4A7", command= self.Random_word_online).place(x=20,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "3 Words ",font=("Arial",10),bg="#A3E4B7", command= self.Random_word_online1).place(x=85,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "6 Words ",font=("Arial",10),bg="#A3E4C7", command= self.Random_word_online2).place(x=155,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "9 Words ",font=("Arial",10),bg="#A3E4D7", command= self.Random_word_online3).place(x=225,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "12 Words ",font=("Arial",10),bg="#A3E4E7", command= self.Random_word_online4).place(x=295,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "15 Words ",font=("Arial",10),bg="#A3E4F7", command= self.Random_word_online5).place(x=373,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "18 Words ",font=("Arial",10),bg="#F3E4A8", command= self.Random_word_online6).place(x=450,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "21 Words ",font=("Arial",10),bg="#F3E4B8", command= self.Random_word_online7).place(x=527,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "24 Words ",font=("Arial",10),bg="#F3E4C8", command= self.Random_word_online8).place(x=603,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "1 Word ",font=("Arial",10),bg="#A3E4A7", command= self.Random_word_offline).place(x=20,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "3 Words ",font=("Arial",10),bg="#A3E4B7", command= self.Random_word_offline1).place(x=85,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "6 Words ",font=("Arial",10),bg="#A3E4C7", command= self.Random_word_offline2).place(x=155,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "9 Words ",font=("Arial",10),bg="#A3E4D7", command= self.Random_word_offline3).place(x=225,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "12 Words ",font=("Arial",10),bg="#A3E4E7", command= self.Random_word_offline4).place(x=295,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "15 Words ",font=("Arial",10),bg="#A3E4F7", command= self.Random_word_offline5).place(x=373,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "18 Words ",font=("Arial",10),bg="#F3E4A8", command= self.Random_word_offline6).place(x=450,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "21 Words ",font=("Arial",10),bg="#F3E4B8", command= self.Random_word_offline7).place(x=527,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "24 Words ",font=("Arial",10),bg="#F3E4C8", command= self.Random_word_offline8).place(x=603,y=220)
        self.get_infoWORD = tkinter.Button(self.word_frame, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationWORD, relief=RAISED, bd=3).place(x=710, y=535)
        ########### hex_frame ###########
        self.hext = tkinter.Label(self.hex_frame, text="Rotation5Bit 20 Scans 128 private keys per scan 12,800 Addresses  ",font=("Arial",14),bg="#F0F0F0",fg="Black").place(x=30,y=95)
        self.hexl1 = tkinter.Label(self.hex_frame, text="Private Keys 1 - 10  ",font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=150,y=350)
        self.hexl2 = tkinter.Label(self.hex_frame, text=" | ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=410,y=350)
        self.hexl3 = tkinter.Label(self.hex_frame, text="Private Keys 11 - 20  ",font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=550,y=350)
        self.rotation_brute = tkinter.Label(self.hex_frame, bg="#F0F0F0",font=("Consolas",8),text="")
        self.rotation_brute.place(x=10,y=375)
        self.labelstarthexnum = tkinter.Label(self.hex_frame, text="1", font=("Arial",16), fg='red').place(x=60,y=130)
        self.labelstarthex = tkinter.Label(self.hex_frame, text="Start \nBIT ", font=("Arial",11), fg='green').place(x=5,y=150)
        self._txt_inputstarthex = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex.insert(0, '66')
        self._txt_inputstarthex.place(x=55,y=170)
        self._txt_inputstarthex.focus()
        self.labelstophex = tkinter.Label(self.hex_frame, text="Stop \nBIT ", font=("Arial",11), fg='orange').place(x=5,y= 200)
        self._txt_inputstophex = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex.insert(0, '67')
        self._txt_inputstophex.place(x=55,y=210)
        self._txt_inputstophex.focus()
        self.labelstarthexnum0 = tkinter.Label(self.hex_frame, text="2", font=("Arial",16), fg='red').place(x=120,y=130)
        self._txt_inputstarthex0 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex0.insert(0, '66')
        self._txt_inputstarthex0.place(x=110,y=170)
        self._txt_inputstarthex0.focus()
        self._txt_inputstophex0 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex0.insert(0, '67')
        self._txt_inputstophex0.place(x=110,y=210)
        self._txt_inputstophex0.focus()
        self.labelstarthexnum1 = tkinter.Label(self.hex_frame, text="3", font=("Arial",16), fg='red').place(x=175,y=130)
        self._txt_inputstarthex1 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex1.insert(0, '66')
        self._txt_inputstarthex1.place(x=165,y=170)
        self._txt_inputstarthex1.focus()
        self._txt_inputstophex1 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex1.insert(0, '67')
        self._txt_inputstophex1.place(x=165,y=210)
        self._txt_inputstophex1.focus()
        self.labelstarthexnum2 = tkinter.Label(self.hex_frame, text="4", font=("Arial",16), fg='red').place(x=230,y=130)
        self._txt_inputstarthex2 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex2.insert(0, '66')
        self._txt_inputstarthex2.place(x=220,y=170)
        self._txt_inputstarthex2.focus()
        self._txt_inputstophex2 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex2.insert(0, '67')
        self._txt_inputstophex2.place(x=220,y=210)
        self._txt_inputstophex2.focus()
        self.labelstarthexnum3 = tkinter.Label(self.hex_frame, text="5", font=("Arial",16), fg='red').place(x=285,y=130)
        self._txt_inputstarthex3 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex3.insert(0, '66')
        self._txt_inputstarthex3.place(x=275,y=170)
        self._txt_inputstarthex3.focus()
        self._txt_inputstophex3 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex3.insert(0, '67')
        self._txt_inputstophex3.place(x=275,y=210)
        self._txt_inputstophex3.focus()
        self.labelstarthexnum4 = tkinter.Label(self.hex_frame, text="6", font=("Arial",16), fg='red').place(x=340,y=130)
        self._txt_inputstarthex4 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex4.insert(0, '66')
        self._txt_inputstarthex4.place(x=330,y=170)
        self._txt_inputstarthex4.focus()
        self._txt_inputstophex4 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex4.insert(0, '67')
        self._txt_inputstophex4.place(x=330,y=210)
        self._txt_inputstophex4.focus()
        self.labelstarthexnum5 = tkinter.Label(self.hex_frame, text="7", font=("Arial",16), fg='red').place(x=395,y=130)
        self._txt_inputstarthex5 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex5.insert(0, '66')
        self._txt_inputstarthex5.place(x=385,y=170)
        self._txt_inputstarthex5.focus()
        self._txt_inputstophex5 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex5.insert(0, '67')
        self._txt_inputstophex5.place(x=385,y=210)
        self._txt_inputstophex5.focus()
        self.labelstarthexnum6 = tkinter.Label(self.hex_frame, text="8", font=("Arial",16), fg='red').place(x=450,y=130)
        self._txt_inputstarthex6 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex6.insert(0, '66')
        self._txt_inputstarthex6.place(x=440,y=170)
        self._txt_inputstarthex6.focus()
        self._txt_inputstophex6 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex6.insert(0, '67')
        self._txt_inputstophex6.place(x=440,y=210)
        self._txt_inputstophex6.focus()
        self.labelstarthexnum7 = tkinter.Label(self.hex_frame, text="9", font=("Arial",16), fg='red').place(x=505,y=130)
        self._txt_inputstarthex7 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex7.insert(0, '66')
        self._txt_inputstarthex7.place(x=495,y=170)
        self._txt_inputstarthex7.focus()
        self._txt_inputstophex7 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex7.insert(0, '67')
        self._txt_inputstophex7.place(x=495,y=210)
        self._txt_inputstophex7.focus()
        self.labelstarthexnum8 = tkinter.Label(self.hex_frame, text="10", font=("Arial",16), fg='red').place(x=560,y=130)
        self._txt_inputstarthex8 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex8.insert(0, '66')
        self._txt_inputstarthex8.place(x=550,y=170)
        self._txt_inputstarthex8.focus()
        self._txt_inputstophex8 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex8.insert(0, '67')
        self._txt_inputstophex8.place(x=550,y=210)
        self._txt_inputstophex8.focus()
        self.labelstarthexnum9 = tkinter.Label(self.hex_frame, text="11", font=("Arial",16), fg='red').place(x=60,y=235)
        self.labelstarthex2 = tkinter.Label(self.hex_frame, text="Start \nBIT ", font=("Arial",11), fg='green').place(x=5,y=260)
        self._txt_inputstarthex9 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex9.insert(0, '66')
        self._txt_inputstarthex9.place(x=55,y=275)
        self._txt_inputstarthex9.focus()
        self.labelstophex2 = tkinter.Label(self.hex_frame, text="Stop \nBIT ", font=("Arial",11), fg='orange').place(x=5,y= 310)
        self._txt_inputstophex9 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex9.insert(0, '67')
        self._txt_inputstophex9.place(x=55,y=315)
        self._txt_inputstophex9.focus()
        self.labelstarthexnum10 = tkinter.Label(self.hex_frame, text="12", font=("Arial",16), fg='red').place(x=120,y=235)
        self._txt_inputstarthex10 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex10.insert(0, '66')
        self._txt_inputstarthex10.place(x=110,y=275)
        self._txt_inputstarthex10.focus()
        self._txt_inputstophex10 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex10.insert(0, '160')
        self._txt_inputstophex10.place(x=110,y=315)
        self._txt_inputstophex10.focus()
        self.labelstarthexnum11 = tkinter.Label(self.hex_frame, text="13", font=("Arial",16), fg='red').place(x=175,y=235)
        self._txt_inputstarthex11 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex11.insert(0, '66')
        self._txt_inputstarthex11.place(x=165,y=275)
        self._txt_inputstarthex11.focus()
        self._txt_inputstophex11 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex11.insert(0, '160')
        self._txt_inputstophex11.place(x=165,y=315)
        self._txt_inputstophex11.focus()
        self.labelstarthexnum12 = tkinter.Label(self.hex_frame, text="14", font=("Arial",16), fg='red').place(x=230,y=235)
        self._txt_inputstarthex12 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex12.insert(0, '66')
        self._txt_inputstarthex12.place(x=220,y=275)
        self._txt_inputstarthex12.focus()
        self._txt_inputstophex12 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex12.insert(0, '160')
        self._txt_inputstophex12.place(x=220,y=315)
        self._txt_inputstophex12.focus()
        self.labelstarthexnum13 = tkinter.Label(self.hex_frame, text="15", font=("Arial",16), fg='red').place(x=285,y=235)
        self._txt_inputstarthex13 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex13.insert(0, '66')
        self._txt_inputstarthex13.place(x=275,y=275)
        self._txt_inputstarthex13.focus()
        self._txt_inputstophex13 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex13.insert(0, '160')
        self._txt_inputstophex13.place(x=275,y=315)
        self._txt_inputstophex13.focus()
        self.labelstarthexnum14 = tkinter.Label(self.hex_frame, text="16", font=("Arial",16), fg='red').place(x=340,y=235)
        self._txt_inputstarthex14 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex14.insert(0, '66')
        self._txt_inputstarthex14.place(x=330,y=275)
        self._txt_inputstarthex14.focus()
        self._txt_inputstophex14 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex14.insert(0, '160')
        self._txt_inputstophex14.place(x=330,y=315)
        self._txt_inputstophex14.focus()
        self.labelstarthexnum15 = tkinter.Label(self.hex_frame, text="17", font=("Arial",16), fg='red').place(x=395,y=235)
        self._txt_inputstarthex15 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex15.insert(0, '66')
        self._txt_inputstarthex15.place(x=385,y=275)
        self._txt_inputstarthex15.focus()
        self._txt_inputstophex15 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex15.insert(0, '160')
        self._txt_inputstophex15.place(x=385,y=315)
        self._txt_inputstophex15.focus()
        self.labelstarthexnum16 = tkinter.Label(self.hex_frame, text="18", font=("Arial",16), fg='red').place(x=450,y=235)
        self._txt_inputstarthex16 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex16.insert(0, '66')
        self._txt_inputstarthex16.place(x=440,y=275)
        self._txt_inputstarthex16.focus()
        self._txt_inputstophex16 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex16.insert(0, '160')
        self._txt_inputstophex16.place(x=440,y=315)
        self._txt_inputstophex16.focus()
        self.labelstarthexnum17 = tkinter.Label(self.hex_frame, text="19", font=("Arial",16), fg='red').place(x=505,y=235)
        self._txt_inputstarthex17 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex17.insert(0, '66')
        self._txt_inputstarthex17.place(x=495,y=275)
        self._txt_inputstarthex17.focus()
        self._txt_inputstophex17 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex17.insert(0, '160')
        self._txt_inputstophex17.place(x=495,y=315)
        self._txt_inputstophex17.focus()
        self.labelstarthexnum18 = tkinter.Label(self.hex_frame, text="20", font=("Arial",16), fg='red').place(x=560,y=235)
        self._txt_inputstarthex18 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex18.insert(0, '66')
        self._txt_inputstarthex18.place(x=550,y=275)
        self._txt_inputstarthex18.focus()
        self._txt_inputstophex18 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex18.insert(0, '256')
        self._txt_inputstophex18.place(x=550,y=315)
        self._txt_inputstophex18.focus()
        self.hex1 = tkinter.Button(self.hex_frame, text=" Rotation 5 Start Scan ",font=("Arial",15),bg="#A3E4D7",command=self.rotation_five).place(x=630,y=240)
        self.start3= tkinter.Button(self.hex_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start3, fg='green').place(x=700,y=180)
        self.stop3= tkinter.Button(self.hex_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop3, fg='red').place(x=760,y=180)
        self.totalbtc_rot = tkinter.Label(self.hex_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=690,y=70)
        self.foundbtc_rot = tkinter.Label(self.hex_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbtc_rot.place(x=750,y=120)
        self.get_infoROT = tkinter.Button(self.hex_frame, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationROT, relief=RAISED, bd=3).place(x=710, y=535)
        ########### mining_frame ###########
        self.mine_title = tkinter.Label(self.mine_frame, text="Bitcoin Solo Mining ",font=("Arial",20),bg="#F0F0F0",fg="Black").place(x=180,y=100)
        self.labeladd_mine = tkinter.Label(self.mine_frame, text="Insert Your Address bitcoin Address  ", font=("Arial",15),fg="red").place(x=220,y=140)
        self._txt_inputadd_mine = tkinter.Entry(self.mine_frame, width=40, font=("Consolas", 16))
        self._txt_inputadd_mine.insert(0, '3GCypcW8LWzNfJEsTvcFwUny3ygPzpTfL4')
        self._txt_inputadd_mine.place(x=100,y=180)
        self._txt_inputadd_mine.focus()
        self.mine_label1 = tkinter.Label(self.mine_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.mine_label1.place(x=20,y=280)
        self.mine_label2 = tkinter.Label(self.mine_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.mine_label2.place(x=20,y=300)
        self.mine_label3 = tkinter.Label(self.mine_frame, bg="#F0F0F0",font=("Arial",18),text="",fg="red")
        self.mine_label3.place(x=80,y=330)
        self.startmine= tkinter.Button(self.mine_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= self.miz_miner, fg='green').place(x=700,y=180)
        #self.startmine= tkinter.Button(self.mine_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= self.stop, fg='red').place(x=760,y=180)
        self.totalbtc_mine = tkinter.Label(self.mine_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=690,y=70)
        self.foundbtc_mine = tkinter.Label(self.mine_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbtc_mine.place(x=750,y=120)
        self.get_infoMINE = tkinter.Button(self.mine_frame, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationMINE, relief=RAISED, bd=3).place(x=710, y=535)
        ########### recovery_frame ###########
        self.recovery_title = tkinter.Label(self.recovery_frame, text=" WIF HEX DEC Recovery Tools ",font=("Arial",20),bg="#F0F0F0",fg="Black").place(x=200,y=80)
        self.labeladd_WIF = tkinter.Label(self.recovery_frame, text="WIF HERE (WIF Recovery Tool ****  MAX 10 MISSING  ****)  ", font=("Arial",14),fg="#FF6700").place(x=90,y=130)
        self._txt_inputadd_WIF = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 14))
        self._txt_inputadd_WIF.insert(0, 'KwDiBf89Qg*bjEhKnhXJuH7LrciVrZi3qYjgd*M7rFU*4sHUHy8*')
        self._txt_inputadd_WIF.place(x=20,y=170)
        self._txt_inputadd_WIF.focus()
        self.labeladd_HEX = tkinter.Label(self.recovery_frame, text="HEX HERE (HEX Recovery Tool ****  MAX 10 MISSING  ****)  ", font=("Arial",14),fg="#FF6700").place(x=90,y=195)
        self._txt_inputadd_HEX = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 14))
        self._txt_inputadd_HEX.insert(0, '0**000000000000000000000000000000000000000000000000000000000000*')
        self._txt_inputadd_HEX.place(x=20,y=235)
        self._txt_inputadd_HEX.focus()
        self.labeladd_DEC = tkinter.Label(self.recovery_frame, text="DEC HERE (DEC Recovery Tool ****  MAX 18 MISSING  ****)  ", font=("Arial",14),fg="#FF6700").place(x=90,y=265)
        self._txt_inputadd_DEC = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 14))
        self._txt_inputadd_DEC.insert(0, '***1')
        self._txt_inputadd_DEC.place(x=20,y=300)
        self._txt_inputadd_DEC.focus()
        self.labeladd_WORD = tkinter.Label(self.recovery_frame, text="Mnemonic HERE (Mnm Recovery Tool ****  MAX 5 MISSING  ****)  ", font=("Arial",14),fg="#FF6700").place(x=90,y=330)
        self._txt_inputadd_WORD = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 14))
        self._txt_inputadd_WORD.insert(0, 'pact crush hero laugh edit dolphin wink you broom fish spring *')
        self._txt_inputadd_WORD.place(x=20,y=360)
        self._txt_inputadd_WORD.focus()
        self.labelWIF1 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.labelWIF1.place(x=20,y=390)
        self.labelWIF2 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",11),text="",fg="green")
        self.labelWIF2.place(x=20,y=420)
        self.labelWIF3 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",16),text="",fg="red")
        self.labelWIF3.place(x=20,y=450)
        self.labelREC = tkinter.Label(self.recovery_frame, text="Remaining ", font=("Arial",18),fg="purple").place(x=260,y=500)
        self.labelWIF4 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",18),text="",fg="red")
        self.labelWIF4.place(x=400,y=500)
        self.sqWIF= tkinter.Button(self.recovery_frame, text= "WIF SEQ",font=("Arial",12),bg="#F3F4F8", command= self.start_recovery_wif_S, fg='black').place(x=677,y=165)
        self.sqHEX= tkinter.Button(self.recovery_frame, text= "HEX SEQ",font=("Arial",12),bg="#F3F4F8", command= self.start_recovery_HEX_S, fg='black').place(x=677,y=230)
        self.sqDEC= tkinter.Button(self.recovery_frame, text= "DEC SEQ",font=("Arial",12),bg="#F3F4F8", command= self.start_recovery_DEC_S, fg='black').place(x=677,y=300)
        self.sqMNEMO= tkinter.Button(self.recovery_frame, text= "Word SEQ",font=("Arial",12),bg="#F3F4F8", command= self.start_recovery_MNEMO_S, fg='black').place(x=677,y=370)
        self.ranWIF= tkinter.Button(self.recovery_frame, text= "WIF Random",font=("Arial",12),bg="#F3E4C8", command= self.start_recovery_wif_R, fg='black').place(x=767,y=165)
        self.ranHEX= tkinter.Button(self.recovery_frame, text= "HEX Random",font=("Arial",12),bg="#F3E4C8", command= self.start_recovery_HEX_R, fg='black').place(x=767,y=230)
        self.ranDEC= tkinter.Button(self.recovery_frame, text= "DEC Random",font=("Arial",12),bg="#F3E4C8", command= self.start_recovery_DEC_R, fg='black').place(x=767,y=300)
        self.ranMNEMO= tkinter.Button(self.recovery_frame, text= "Word Random",font=("Arial",12),bg="#F3E4C8", command= self.start_recovery_MNEMO_R, fg='black').place(x=767,y=370)
        self.totalbtc_recovery = tkinter.Label(self.recovery_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple").place(x=690,y=70)
        self.foundbtc_recovery = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.foundbtc_recovery.place(x=750,y=120)
        self.get_infoREC = tkinter.Button(self.recovery_frame, text="Information/Help", width=16, font=("arial", 10, "bold"), activebackground="#F0F0F0",fg="red",bg="#F0F0F0",command=self.informationREC, relief=RAISED, bd=3).place(x=710, y=535)
        self.labeladd_ADD = tkinter.Label(self.recovery_frame, text="Address looking For", font=("Arial",11),fg="#FF6700").place(x=20,y=515)
        self._txt_inputadd_look = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 14))
        self._txt_inputadd_look.insert(0, '0x4fa2345bd9ffb1275eaa2c047dbe56ab250bbaaa')
        self._txt_inputadd_look.place(x=20,y=535)
        self._txt_inputadd_look.focus()

    ########### Recovery Tools  ###########
    def start_recovery_wif_S(self):
        scan_IN = 'WIF'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_WIF.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_HEX_S(self):
        scan_IN = 'HEX'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_HEX.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_DEC_S(self):
        scan_IN = 'DEC'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_DEC.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
    
    def start_recovery_MNEMO_S(self):
        scan_IN = 'mnemonic'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_WORD.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_wif_R(self):
        scan_IN = 'WIF'
        mode = 'random'
        rec_IN = self._txt_inputadd_WIF.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_HEX_R(self):
        scan_IN = 'HEX'
        mode = 'random'
        rec_IN = self._txt_inputadd_HEX.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_DEC_R(self):
        scan_IN = 'DEC'
        mode = 'random'
        rec_IN = self._txt_inputadd_DEC.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
    
    def start_recovery_MNEMO_R(self):
        scan_IN = 'mnemonic'
        mode = 'random'
        rec_IN = self._txt_inputadd_WORD.get()
        MIZ.recovery_main(self, scan_IN, rec_IN, mode)
        total+=1
        totaladd+=5
    ########### Mining TOOL ###########   
    def StartMining(self) :
        subscribe_t = NewSubscribeThread(None)
        subscribe_t.start()
        scantext = f'[  {timer()}  ]  [*] Subscribe thread started.'
        logg(scantext)
        self.mine_label1.config(text = scantext)
        self.mine_label1.update()
        time.sleep(1)
        miner_t = CoinMinerThread(None)
        miner_t.start()
        scantext1 = f'[  {timer()}  ]  [*] Bitcoin Miner Thread Started.'
        logg(scantext1)
        self.mine_label2.config(text = scantext1)
        self.mine_label2.update()
        scantext3 = f'[  {timer()}  ]  Mining Has started !!! This is work in progress. \n Check the CMD window to see it working. \n \n While mining you can do other tools.'
        self.mine_label3.config(text = scantext3)
        self.mine_label3.update()
    
    def miz_miner(self):
        global address
        address = self._txt_inputadd_mine.get().strip().replace(" ", "")
        signal(SIGINT , handler)
        self.StartMining()
    ########### Calulator TOOL ###########  
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
        tkinter.Label(self.windowcal_informationcal,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infocal, bg="#F0F0F0").place(x=5,y=15)
        self.windowcal_informationcal.mainloop()
    
    def informationROT(self):
        self.window_informationROT = Toplevel()
        self.window_informationROT.title("Information")
        self.window_informationROT.geometry("600x440")
        self.window_informationROT.iconbitmap('images/miz.ico')
        self.window_informationROT.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.window_informationROT, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=150,y=300)
        tkinter.Label(self.window_informationROT,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infoROT, bg="#F0F0F0").place(x=5,y=15)
        self.window_informationROT.mainloop()

    def informationREC(self):
        self.window_informationREC = Toplevel()
        self.window_informationREC.title("Information")
        self.window_informationREC.geometry("540x440")
        self.window_informationREC.iconbitmap('images/miz.ico')
        self.window_informationREC.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.window_informationREC, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=150,y=300)
        tkinter.Label(self.window_informationREC,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infoREC, bg="#F0F0F0").place(x=5,y=15)
        self.window_informationREC.mainloop()
        
    def informationMAIN(self):
        self.window_informationMAIN = Toplevel()
        self.window_informationMAIN.title("Information")
        self.window_informationMAIN.geometry("540x440")
        self.window_informationMAIN.iconbitmap('images/miz.ico')
        self.window_informationMAIN.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.window_informationMAIN, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=150,y=300)
        tkinter.Label(self.window_informationMAIN,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infoMAIN, bg="#F0F0F0").place(x=5,y=15)
        self.window_informationMAIN.mainloop()
        
    def informationPAGE(self):
        self.window_informationPAGE = Toplevel()
        self.window_informationPAGE.title("Information")
        self.window_informationPAGE.geometry("720x540")
        self.window_informationPAGE.iconbitmap('images/miz.ico')
        self.window_informationPAGE.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.window_informationPAGE, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=170,y=430)
        tkinter.Label(self.window_informationPAGE,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infoPAGE, bg="#F0F0F0").place(x=5,y=15)
        self.window_informationPAGE.mainloop()
    
    def informationBRAIN(self):
        self.window_informationBRAIN = Toplevel()
        self.window_informationBRAIN.title("Information")
        self.window_informationBRAIN.geometry("800x440")
        self.window_informationBRAIN.iconbitmap('images/miz.ico')
        self.window_informationBRAIN.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.window_informationBRAIN, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=270,y=300)
        tkinter.Label(self.window_informationBRAIN,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infoBRAIN, bg="#F0F0F0").place(x=5,y=15)
        self.window_informationBRAIN.mainloop()
        
    def informationWORD(self):
        self.window_informationWORD = Toplevel()
        self.window_informationWORD.title("Information")
        self.window_informationWORD.geometry("620x440")
        self.window_informationWORD.iconbitmap('images/miz.ico')
        self.window_informationWORD.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.window_informationWORD, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=230,y=300)
        tkinter.Label(self.window_informationWORD,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infoWORD, bg="#F0F0F0").place(x=5,y=15)
        self.window_informationWORD.mainloop()
        
    def informationMINE(self):
        self.window_informationMINE = Toplevel()
        self.window_informationMINE.title("Information")
        self.window_informationMINE.geometry("780x540")
        self.window_informationMINE.iconbitmap('images/miz.ico')
        self.window_informationMINE.config(bg="#F0F0F0")
        self.widget = tkinter.Label(self.window_informationMINE, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=290,y=440)
        tkinter.Label(self.window_informationMINE,fg="black",font=("arial",11,"bold","italic"),text=MIZINFO.infoMINE, bg="#F0F0F0").place(x=5,y=15)
        self.window_informationMINE.mainloop()
        
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
    ###########  Brute PAGE Program Main ###########
    def brute_results_page(self, page):
        global total, totaladd
        scantext = MIZ.get_page(self, page)
        self.page_brute.config(text = scantext)
        self.page_brute.update()
        total+=128
        totaladd+=512
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
    
    def Random_Bruteforce_Speed_page(self):
        startpage = self._txt_inputstartpage.get().strip().replace(" ", "")
        stoppage = self._txt_inputstoppage.get().strip().replace(" ", "")
        while run1:
            page =int(RandomInteger(int(startpage), int(stoppage)))
            self.brute_results_page(page)
    
    def Sequential_Bruteforce_speed_page(self):
        startpage = self._txt_inputstartpage.get().strip().replace(" ", "")
        stoppage = self._txt_inputstoppage.get().strip().replace(" ", "")
        mag = self._txt_inputmagpage.get().strip().replace(" ", "")
        while run1:
            dec = int(startpage)
            if dec == int(stoppage):
                self.stop1()
            else:
                self.brute_results_page(dec)
                startpage = int(startpage) + int(mag)
    
    def Sequential_Bruteforce_speed_back_page(self):
        startpage = self._txt_inputstartpage.get().strip().replace(" ", "")
        stoppage = self._txt_inputstoppage.get().strip().replace(" ", "")
        mag = self._txt_inputmagpage.get().strip().replace(" ", "")
        while run1:
            dec = int(stoppage)
            if dec == int(startpage):
                self.stop1()
            else:
                self.brute_results_page(dec)
                stoppage = int(stoppage) - int(mag)
    ###########  Brute Program Main ###########
    def brute_results(self, dec):
        global total, totaladd
        scantext = MIZ.brute_btc(self, dec)
        self.bfr.config(text = scantext)
        self.bfr.update()
        total+=1
        totaladd+=4
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
    
    def brute_results_online(self, dec):
        global total, totaladd
        scantext = MIZ.super_bal(self, dec)
        self.bfr.config(text = scantext)
        self.bfr.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
        
    def Random_Bruteforce_Speed_online(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        while self.run:
            dec =int(RandomInteger(int(startdec), int(stopdec)))
            self.brute_results_online(dec)

    def Sequential_Bruteforce_speed_online(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        mag = self._txt_inputmag.get().strip().replace(" ", "")
        while self.run:
            dec = int(startdec)
            if dec == int(stopdec):
                self.stop()
            else:
                self.brute_results_online(dec)
                startdec = int(startdec) + int(mag)
    
    def Sequential_Bruteforce_speed_back_online(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        mag = self._txt_inputmag.get().strip().replace(" ", "")
        while self.run:
            dec = int(stopdec)
            if dec == int(startdec):
                self.stop()
            else:
                self.brute_results_online(dec)
                stopdec = int(stopdec) - int(mag)

    ###########  Rotation 5 Program Main ###########
    def rotation_results(self, dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18):
        global total, totaladd
        scantext = MIZ.hexhunter(self, dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18)
        self.rotation_brute.config(text = scantext)
        self.rotation_brute.update()
        total+=20   # 2560
        totaladd+= 100  #  12800
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def rotation_five(self):
        startbit = self._txt_inputstarthex.get().strip().replace(" ", "")
        stopbit = self._txt_inputstophex.get().strip().replace(" ", "")
        startbit0 = self._txt_inputstarthex0.get().strip().replace(" ", "")
        stopbit0 = self._txt_inputstophex0.get().strip().replace(" ", "")
        startbit1 = self._txt_inputstarthex1.get().strip().replace(" ", "")
        stopbit1 = self._txt_inputstophex1.get().strip().replace(" ", "")
        startbit2 = self._txt_inputstarthex2.get().strip().replace(" ", "")
        stopbit2 = self._txt_inputstophex2.get().strip().replace(" ", "")
        startbit3 = self._txt_inputstarthex3.get().strip().replace(" ", "")
        stopbit3 = self._txt_inputstophex3.get().strip().replace(" ", "")
        startbit4 = self._txt_inputstarthex4.get().strip().replace(" ", "")
        stopbit4 = self._txt_inputstophex4.get().strip().replace(" ", "")
        startbit5 = self._txt_inputstarthex5.get().strip().replace(" ", "")
        stopbit5 = self._txt_inputstophex5.get().strip().replace(" ", "")
        startbit6 = self._txt_inputstarthex6.get().strip().replace(" ", "")
        stopbit6 = self._txt_inputstophex6.get().strip().replace(" ", "")
        startbit7 = self._txt_inputstarthex7.get().strip().replace(" ", "")
        stopbit7 = self._txt_inputstophex7.get().strip().replace(" ", "")
        startbit8 = self._txt_inputstarthex8.get().strip().replace(" ", "")
        stopbit8 = self._txt_inputstophex8.get().strip().replace(" ", "")
        startbit9 = self._txt_inputstarthex9.get().strip().replace(" ", "")
        stopbit9 = self._txt_inputstophex9.get().strip().replace(" ", "")
        startbit10 = self._txt_inputstarthex10.get().strip().replace(" ", "")
        stopbit10 = self._txt_inputstophex10.get().strip().replace(" ", "")
        startbit11 = self._txt_inputstarthex11.get().strip().replace(" ", "")
        stopbit11 = self._txt_inputstophex11.get().strip().replace(" ", "")
        startbit12 = self._txt_inputstarthex12.get().strip().replace(" ", "")
        stopbit12 = self._txt_inputstophex12.get().strip().replace(" ", "")
        startbit13 = self._txt_inputstarthex13.get().strip().replace(" ", "")
        stopbit13 = self._txt_inputstophex13.get().strip().replace(" ", "")
        startbit14 = self._txt_inputstarthex14.get().strip().replace(" ", "")
        stopbit14 = self._txt_inputstophex14.get().strip().replace(" ", "")
        startbit15 = self._txt_inputstarthex15.get().strip().replace(" ", "")
        stopbit15 = self._txt_inputstophex15.get().strip().replace(" ", "")
        startbit16 = self._txt_inputstarthex16.get().strip().replace(" ", "")
        stopbit16 = self._txt_inputstophex16.get().strip().replace(" ", "")
        startbit17 = self._txt_inputstarthex17.get().strip().replace(" ", "")
        stopbit17 = self._txt_inputstophex17.get().strip().replace(" ", "")
        startbit18 = self._txt_inputstarthex18.get().strip().replace(" ", "")
        stopbit18 = self._txt_inputstophex18.get().strip().replace(" ", "")
        while run3:
            dec =int(RandomInteger(2**(int(startbit)), 2**(int(stopbit))))
            dec0 =int(RandomInteger(2**(int(startbit0)), 2**(int(stopbit0))))
            dec1 =int(RandomInteger(2**(int(startbit1)), 2**(int(stopbit1))))
            dec2 =int(RandomInteger(2**(int(startbit2)), 2**(int(stopbit2))))
            dec3 =int(RandomInteger(2**(int(startbit3)), 2**(int(stopbit3))))
            dec4 =int(RandomInteger(2**(int(startbit4)), 2**(int(stopbit4))))
            dec5 =int(RandomInteger(2**(int(startbit5)), 2**(int(stopbit5))))
            dec6 =int(RandomInteger(2**(int(startbit6)), 2**(int(stopbit6))))
            dec7 =int(RandomInteger(2**(int(startbit7)), 2**(int(stopbit7))))
            dec8 =int(RandomInteger(2**(int(startbit8)), 2**(int(stopbit8))))
            dec9 =int(RandomInteger(2**(int(startbit9)), 2**(int(stopbit9))))
            dec10 =int(RandomInteger(2**(int(startbit10)), 2**(int(stopbit10))))
            dec11 =int(RandomInteger(2**(int(startbit11)), 2**(int(stopbit11))))
            dec12 =int(RandomInteger(2**(int(startbit12)), 2**(int(stopbit12))))
            dec13 =int(RandomInteger(2**(int(startbit13)), 2**(int(stopbit13))))
            dec14 =int(RandomInteger(2**(int(startbit14)), 2**(int(stopbit14))))
            dec15 =int(RandomInteger(2**(int(startbit15)), 2**(int(stopbit15))))
            dec16 =int(RandomInteger(2**(int(startbit16)), 2**(int(stopbit16))))
            dec17 =int(RandomInteger(2**(int(startbit17)), 2**(int(stopbit17))))
            dec18 =int(RandomInteger(2**(int(startbit18)), 2**(int(stopbit18))))
            self.rotation_results(dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18)
    ###########  Brain Program Main ###########
    def brain_results_online(self, passphrase):
        global total, totaladd
        brainvartext = passphrase
        brainvartext1 = MIZ.rbonline(self, passphrase)
        self.brain_update.config(text = brainvartext)
        self.brain_update1.config(text = brainvartext1)
        self.brain_update.update()
        self.brain_update1.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
    
    def Random_brain_cal(self):
        passphrase = self.result.get().strip()
        global total, totaladd
        brainvartextca1 = MIZ.rbonline(self, passphrase)
        self.brain_updatecal1.config(text = brainvartextca1)
        self.brain_updatecal1.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
        
    def Random_brain_single(self):
        passphrase = self._txt_inputbrain.get().strip()
        global total, totaladd
        brainvartext = passphrase
        brainvartext1 = MIZ.rbonline(self, passphrase)
        self.brain_update.config(text = brainvartext)
        self.brain_update1.config(text = brainvartext1)
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
        brainvartext = passphrase
        brainvartext1 = MIZ.rboffline(self, passphrase)
        self.brain_update.config(text = brainvartext)
        self.brain_update1.config(text = brainvartext1)
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
        self.popwin.title("BitcoinHunter.py")
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
        #self.popwin.after(2000,lambda:self.popwin.destroy())
        ########### START Window POP UP ###########
    def startpop(self):
        self.pop = Toplevel()
        self.pop.title("BitHunter.py")
        #self.pop.iconbitmap('images/miz.ico')
        self.pop.geometry("500x300")
        self.widgetpop = tkinter.Label(self.pop, compound='top')
        self.widgetpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetpop['text'] = "© MIZOGG 2018 - 2022"
        self.widgetpop['image'] = self.widgetpop.miz_image_png
        self.widgetpop.place(x=140,y=220)
        self.label = tkinter.Label(self.pop, text='Welcome to BitcoinHunter...... \n\n Made By Mizogg.co.uk \n\n Version 1.14 12/06/23').pack(pady=10)
        self.label1 = tkinter.Label(self.pop, text= "BitcoinHunter application use at your own risk.\n There is no promise of warranty.\n\n  Auto Agree 5 secs", font=('Helvetica 8 bold')).pack(pady=10)
        self.framepop = Frame(self.pop)
        self.framepop.pack(pady=10)
        self.buttonpop = Button(self.framepop, text=" Agree ", command=lambda: self.pop.destroy())
        self.buttonpop.grid(row=0, column=1)
        self.buttonpop = Button(self.framepop, text=" Disagree ", command=quit)
        self.buttonpop.grid(row=0, column=2)
        self.pop.after(5000,lambda:self.pop.destroy())
        
    def CLOSEWINDOW(self):
        self.pop.destroy()
    ########### CPU and RAM Counter ###########
    def cpu_met(self):
        self.cpu_use = psutil.cpu_percent()
        self.cpu_label.config(text='Total CPU {} %'.format(self.cpu_use))
        self.cpu_label.after(1000,self.cpu_met)
        self.ram_use = psutil.virtual_memory()[2]
        self.ram_label.config(text='RAM Used {} %'.format(self.ram_use))
        ram_free = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
        self.ram_free = str(ram_free)[:4]
        self.ram_free_label.config(text='RAM Free {} %'.format(self.ram_free))
    ########### TIME Counter ###########    
    def time(self):
        self.stringtime = strftime('%H:%M:%S %p')
        self.lbl.config(text = self.stringtime)
        self.lbl.after(1000, self.time)

        ###########  Mnemonic Program Main ###########
    def word_results_online(self, rnds):
        global total, totaladd
        mnem = MIZ.create_valid_mnemonics(strength=int(rnds))
        wordvar = mnem
        wordvartext = MIZ.rwonline(self, mnem)
        self.word_update.config(text = wordvar)
        self.word_update1.config(text = wordvartext)
        self.word_update.update()
        self.word_update1.update()
        total+=1
        totaladd+=3
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
    
    def Random_word_online(self):
        while run2:
            rnds = '16'
            self.word_results_online(rnds)
            
    def Random_word_online1(self):
        while run2:
            rnds = '32'
            self.word_results_online(rnds)
            
    def Random_word_online2(self):
        while run2:
            rnds = '64'
            self.word_results_online(rnds)
            
    def Random_word_online3(self):
        while run2:
            rnds = '96'
            self.word_results_online(rnds)
            
    def Random_word_online4(self):
        while run2:
            rnds = '128'
            self.word_results_online(rnds)
            
    def Random_word_online5(self):
        while run2:
            rnds = '160'
            self.word_results_online(rnds)
            
    def Random_word_online6(self):
        while run2:
            rnds = '192'
            self.word_results_online(rnds)
            
    def Random_word_online7(self):
        while run2:
            rnds = '224'
            self.word_results_online(rnds)
            
    def Random_word_online8(self):
        while run2:
            rnds = '256'
            self.word_results_online(rnds)
        
    def Random_word_single(self):
        mnem = self._txt_inputword.get()
        self.random_word_results(mnem)
        
    def Random_word_random(self):
        lenght= ('128','256')
        rnds = random.choice(lenght)
        mnem = MIZ.create_valid_mnemonics(strength=int(rnds))
        self.random_word_results(mnem)
    
    def random_word_results(self, mnem):
        global total, totaladd
        wordvar = mnem
        wordvartext = MIZ.rwonline(self, mnem)
        self.word_update.config(text = wordvar)
        self.word_update1.config(text = wordvartext)
        self.word_update1.update()
        self.word_update.update()
        total+=1
        totaladd+=1
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
        
    def word_results_offline(self, rnds):
        global total, totaladd
        mnem = MIZ.create_valid_mnemonics(strength=int(rnds))
        wordvartext = MIZ.rwoffline(self, mnem)
        self.word_update.config(text = mnem)
        self.word_update1.config(text = wordvartext)
        self.word_update.update()
        self.word_update1.update()
        total+=1
        totaladd+=3
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def Random_word_offline(self):
        while run2:
            rnds = '16'
            self.word_results_offline(rnds)

    def Random_word_offline1(self):
        while run2:
            rnds = '32'
            self.word_results_offline(rnds)

    def Random_word_offline2(self):
        while run2:
            rnds = '64'
            self.word_results_offline(rnds)

    def Random_word_offline3(self):
        while run2:
            rnds = '96'
            self.word_results_offline(rnds)

    def Random_word_offline4(self):
        while run2:
            rnds = '128'
            self.word_results_offline(rnds)

    def Random_word_offline5(self):
        while run2:
            rnds = '160'
            self.word_results_offline(rnds)

    def Random_word_offline6(self):
        while run2:
            rnds = '192'
            self.word_results_offline(rnds)

    def Random_word_offline7(self):
        while run2:
            rnds = '224'
            self.word_results_offline(rnds)

    def Random_word_offline8(self):
        while run2:
            rnds = '256'
            self.word_results_offline(rnds)
    ########### Conversion Main Program ###########
    def evt_btc_bin(self):
        try:
            bin_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = MIZ.bin2dec(bin_value)
            hex_value = MIZ.bin2hex(bin_value)
            bit_value = MIZ.bin2bit(bin_value)
            btc_value = MIZ.int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
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
        except Exception as ex:
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
    ########### START ###########
    def mainloop(self):
        self.startpop()
        self.cpu_met()
        self.time()
        self.main_frame.mainloop()

if __name__ == "__main__":
    win = MainWindow()
    win.mainloop()
