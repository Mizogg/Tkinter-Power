import hmac, struct, codecs, sys, os, binascii, hashlib, base58
import random
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import bit
from bit import Key
import trotter
import webbrowser
from datetime import datetime
from time import strftime, sleep
import secp256k1 as ice
from bloomfilter import BloomFilter
with open('btc.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)

with open('eth.bf', "rb") as fp:
    bloom_filtereth = BloomFilter.load(fp)

with open('eth1.bf', "rb") as fp:
    bloom_filtereth1 = BloomFilter.load(fp)
    
def countadd():
    addr_count = len(bloom_filterbtc) + len(bloom_filtereth) + len(bloom_filtereth1)
    addr_count_print = (f'Total BTC & ETH Addresses Loaded and Checking : {addr_count}')
    return addr_count_print
# For Menu
def donothing():
   x = 0

def openweb():
   x = webbrowser.open("https://mizogg.co.uk")
   
def opentelegram():
   x = webbrowser.open("https://t.me/CryptoCrackersUK")
# WORD Wallet
order	= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

with open('files/english.txt') as f:
    wordlist = f.read().split('\n')

def mnem_to_seed(words):
    salt = 'mnemonic'
    seed = hashlib.pbkdf2_hmac("sha512",words.encode("utf-8"), salt.encode("utf-8"), 2048)
    return seed


def bip39seed_to_bip32masternode(seed):
    h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code

def parse_derivation_path(str_derivation_path="m/44'/0'/0'/0/0"):
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def parse_derivation_path2(str_derivation_path="m/49'/0'/0'/0/0"):      
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/49'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def derive_bip32childkey(parent_key, parent_chain_code, i):
    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & 0x80000000) != 0:
        key = b'\x00' + parent_key
    else:
        key = bit.Key.from_bytes(parent_key).public_key
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % order
        if a < order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code
    
def bip39seed_to_private_key(bip39seed, n=1):
    const = "m/44'/0'/0'/0/"
    str_derivation_path = "m/44'/0'/0'/0/0"
    derivation_path = parse_derivation_path(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key
    
def bip39seed_to_private_key2(bip39seed, n=1):
    const = "m/49'/0'/0'/0/"
    str_derivation_path = "m/49'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key3(bip39seed, n=1):
    const = "m/84'/0'/0'/0/"
    str_derivation_path = "m/84'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key4(bip39seed, n=1):
    const = "m/44'/60'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/44'/60'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

# Recovery Program
def complete_key(rec_IN_string, missing_letters):
    for letter in missing_letters:
        rec_IN_string = rec_IN_string.replace('*', letter, 1)
    return rec_IN_string

def btc_address_from_private_key(my_secret, secret_type):
    assert secret_type in ['WIF', 'HEX', 'DEC', 'mnemonic']
    if secret_type == 'WIF':
        if my_secret.startswith('5H') or my_secret.startswith('5J') or my_secret.startswith('5K') or my_secret.startswith('K') or my_secret.startswith('L'):
            if my_secret.startswith('5H') or my_secret.startswith('5J') or my_secret.startswith('5K'):
                first_encode = base58.b58decode(my_secret)
                private_key_full = binascii.hexlify(first_encode)
                private_key = private_key_full[2:-8]
                private_key_hex = private_key.decode("utf-8")
                dec = int(private_key_hex, 16)
            elif my_secret.startswith('K') or my_secret.startswith('L'):
                first_encode = base58.b58decode(my_secret)
                private_key_full = binascii.hexlify(first_encode)
                private_key = private_key_full[2:-8]
                private_key_hex = private_key.decode("utf-8")
                dec = int(private_key_hex[0:64], 16)
    elif secret_type == 'HEX':
        dec = int(my_secret[0:64], 16)
    elif secret_type == 'mnemonic':
        pass
    elif secret_type == 'DEC':
        dec = int(my_secret)
    else:
        raise Exception("I don't know how to handle this type.")
    return dec

########### THE MAIN PROGRAM Recovery ###########
class MainWindow():
    def __init__(self):
        found =0
        self.found = found
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
        self._window.helpmenu.add_command(label="Help Telegram Group", command=opentelegram)
        self._window.helpmenu.add_command(label="Mizogg Website", command=openweb)
        self._window.helpmenu.add_command(label="About CrytpoHunter", command=self.startpop)
        self._window.menubar.add_cascade(label="Help", menu=self._window.helpmenu)
        self._window.config(menu=self._window.menubar)
        self.my_notebook = ttk.Notebook(self._window)
        self.my_notebook.pack(pady=5)
        self.recovery_frame = Frame(self.my_notebook, width=880, height=700)
        self.recovery_frame.pack(fill="both", expand=1)
        self.my_notebook.add(self.recovery_frame, text="Recovery Tool")
        self.widget = tkinter.Label(self._window, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2023"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=590,y=30)
        self.lbl = tkinter.Label(self._window, font = ('calibri', 28, 'bold'), background = '#F0F0F0', foreground = 'purple')
        self.lbl.place(x=10,y=30)
        self.tpk = tkinter.Label(self._window, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=240,y=30)
        self.totalC = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",12),text="")
        self.totalC.place(x=380,y=30)
        self.totaladd = tkinter.Label(self._window, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=240,y=50)
        self.totalA = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",12),text="")
        self.totalA.place(x=380,y=50)
        self.addcount = tkinter.Label(self._window, text=countadd(),font=("Arial",14),bg="#F0F0F0",fg="purple").place(x=80,y=80)
        ########### recovery_frame ###########
        self.recovery_title = tkinter.Label(self.recovery_frame, text=" WIF HEX DEC Recovery Tools ",font=("Arial",20),bg="#F0F0F0",fg="Black").place(x=200,y=80)
        self.labeladd_WIF = tkinter.Label(self.recovery_frame, text="WIF HERE (WIF Recovery Tool ****  MAX 10 MISSING  ****)  ", font=("Arial",14),fg="#FF6700").place(x=90,y=130)
        self._txt_inputadd_WIF = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 14))
        self._txt_inputadd_WIF.insert(0, 'KwDiBf89*gGbjEhKnhXJuH7Lr*iVrZi3qYjgd9M7rFU74sHUHy8*')
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
        self.labelREC1 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.labelREC1.place(x=20,y=450)
        self.labelREC2 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",11),text="",fg="green")
        self.labelREC2.place(x=20,y=480)
        self.labelREC3 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",16),text="",fg="red")
        self.labelREC3.place(x=20,y=510)
        self.labelREC = tkinter.Label(self.recovery_frame, text="Remaining ", font=("Arial",18),fg="purple").place(x=260,y=560)
        self.labelREC4 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",18),text="",fg="red")
        self.labelREC4.place(x=400,y=560)
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
        self.labeladd_ADD = tkinter.Label(self.recovery_frame, text="Address looking For", font=("Arial",11),fg="#FF6700").place(x=20,y=390)
        self._txt_inputadd_look = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 14))
        self._txt_inputadd_look.insert(0, '1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb')
        self._txt_inputadd_look.place(x=20,y=420)
        self._txt_inputadd_look.focus()

        ########### Recovery Tools  ###########
    def start_recovery_wif_S(self):
        scan_IN = 'WIF'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_WIF.get()
        self.recovery_main(scan_IN, rec_IN, mode)
        
    def start_recovery_HEX_S(self):
        scan_IN = 'HEX'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_HEX.get()
        self.recovery_main(scan_IN, rec_IN, mode)
        
    def start_recovery_DEC_S(self):
        scan_IN = 'DEC'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_DEC.get()
        self.recovery_main(scan_IN, rec_IN, mode)
    
    def start_recovery_MNEMO_S(self):
        scan_IN = 'mnemonic'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_WORD.get()
        self.recovery_main(scan_IN, rec_IN, mode)
        
    def start_recovery_wif_R(self):
        scan_IN = 'WIF'
        mode = 'random'
        rec_IN = self._txt_inputadd_WIF.get()
        self.recovery_main(scan_IN, rec_IN, mode)
        
    def start_recovery_HEX_R(self):
        scan_IN = 'HEX'
        mode = 'random'
        rec_IN = self._txt_inputadd_HEX.get()
        self.recovery_main(scan_IN, rec_IN, mode)
        
    def start_recovery_DEC_R(self):
        scan_IN = 'DEC'
        mode = 'random'
        rec_IN = self._txt_inputadd_DEC.get()
        self.recovery_main(scan_IN, rec_IN, mode)
    
    def start_recovery_MNEMO_R(self):
        scan_IN = 'mnemonic'
        mode = 'random'
        rec_IN = self._txt_inputadd_WORD.get()
        self.recovery_main( scan_IN, rec_IN, mode)
        
    def recovery_main(self, scan_IN, rec_IN, mode):
        totaladd = total = 0
        add_find = self._txt_inputadd_look.get()
        missing_length = rec_IN.count('*')
        key_length = len(rec_IN)
        recoverytext = f'Looking for {missing_length} characters in {rec_IN}'
        self.labelREC1.config(text = recoverytext)
        self.labelREC1.update()
        if scan_IN == 'WIF':
                secret_type = 'WIF'
                allowed_characters = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        elif scan_IN == 'HEX':
                secret_type = 'HEX'
                allowed_characters = '0123456789abcdef'
        elif scan_IN == 'DEC':
                secret_type = 'DEC'
                allowed_characters = '0123456789'
        elif scan_IN == 'mnemonic':
                secret_type = 'mnemonic'
                allowed_characters = wordlist

        missing_letters_master_list = trotter.Amalgams(missing_length, allowed_characters)
        try:
            self.labelREC2.config(text = missing_letters_master_list)
            self.labelREC2.update()
            max_loop_length = len(missing_letters_master_list)
        except OverflowError:
            max_loop_length = sys.maxsize
            if mode == 'sequential':
                print(f"Warning: Some letters will not be processed in sequential mode because "
                      f"the possible space is too large. Try random mode.")
        remaining = max_loop_length
        for i in range(max_loop_length):
            if mode == 'sequential':
                potential_key = complete_key(rec_IN, missing_letters_master_list[i])
            elif mode == 'random':
                potential_key = complete_key(rec_IN, missing_letters_master_list.random())
            if secret_type == 'mnemonic':
                seed = mnem_to_seed(potential_key)
                for i in range (1,5):
                    pvk = bip39seed_to_private_key(seed, i)
                    pvk2 = bip39seed_to_private_key2(seed, i)
                    pvk3 = bip39seed_to_private_key3(seed, i)
                    pvk4 = bip39seed_to_private_key4(seed, i)
                    caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
                    uaddr = ice.privatekey_to_address(0, False, (int.from_bytes(pvk, "big")))
                    p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
                    bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
                    ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
                    #print(f" Path m/44'/60'/0'/0/{i} mnemonic: {potential_key}", end='\r')
            else:
                dec = btc_address_from_private_key(potential_key, secret_type=secret_type)
                uaddr = ice.privatekey_to_address(0, False, dec)
                caddr = ice.privatekey_to_address(0, True, dec)
                p2sh = ice.privatekey_to_address(1, True, dec)
                bech32 = ice.privatekey_to_address(2, True, dec)
                ethaddr = ice.privatekey_to_ETH_address(dec)
            self.labelREC3.config(text = potential_key)
            self.labelREC3.update()
            remaining -= 1
            self.labelREC4.config(text = remaining)
            self.labelREC4.update()
            total+=1
            totaladd+=5
            self.totalC.config(text = f'{total}')
            self.totalA.config(text = f'{totaladd}')
            if caddr in add_find:
                wintext = f"\n key: {potential_key} address: {caddr}"
                f=open('foundcaddr.txt','a')
                f.write(wintext)
                self.found+=1
                self.foundbtc_recovery.config(text = f'{self.found}')
                self.WINTEXT = wintext
                self.popwinner()
            if uaddr in add_find:
                wintext = f"\n key: {potential_key} address: {uaddr}"
                f=open('founduaddr.txt','a')
                f.write(wintext)
                self.found+=1
                self.foundbtc_recovery.config(text = f'{self.found}')
                self.WINTEXT = wintext
                self.popwinner()
            if p2sh in bloom_filterbtc or p2sh in add_find:
                wintext = f"\n key: {potential_key} address: {p2sh}"
                f=open('foundp2sh.txt','a')
                f.write(wintext)
                self.found+=1
                self.foundbtc_recovery.config(text = f'{self.found}')
                self.WINTEXT = wintext
                self.popwinner()
            if bech32 in bloom_filterbtc or bech32 in add_find:
                wintext = f"\n key: {potential_key} address: {bech32}"
                f=open('foundbech32.txt','a')
                f.write(wintext)
                self.found+=1
                self.foundbtc_recovery.config(text = f'{self.found}')
                self.WINTEXT = wintext
                self.popwinner()
            if ethaddr[2:] in bloom_filtereth or ethaddr[2:] in bloom_filtereth1 or ethaddr in add_find.lower():
                wintext = f"\n key: {potential_key} address: {ethaddr}"
                f=open('foundeth.txt','a')
                f.write(wintext)
                self.found+=1
                self.foundbtc_recovery.config(text = f'{self.found}')
                self.WINTEXT = wintext
                self.popwinner()
    def popwinner(self):
        self.popwin = Toplevel()
        self.popwin.title("BitcoinHunter.py")
        self.popwin.iconbitmap('images/miz.ico')
        self.popwin.geometry("700x250")
        self.widgetwinpop = tkinter.Label(self.popwin, compound='top')
        self.widgetwinpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetwinpop['text'] = "© MIZOGG 2018 - 2023"
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
        self.pop.title("BitHunter.py")
        self.pop.iconbitmap('images/miz.ico')
        self.pop.geometry("500x300")
        self.widgetpop = tkinter.Label(self.pop, compound='top')
        self.widgetpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetpop['text'] = "© MIZOGG 2018 - 2023"
        self.widgetpop['image'] = self.widgetpop.miz_image_png
        self.widgetpop.place(x=140,y=220)
        self.label = tkinter.Label(self.pop, text='Welcome to Recovery...... \n\n Made By Mizogg.co.uk \n\n Version 1 11/06/23').pack(pady=10)
        self.label1 = tkinter.Label(self.pop, text= "Recovery application use at your own risk.\n There is no promise of warranty.\n\n  Auto Agree 5 secs", font=('Helvetica 8 bold')).pack(pady=10)
        self.framepop = Frame(self.pop)
        self.framepop.pack(pady=10)
        self.buttonpop = Button(self.framepop, text=" Agree ", command=lambda: self.pop.destroy())
        self.buttonpop.grid(row=0, column=1)
        self.buttonpop = Button(self.framepop, text=" Disagree ", command=quit)
        self.buttonpop.grid(row=0, column=2)
        self.pop.after(5000,lambda:self.pop.destroy())
        
    def time(self):
        self.stringtime = strftime('%H:%M:%S %p')
        self.lbl.config(text = self.stringtime)
        self.lbl.after(1000, self.time)
        
    def mainloop(self):
        self.startpop()
        self.time()
        self.recovery_frame.mainloop()

if __name__ == "__main__":
    win = MainWindow()
    win.mainloop()