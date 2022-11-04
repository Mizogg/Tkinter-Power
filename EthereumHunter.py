#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 04.11.2022 https://t.me/CryptoCrackersUK
from tkinter import * 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
from time import strftime, sleep
from pathlib import Path
import secp256k1 as ice
import random
import webbrowser
import hmac, struct, time, codecs, sys, os, binascii, hashlib

try:
    import base58
    import ecdsa
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    from lxml import html
    import requests
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import numpy as np

except ImportError:
    import subprocess
    subprocess.check_call(["python", '-m', 'pip', 'install', 'base58'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'ecdsa'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'simplebloomfilter'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bitarray==1.9.2'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'lxml'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'requests'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bit'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'numpy'])
    import base58
    import ecdsa
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    from lxml import html
    import requests
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import numpy as np
# ============================================================================= 
# Ethereum Price chart
# =============================================================================
def price(exchange=''):
    url = 'https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=GBP,USD,EUR'
    page = requests.get(url)
    data = page.json()
    return data
# ============================================================================= 
# Balance Checking
# ============================================================================= 
def get_balance(ethaddr):
    urlblock = "https://ethereum.atomicwallet.io/address/" + ethaddr
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    return source_code
# ============================================================================= 
# FOR Conversion TAB
# ============================================================================= 
def bin2dec(value):
    return int(value, 2)

def bin2hex(value):
    return hex(int(value, 2))

def dec2bin(value):
    return bin(int(value))

def dec2hex(value):
    return hex(int(value))

def hex2bin(value):
    return bin(int(value, 16))

def hex2dec(value):
    return int(value, 16)

def addr2int(value):
    source_code = get_balance(value)
    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    balanceid = source_code.xpath(balance_id)
    balance = str(balanceid[0].text_content())
    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    txsid = source_code.xpath(txs_id)
    txs = str(txsid[0].text_content())
    dataadd= (f'''==================================================================================
Ethereum Address : {value} : 
:Balance: [{balance}] :Transactions: [{txs}]
==================================================================================
''')
    return dataadd

def int2addr(value):
    dec=int(value)
    HEX = "%064x" % dec
    ethaddr = ice.privatekey_to_ETH_address(dec)
    
    source_code = get_balance(ethaddr)
    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    balanceid = source_code.xpath(balance_id)
    balance = str(balanceid[0].text_content())
    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    txsid = source_code.xpath(txs_id)
    txs = str(txsid[0].text_content())
    dataadd= (f'''==================================================================================
Ethereum Address : {ethaddr} : 
:Balance: [{balance}] :Transactions: [{txs}]
==================================================================================
''')
    return dataadd
# ============================================================================= 
# For Menu
# ============================================================================= 
def donothing():
   x = 0

def openweb():
   x = webbrowser.open("https://mizogg.co.uk")
   
def opentelegram():
   x = webbrowser.open("https://t.me/CryptoCrackersUK")

def hunter16x16():
    x =  os.system('python 16x16.py')  
# ============================================================================= 
# For Word Tab
# ============================================================================= 
derivation_total_path_to_check = 1
order	= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

with open('files/english.txt') as f:
    wordlist = f.read().split('\n')
    
def create_valid_mnemonics(strength):

    rbytes = os.urandom(strength // 8)
    h = hashlib.sha256(rbytes).hexdigest()
    
    b = ( bin(int.from_bytes(rbytes, byteorder="big"))[2:].zfill(len(rbytes) * 8) \
         + bin(int(h, 16))[2:].zfill(256)[: len(rbytes) * 8 // 32] )
    
    result = []
    for i in range(len(b) // 11):
        idx = int(b[i * 11 : (i + 1) * 11], 2)
        result.append(wordlist[idx])

    return " ".join(result)

def mnem_to_seed(words):
    salt = 'mnemonic'
    seed = hashlib.pbkdf2_hmac("sha512",words.encode("utf-8"), salt.encode("utf-8"), 2048)
    return seed


def bip39seed_to_bip32masternode(seed):
    h = hmac.new(b'Ethereum seed', seed, hashlib.sha512).digest()
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
#        key = bytes(PublicKey(parent_key))
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
    const = "m/44'/60'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/44'/60'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def random_word_results(self, mnem):
    seed = mnem_to_seed(mnem)
    pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
    ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk, "big"))
    dec = (int.from_bytes(pvk, "big"))
    HEX = "%064x" % dec
    cpath = "m/44'/60'/0'/0/0"
    source_code = get_balance(ethaddr)
    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    balanceid = source_code.xpath(balance_id)
    balance = str(balanceid[0].text_content())
    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    txsid = source_code.xpath(txs_id)
    txs = str(txsid[0].text_content())
    wordvar = tkinter.StringVar()
    wordvar.set(mnem)
    wordvartext = tkinter.StringVar()
    wordvartext1 = (f'''====================================================:Balance:TXS:
Ethereum Address : {ethaddr} : [{balance}] : [{txs}]
Hexadecimal Private Key : {HEX}
==================================================================================
''')
    wordvartext.set(wordvartext1)
    self.word_update.config(textvariable = wordvar, relief='flat')
    self.word_update1.config(textvariable = wordvartext, relief='flat')
    self.word_update1.update()
    self.word_update.update()
# ============================================================================= 


information = ('''
https://en.wikipedia.org/wiki/Ethereum

Ethereum is a decentralized, open-source blockchain with smart contract functionality. Ether (Abbreviation: ETH; sign: Ξ) is the native cryptocurrency of the platform. 
Among cryptocurrencies, ether is second only to bitcoin in market capitalization.

Ethereum was conceived in 2013 by programmer Vitalik Buterin. Additional founders of Ethereum included Gavin Wood, Charles Hoskinson, 
Anthony Di Iorio and Joseph Lubin.

In 2014, development work began and was crowdfunded, and the network went live on 30 July 2015. 
Ethereum allows anyone to deploy permanent and immutable decentralized applications onto it, with which users can interact.
Decentralized finance (DeFi) applications provide a broad array of financial services without the need for typical financial intermediaries like brokerages,
exchanges, or banks, such as allowing cryptocurrency users to borrow against their holdings or lend them out for interest. 
 
 Ethereum also allows users to create and exchange NFTs, which are unique tokens representing ownership of an associated asset or privilege, 
 as recognized by any number of institutions. 
 
 Additionally, many other cryptocurrencies utilize the ERC-20 token standard on top of the Ethereum blockchain and have utilized the platform for initial coin offerings.

On 15 September 2022, Ethereum transitioned its consensus mechanism from proof-of-work (PoW) to proof-of-stake (PoS) in an upgrade process known as "the Merge".

Ethereum addresses are composed of the prefix "0x" (a common identifier for hexadecimal) concatenated with the rightmost 20 bytes of the Keccak-256 
hash of the ECDSA public key (the curve used is the so-called secp256k1). In hexadecimal, two digits represent a byte, 
and so addresses contain 40 hexadecimal digits, e.g. 0xb794f5ea0ba39494ce839613fffba74279579268. 

Contract addresses are in the same format, however, they are determined by sender and creation transaction nonce.
''')

creditsinfo = ('''
            Look for Ethereum with tkinter and python in GUI.

                    Made By Mizogg.co.uk
                        Version = 1.0

        More Information and help please check links in menu help !!!
''')
# =============================================================================
# BrainWallet
# ============================================================================= 
class BrainWallet:

    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = str(hashlib.sha256(
            passphrase.encode('utf-8')).hexdigest())
        address =  BrainWallet.generate_address_from_private_key(private_key)
        return private_key, address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Add Ethereum byte
        Ethereum_byte = b'04'
        public_key = Ethereum_byte + key_hex
        return public_key

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        # Run ripemd160 for the SHA256
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        # Add network byte
        network_byte = b'00'
        network_Ethereum_public_key = network_byte + ripemd160_bpk_hex
        network_Ethereum_public_key_bytes = codecs.decode(
            network_Ethereum_public_key, 'hex')
        # Double SHA256 to get checksum
        sha256_nbpk = hashlib.sha256(network_Ethereum_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        # Concatenate public key and checksum to get the address
        address_hex = (network_Ethereum_public_key + checksum).decode('utf-8')
        wallet = BrainWallet.base58(address_hex)
        return wallet

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        # Convert hex to decimal
        address_int = int(address_hex, 16)
        # Append digits to the start of string
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string
# ============================================================================= 
# Database Load and Files
# ============================================================================= 
mylist = []
with open('eth.bf', "rb") as fp:
    bloom_filterETH = BloomFilter.load(fp)
addr_count = len(bloom_filterETH)  
addr_count_print = f'Total Ethereum Addresses Loaded and Checking : {addr_count}'
    
# =============================================================================  
with open('files/words.txt', newline='', encoding='utf-8') as f:
    for line in f:
        mylist.append(line.strip())

max_p = 115792089237316195423570985008687907852837564279074904382605163141518161494336
totaladd = total = found =0
run = run1 = run2 = True
# SAVE and Sart
filenamestart = 'startdec.txt'
path = Path(filenamestart)

if path.is_file():
    with open(filenamestart, newline='', encoding='utf-8') as f:
        contents = f.readline()
        startdec = int(contents)

else:
    startdec = 1
stopdec = max_p

class MainWindow():
    C_FONT = ("Consolas", 16)
    C_TXT_MAXLEN = 30
    def __init__(self):   
        def start():
           global run
           run= True

        def stop():
           global run
           run= False
           
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

        def RandomInteger(minN, maxN):
            return random.randrange(minN, maxN)

        def popwin(WINTEXT):
            global popwin
            popwin = Toplevel(self._window)
            popwin.title("EthereumHunter.py")
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
        # ============================================================================= 
        #  Brute Program Main
        # ============================================================================= 
        def brute_results(dec):
            global total, totaladd, found
            ethaddr = ice.privatekey_to_ETH_address(int(dec))
            HEX = "%064x" % dec
            length = len(bin(dec))
            length -=2
            if ethaddr in bloom_filterETH:
                self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nETH Address : {ethaddr}')
                found+=1
                self.l8.config(text = f'{found}')
                with open('found.txt', 'a') as result:
                    result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nETH Address : {ethaddr}\n')
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nETH Address : {ethaddr}")
                popwin(WINTEXT)
            self.l2.config(text = f'\n DEC Key: {dec}\n Bits {length} \n\n HEX Key: {HEX} \n\n ETH Address : {ethaddr}')
            self.l2.update()
            total+=1
            totaladd+=1
            self.l4.config(text = f'{total}')
            self.l6.config(text = f'{totaladd}')

        def Random_Bruteforce_Speed():
            while run:
                dec =int(RandomInteger(startdec, stopdec))
                brute_results(dec)

        def Sequential_Bruteforce_speed():
            while run:
                global startdec
                START = startdec
                STOP = stopdec
                dec = int(START)
                brute_results(dec)
                startdec = startdec +1
        # ============================================================================= 
        #  Brain Program Main
        # =============================================================================
        def brain_results_online(passphrase):
            global total, totaladd, found
            wallet = BrainWallet()
            private_key, addr = wallet.generate_address_from_passphrase(passphrase)
            dec = int(private_key, 16)
            ethaddr = ice.privatekey_to_ETH_address(int(dec))
            source_code = get_balance(ethaddr)
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())
            brainvar = tkinter.StringVar()
            brainvar.set(passphrase)
            brainvartext = tkinter.StringVar()
            brainvartext1 = (f'\n Private Key In HEX : \n\n {private_key} \n\n Ethereum Adress : {ethaddr} \n Balance  [{balance}]  Transactions : [{txs}]')
            brainvartext.set(brainvartext1)
            self.brain_update.config(textvariable = brainvar, relief='flat')
            self.brain_update1.config(textvariable = brainvartext, relief='flat')
            if int(txs) > 0 :
                found+=1
                self.l88.config(text = f'{found}')
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Ethereum Adress : {ethaddr} \n Balance  [{balance}]  Transactions : [{txs}]')
                WINTEXT = (f"Passphrase {passphrase}\n HEX Key: {private_key} \n BTC Address : {ethaddr}  \n \n Balance  [{balance}]  Transactions : [{txs}]")
                popwin(WINTEXT)
            self.brain_update.update()
            self.brain_update1.update()
            total+=1
            totaladd+=1
            self.l44.config(text = f'{total}')
            self.l66.config(text = f'{totaladd}')
        
        def Random_brain_online():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(1,3)))
                brain_results_online(passphrase)
                
                
        def Random_brain_online1():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(3,9)))
                brain_results_online(passphrase)

        def Random_brain_online2():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(9,15)))
                brain_results_online(passphrase)
                
        def Random_brain_online3():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(15,18)))
                brain_results_online(passphrase)

        def Random_brain_online4():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(18,21)))
                brain_results_online(passphrase)

        def Random_brain_online5():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(21,24)))
                brain_results_online(passphrase)
        
        def Random_brain_online6():
            while run1:
                for i in range(0,len(mylist)):
                    passphrase = mylist[i]
                    brain_results_online(passphrase)

        def brain_results_offline(passphrase):
            global total, totaladd, found
            wallet = BrainWallet()
            private_key, addr = wallet.generate_address_from_passphrase(passphrase)
            dec = int(private_key, 16)
            ethaddr = ice.privatekey_to_ETH_address(int(dec))
            brainvar = tkinter.StringVar()
            brainvar.set(passphrase)
            brainvartext = tkinter.StringVar()
            brainvartext1 = (f'\n Private Key In HEX : \n\n {private_key} \n\n Ethereum Adress : {ethaddr} ')
            brainvartext.set(brainvartext1)
            self.brain_update.config(textvariable = brainvar, relief='flat')
            self.brain_update1.config(textvariable = brainvartext, relief='flat')
            if ethaddr in bloom_filterETH:
                found+=1
                self.l88.config(text = f'{found}')
                WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Ethereum Adress : {ethaddr}')
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            self.brain_update.update()
            self.brain_update1.update()
            total+=1
            totaladd+=1
            self.l44.config(text = f'{total}')
            self.l66.config(text = f'{totaladd}')
            
            
        def Random_brain_offline():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(1,3)))
                brain_results_offline(passphrase)

        def Random_brain_offline1():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(3,9)))
                brain_results_offline(passphrase)

        def Random_brain_offline2():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(9,15)))
                brain_results_offline(passphrase)

        def Random_brain_offline3():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(15,18)))
                brain_results_offline(passphrase)

        def Random_brain_offline4():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(18,21)))
                brain_results_offline(passphrase)
                
        def Random_brain_offline5():
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(21,24)))
                brain_results_offline(passphrase)
                
        def Random_brain_offline6():
            while run1:
                for i in range(0,len(mylist)):
                    passphrase = mylist[i]
                    brain_results_offline(passphrase)
        # ============================================================================= 
        #  Mnemonic Program Main
        # ============================================================================= 
        def word_results_online(rnds):
            global total, totaladd, found
            mnem = create_valid_mnemonics(strength=int(rnds))
            seed = mnem_to_seed(mnem)
            pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
            dec = (int.from_bytes(pvk, "big"))
            HEX = "%064x" % dec
            ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk, "big"))
            source_code = get_balance(ethaddr)
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())
            wordvar = tkinter.StringVar()
            wordvar.set(mnem)
            wordvartext = tkinter.StringVar()
            wordvartext1 = (f'\n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX} \n Ethereum Adress : {ethaddr} \n Balance  [{balance}]  Transactions : [{txs}]')
            wordvartext.set(wordvartext1)
            self.word_update.config(textvariable = wordvar, relief='flat')
            self.word_update1.config(textvariable = wordvartext, relief='flat')
            if int(txs) > 0 :
                found+=1
                self.l888.config(text = f'{found}')
                WINTEXT = f'\n Mnemonic : {mnem} \n Dec Key: {dec} \n HEX Key: {HEX} \n Ethereum Adress : {ethaddr} \n Balance  [{balance}] ] Transactions : [{txs}]'
                with open('found.txt', 'a', encoding='utf-8') as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            self.word_update.update()
            self.word_update1.update()
            total+=1
            totaladd+=1
            self.l444.config(text = f'{total}')
            self.l666.config(text = f'{totaladd}')
        
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
            global total, totaladd, found
            mnem = create_valid_mnemonics(strength=int(rnds))
            seed = mnem_to_seed(mnem)
            pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
            dec = (int.from_bytes(pvk, "big"))
            HEX = "%064x" % dec
            cpath = "m/44'/60'/0'/0/0"
            ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk, "big"))
            wordvar = tkinter.StringVar()
            wordvar.set(mnem)
            wordvartext = tkinter.StringVar()
            wordvartext1 = (f' Ethereum {cpath} :  {ethaddr} \n Ethereum {cpath} : Decimal Private Key \n {dec} \n Ethereum {cpath} : Hexadecimal Private Key \n {HEX}')
            wordvartext.set(wordvartext1)
            self.word_update.config(textvariable = wordvar, relief='flat')
            self.word_update1.config(textvariable = wordvartext, relief='flat')
            if ethaddr in bloom_filterETH:
                found+=1
                self.l888.config(text = f'{found}')
                WINTEXT = f'\n Mnemonic: {mnem} \n Ethereum {cpath} :  {ethaddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            self.word_update.update()
            self.word_update1.update()
            total+=1
            totaladd+=1
            self.l444.config(text = f'{total}')
            self.l666.config(text = f'{totaladd}')

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
        # ============================================================================= 
        #  Main Window Program Menu Bar
        # ============================================================================= 
        self._window = tkinter.Tk()
        self._window.title("EthereumHunter.py @ Mizogg.co.uk")
        self._window.iconbitmap('images/miz.ico')
        self._window.config(bg="black")
        self._window.geometry("860x660")
        self._window.resizable(False, False)
        self._window.menubar = Menu(self._window)
        self._window.filemenu = Menu(self._window.menubar, tearoff=0)
        # self._window.filemenu.add_command(label="New", command=donothing)
        # self._window.filemenu.add_command(label="Edit Start DEC", command=donothing)
        # self._window.filemenu.add_command(label="Save", command=donothing)
        self._window.filemenu.add_separator()
        self._window.filemenu.add_command(label="Exit", command=self._window.quit)
        self._window.menubar.add_cascade(label="File", menu=self._window.filemenu)
        self._window.helpmenu = Menu(self._window.menubar, tearoff=0)
        self._window.helpmenu.add_command(label="Help Telegram Group", command=opentelegram)
        self._window.helpmenu.add_command(label="Mizogg Website", command=openweb)
        self._window.helpmenu.add_command(label="About EthereumHunter", command=self.startpop)
        self._window.menubar.add_cascade(label="Help", menu=self._window.helpmenu)
        self._window.config(menu=self._window.menubar)
        self.my_notebook = ttk.Notebook(self._window)
        self.my_notebook.pack(pady=5)
        self.main_frame = Frame(self.my_notebook, width=840, height=620)
        self.Ethereum_frame = Frame(self.my_notebook, width=840, height=620)
        self.brain_frame = Frame(self.my_notebook, width=840, height=620)
        self.word_frame = Frame(self.my_notebook, width=840, height=620)
        self.about_frame = Frame(self.my_notebook, width=840, height=620)
        self.credits_frame = Frame(self.my_notebook, width=840, height=620)
        self.main_frame.pack(fill="both", expand=1)
        self.Ethereum_frame.pack(fill="both", expand=1)
        self.brain_frame.pack(fill="both", expand=1)
        self.word_frame.pack(fill="both", expand=1)
        self.about_frame.pack(fill="both", expand=1)
        self.credits_frame.pack(fill="both", expand=1)
        # Add our Tabs and Order of them
        self.my_notebook.add(self.Ethereum_frame, text="Ethereum Hunting")
        self.my_notebook.add(self.main_frame, text="Conversion Tools ")
        self.my_notebook.add(self.brain_frame, text="Brain Hunting")
        self.my_notebook.add(self.word_frame, text="Mnemonic Hunting")
        self.my_notebook.add(self.about_frame, text="About Ethereum")
        self.my_notebook.add(self.credits_frame, text="Credits")
        # ============================================================================= 
        #  Main Tab
        # ============================================================================= 
        label = tkinter.Label(self.main_frame, text=" Type:", font=MainWindow.C_FONT)
        label.place(x=5,y=100)
        self._txt_input = tkinter.Entry(self.main_frame, width=46, font=MainWindow.C_FONT)
        self._txt_input.place(x=80,y=100)
        self._txt_input.focus()
        self._bt_bin = tkinter.Button(self.main_frame, text="Bin", font=MainWindow.C_FONT, command=self.evt_bt_bin)
        self._bt_bin.place(x=645,y=100)
        self._bt_dec = tkinter.Button(self.main_frame, text="Dec", font=MainWindow.C_FONT, command=self.evt_bt_dec)
        self._bt_dec.place(x=715,y=100)
        self._bt_hex = tkinter.Button(self.main_frame, text="Hex", font=MainWindow.C_FONT, command=self.evt_bt_hex)
        self._bt_hex.place(x=785,y=100)
        self._rd_dec = tkinter.Button(self.main_frame, text="Random", font=MainWindow.C_FONT, command=self.evt_rd_dec)
        self._rd_dec.place(x=15,y=150)
        labeladdr = tkinter.Label(self.main_frame, text=" When Searching for adress it will generate a random private key this will not match the address", font=("Arial", 10))
        labeladdr.place(x=150,y=150)
        self._bt_ip = tkinter.Button(self.main_frame, text="Address", font=MainWindow.C_FONT, command=self.evt_bt_ip)
        self._bt_ip.place(x=715,y=150)
        label = tkinter.Label(self.main_frame, text="  Binary ", font=MainWindow.C_FONT)
        label.place(x=5,y=200)
        self._stringvar_bin = tkinter.StringVar()
        txt_output = tkinter.Entry(self.main_frame, textvariable=self._stringvar_bin, width=56, font=MainWindow.C_FONT)
        txt_output.place(x=130,y=200)
        label = tkinter.Label(self.main_frame, text=" Decimal ", font=MainWindow.C_FONT)
        label.place(x=5,y=240)
        self._stringvar_dec = tkinter.StringVar()
        txt_output = tkinter.Entry(self.main_frame, textvariable=self._stringvar_dec, width=56, font=MainWindow.C_FONT)
        txt_output.place(x=130,y=240)
        label = tkinter.Label(self.main_frame, text="Hexadecimal ", font=MainWindow.C_FONT)
        label.place(x=2,y=280)
        self._stringvar_hex = tkinter.StringVar()
        txt_output = tkinter.Entry(self.main_frame, textvariable=self._stringvar_hex, width=48, font=MainWindow.C_FONT)
        txt_output.place(x=150,y=280)
        label1 = tkinter.Label(self.main_frame, text=" ETH Address ", font=MainWindow.C_FONT)
        label1.place(x=300,y=310)
        self._stringvar_addr = tkinter.StringVar()
        txt_output = tkinter.Label(self.main_frame, textvariable=self._stringvar_addr, font=("Arial", 12))
        txt_output.place(x=50,y=350)
        # =============================================================================
        #  Widgets 
        # =============================================================================
        def time():
            string = strftime('%H:%M:%S %p')
            lbl.config(text = string)
            lbl.after(1000, time)
        self.widget = tkinter.Label(self._window, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=590,y=30)
        self.widgetHunter = tkinter.Button(self._window, text= "16x16 BTC Hunter ",font=("Arial",10),bg="gold", command= hunter16x16)
        self.widgetHunter.place(x=690,y=590)
        lbl = tkinter.Label(self._window, font = ('calibri', 40, 'bold'), background = '#F0F0F0', foreground = 'purple')
        lbl.place(x=10,y=30)
        time()
        # =============================================================================
        # about_frame
        # =============================================================================
        about1 = tkinter.Frame(master = self.about_frame, bg = '#F0F0F0')
        about1.pack(fill='both', expand='yes')
        pricelable_data = f"Todays Ethereum Price £ {price('ETH')} "
        pricelable = tkinter.Label(master = about1, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple")
        pricelable.place(x=90, y=530)
        editArea = tkst.ScrolledText(master = about1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        editArea.insert(tkinter.INSERT, information)
        # =============================================================================
        # credits_frame
        # =============================================================================
        credits1 = tkinter.Frame(master = self.credits_frame, bg = '#F0F0F0')
        credits1.pack(fill='both', expand='yes')
        pricelable_data = f"Todays Ethereum Price £ {price('ETH')} "
        pricelable = tkinter.Label(master = credits1, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple")
        pricelable.place(x=90, y=530)
        editArea = tkst.ScrolledText(master = credits1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        editArea.insert(tkinter.INSERT, creditsinfo)
        # =============================================================================
        # brain_frame
        # =============================================================================
        self.l33 = tkinter.Label(self.brain_frame, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l44 = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l55 = tkinter.Label(self.brain_frame, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l66 = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l77 = tkinter.Label(self.brain_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple")
        self.l88 = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        # =============================================================================
        self.l33.place(x=330,y=5)
        self.l44.place(x=470,y=5)
        self.l55.place(x=330,y=25)
        self.l66.place(x=470,y=25)
        self.l77.place(x=680,y=70)
        self.l88.place(x=740,y=120)
        self.brain_update = tkinter.Entry(self.brain_frame, state='readonly', bg="#F0F0F0",font=("Arial",12),text="", width=80, fg="Red")
        self.brain_update.place(x=30,y=310)
        self.brain_update1 = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",14),text="")
        self.brain_update1.place(x=60,y=350)
        self.start1= tkinter.Button(self.brain_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start1)
        self.stop1= tkinter.Button(self.brain_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop1)
        self.start1.place(x=690,y=180)
        self.stop1.place(x=750,y=180)
        labelbrain = tkinter.Label(self.brain_frame, text="Brain \nWords ", font=("Arial",13))
        labelbrain.place(x=5,y=75)
        self._txt_inputbrain = tkinter.Entry(self.brain_frame, width=36, font=MainWindow.C_FONT)
        self._txt_inputbrain.place(x=80,y=80)
        self._txt_inputbrain.focus()
        self._bt_bin = tkinter.Button(self.brain_frame, text="Enter", font=MainWindow.C_FONT, command=self.Random_brain_single)
        self._bt_bin.place(x=545,y=75)
        self.titleb = tkinter.Label(self.brain_frame, text="Brain Wallet Words ",font=("Arial",16),bg="#F0F0F0",fg="Black")
        self.titleb.place(x=380,y=270)
        self.title1 = tkinter.Label(self.brain_frame, text="Random Brain Wallet Generator Online Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.title1.place(x=60,y=130)
        self.title2 = tkinter.Label(self.brain_frame, text="Random Brain Wallet Generator Offline Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.title2.place(x=60,y=130)
        # Create our  Brain Buttons
        self.my_button = tkinter.Button(self.brain_frame, text= "1 Word ",font=("Arial",10),bg="#B6E1A4", command= Random_brain_online6)
        self.my_button.place(x=10,y=160)
        self.my_button = tkinter.Button(self.brain_frame, text= "1-3 Words ",font=("Arial",10),bg="#A3E4A7", command= Random_brain_online)
        self.my_button.place(x=73,y=160)
        self.my_button = tkinter.Button(self.brain_frame, text= "3-9 Words ",font=("Arial",10),bg="#A3E4B7", command= Random_brain_online1)
        self.my_button.place(x=155,y=160)
        self.my_button = tkinter.Button(self.brain_frame, text= "9-15 Words ",font=("Arial",10),bg="#A3E4C7", command= Random_brain_online2)
        self.my_button.place(x=240,y=160)
        self.my_button = tkinter.Button(self.brain_frame, text= "15-18 Words ",font=("Arial",10),bg="#A3E4D7", command= Random_brain_online3)
        self.my_button.place(x=330,y=160)
        self.my_button = tkinter.Button(self.brain_frame, text= "18-21 Words ",font=("Arial",10),bg="#A3E4E7", command= Random_brain_online4)
        self.my_button.place(x=430,y=160)
        self.my_button = tkinter.Button(self.brain_frame, text= "21-24 Words ",font=("Arial",10),bg="#A3E4F7", command= Random_brain_online5)
        self.my_button.place(x=530,y=160)
        self.my_button = tkinter.Button(self.brain_frame, text= "1 Word ",font=("Arial",10),bg="#B6E1A4", command= Random_brain_offline6)
        self.my_button.place(x=10,y=220)
        self.my_button = tkinter.Button(self.brain_frame, text= "1-3 Words ",font=("Arial",10),bg="#A3E4A7", command= Random_brain_offline)
        self.my_button.place(x=73,y=220)
        self.my_button = tkinter.Button(self.brain_frame, text= "3-9 Words ",font=("Arial",10),bg="#A3E4B7", command= Random_brain_offline1)
        self.my_button.place(x=155,y=220)
        self.my_button = tkinter.Button(self.brain_frame, text= "9-15 Words ",font=("Arial",10),bg="#A3E4C7", command= Random_brain_offline2)
        self.my_button.place(x=240,y=220)
        self.my_button = tkinter.Button(self.brain_frame, text= "15-18 Words ",font=("Arial",10),bg="#A3E4D7", command= Random_brain_offline3)
        self.my_button.place(x=330,y=220)
        self.my_button = tkinter.Button(self.brain_frame, text= "18-21 Words ",font=("Arial",10),bg="#A3E4E7", command= Random_brain_offline4)
        self.my_button.place(x=430,y=220)
        self.my_button = tkinter.Button(self.brain_frame, text= "21-24 Words ",font=("Arial",10),bg="#A3E4F7", command= Random_brain_offline5)
        self.my_button.place(x=530,y=220)
        # =============================================================================
        # Ethereum_frame
        # =============================================================================
        self.l1 = tkinter.Label(self.Ethereum_frame, text="Random Wallet Generator ",font=("Arial",20),bg="#F0F0F0",fg="Black")
        self.t1 = tkinter.Label(self.Ethereum_frame, text=addr_count_print,font=("Arial",14),bg="#F0F0F0",fg="Black")
        self.r1 = tkinter.Button(self.Ethereum_frame, text="Generate Random Wallets ",font=("Arial",15),bg="#A3E4D7",command=Random_Bruteforce_Speed)
        self.s1 = tkinter.Button(self.Ethereum_frame, text="Generate Sequential Wallets ",font=("Arial",15),bg="#A3E4D7",command=Sequential_Bruteforce_speed)
        self.start= tkinter.Button(self.Ethereum_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start)
        self.stop= tkinter.Button(self.Ethereum_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop)
        self.l2 = tkinter.Label(self.Ethereum_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l3 = tkinter.Label(self.Ethereum_frame, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l4 = tkinter.Label(self.Ethereum_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l5 = tkinter.Label(self.Ethereum_frame, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l6 = tkinter.Label(self.Ethereum_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l7 = tkinter.Label(self.Ethereum_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple")
        self.l8 = tkinter.Label(self.Ethereum_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        pricelable_data = f"Todays Ethereum Price £ {price('ETH')} "
        pricelable = tkinter.Label(self.Ethereum_frame, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple")
        pricelable.place(x=90, y=530)
        # =============================================================================
        self.l1.place(x=100,y=70)
        self.t1.place(x=80,y=110)
        self.r1.place(x=60,y=140)
        self.s1.place(x=360,y=140)
        self.start.place(x=690,y=180)
        self.stop.place(x=750,y=180)
        self.l2.place(x=30,y=220)
        self.l3.place(x=300,y=5)
        self.l4.place(x=440,y=5)
        self.l5.place(x=300,y=25)
        self.l6.place(x=440,y=25)
        self.l7.place(x=680,y=70)
        self.l8.place(x=740,y=120)
        # =============================================================================
        # word_frame
        # =============================================================================
        self.l333 = tkinter.Label(self.word_frame, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l444 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l555 = tkinter.Label(self.word_frame, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l666 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l777 = tkinter.Label(self.word_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple")
        self.l888 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        # =============================================================================
        self.l333.place(x=330,y=5)
        self.l444.place(x=470,y=5)
        self.l555.place(x=330,y=25)
        self.l666.place(x=470,y=25)
        self.l777.place(x=680,y=70)
        self.l888.place(x=740,y=120)
        self.word_update = tkinter.Entry(self.word_frame, state='readonly', bg="#F0F0F0",font=("Arial",12),text="", width=80,fg="Red")
        self.word_update.place(x=30,y=280)
        self.word_update1 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",11),text="")
        self.word_update1.place(x=60,y=300)
        self.start2= tkinter.Button(self.word_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start2)
        self.stop2= tkinter.Button(self.word_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop2)
        self.start2.place(x=690,y=180)
        self.stop2.place(x=750,y=180)
        labelword = tkinter.Label(self.word_frame, text="Mnemonic", font=("Arial",13))
        labelword.place(x=5,y=75)
        self._txt_inputword = tkinter.Entry(self.word_frame, width=36, font=MainWindow.C_FONT)
        self._txt_inputword.place(x=90,y=80)
        self._txt_inputword.focus()
        self._word_bin = tkinter.Button(self.word_frame, text="Enter", font=MainWindow.C_FONT, command=self.Random_word_single)
        self._word_bin.place(x=545,y=75)
        self.titlem = tkinter.Label(self.word_frame, text="Mnemonic Words ",font=("Arial",16),bg="#F0F0F0",fg="Black")
        self.titlem.place(x=380,y=250)
        self.titlem1 = tkinter.Label(self.word_frame, text="Random Mnemonic Wallet Generator Online Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.titlem1.place(x=60,y=130)
        self.titlem2 = tkinter.Label(self.word_frame, text="Random Mnemonic Wallet Generator Offline Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.titlem2.place(x=60,y=190)
        self.my_buttonword = tkinter.Button(self.word_frame, text="Random Single", font=("Arial",10),bg="#A3E4A7", command=self.Random_word_random)
        self.my_buttonword.place(x=690,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "1 Word ",font=("Arial",10),bg="#A3E4A7", command= Random_word_online)
        self.my_buttonword.place(x=40,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "3 Words ",font=("Arial",10),bg="#A3E4B7", command= Random_word_online1)
        self.my_buttonword.place(x=100,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "6 Words ",font=("Arial",10),bg="#A3E4C7", command= Random_word_online2)
        self.my_buttonword.place(x=167,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "9 Words ",font=("Arial",10),bg="#A3E4D7", command= Random_word_online3)
        self.my_buttonword.place(x=234,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "12 Words ",font=("Arial",10),bg="#A3E4E7", command= Random_word_online4)
        self.my_buttonword.place(x=301,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "15 Words ",font=("Arial",10),bg="#A3E4F7", command= Random_word_online5)
        self.my_buttonword.place(x=374,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "18 Words ",font=("Arial",10),bg="#F3E4A8", command= Random_word_online6)
        self.my_buttonword.place(x=447,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "21 Words ",font=("Arial",10),bg="#F3E4B8", command= Random_word_online7)
        self.my_buttonword.place(x=520,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "24 Words ",font=("Arial",10),bg="#F3E4C8", command= Random_word_online8)
        self.my_buttonword.place(x=593,y=160)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "1 Word ",font=("Arial",10),bg="#A3E4A7", command= Random_word_offline)
        self.my_buttonword.place(x=40,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "3 Words ",font=("Arial",10),bg="#A3E4B7", command= Random_word_offline1)
        self.my_buttonword.place(x=100,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "6 Words ",font=("Arial",10),bg="#A3E4C7", command= Random_word_offline2)
        self.my_buttonword.place(x=167,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "9 Words ",font=("Arial",10),bg="#A3E4D7", command= Random_word_offline3)
        self.my_buttonword.place(x=234,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "12 Words ",font=("Arial",10),bg="#A3E4E7", command= Random_word_offline4)
        self.my_buttonword.place(x=301,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "15 Words ",font=("Arial",10),bg="#A3E4F7", command= Random_word_offline5)
        self.my_buttonword.place(x=374,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "18 Words ",font=("Arial",10),bg="#F3E4A8", command= Random_word_offline6)
        self.my_buttonword.place(x=447,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "21 Words ",font=("Arial",10),bg="#F3E4B8", command= Random_word_offline7)
        self.my_buttonword.place(x=520,y=220)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "24 Words ",font=("Arial",10),bg="#F3E4C8", command= Random_word_offline8)
        self.my_buttonword.place(x=593,y=220)
    
    def startpop(self):
        global pop
        pop = Toplevel(self._window)
        pop.title("EthereumHunter.py")
        pop.iconbitmap('images/miz.ico')
        pop.geometry("700x250")
        widget = tkinter.Label(pop, compound='top')
        widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        widget['text'] = "© MIZOGG 2018 - 2022"
        widget['image'] = widget.miz_image_png
        widget.place(x=220,y=180)
        # Create a Label Text
        label = Label(pop, text='Welcome to EthereumHunter...... \n\n Made By Mizogg.co.uk \n\n Version 1.5 04/11/22')
        label.pack(pady=10)
        Label(pop, text= "This window will get closed after 3 seconds...", font=('Helvetica 8 bold')).pack(pady=10)
        # Add a Frame
        frame = Frame(pop)
        frame.pack(pady=10)
        # Add Button for making selection
        button1 = Button(frame, text=" Close ",
        command=self.CLOSEWINDOW)
        button1.grid(row=0, column=1)
        pop.after(3000,lambda:pop.destroy())
    
    def CLOSEWINDOW(self):
        pop.destroy()
   
    def Random_brain_single(self):
        passphrase = self._txt_inputbrain.get().strip()
        brain_results_online(passphrase)
        
    def Random_word_single(self):
        mnem = self._txt_inputword.get()
        random_word_results(self, mnem)
        
    def Random_word_random(self):
        lenght= ('128','256')
        rnds = random.choice(lenght)
        mnem = create_valid_mnemonics(strength=int(rnds))
        random_word_results(self, mnem)
    
    def evt_bt_bin(self):
        try:
            bin_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = bin2dec(bin_value)
            hex_value = bin2hex(bin_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, btc_value)
        except Exception:
            tkinter.messagebox.showerror("Error", "Invalid Binary conversion")
            print(ex, file=sys.stderr)
    
    def evt_bt_dec(self):
        try:
            dec_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
            
    def evt_rd_dec(self):
        try:
            dec_value = int(random.randrange(startdec, stopdec))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
        
    def evt_bt_hex(self):
        try:
            hex_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = hex2bin(hex_value)
            dec_value = hex2dec(hex_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Hexadecimal conversion")
            print(ex, file=sys.stderr)
    
    def evt_bt_ip(self):
        try:
            btc_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = int(random.randrange(1, max_p))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            btc_value = addr2int(btc_value)
            self._set_values(bin_value, dec_value, hex_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Address conversion")
            print(ex, file=sys.stderr)
    
    def _set_values(self, bin_value, dec_value, hex_value, btc_value):
        if not bin_value.startswith("0b"):
            bin_value = "0b" + bin_value
        if not hex_value.startswith("0x"):
            hex_value = "0x" + hex_value
        self._stringvar_bin.set(bin_value)
        self._stringvar_dec.set(dec_value)
        self._stringvar_hex.set(hex_value)
        self._stringvar_addr.set(btc_value)
        self._stringvar_bin.set(bin_value)
        self._stringvar_dec.set(dec_value)
        self._stringvar_hex.set(hex_value)
        self._stringvar_addr.set(btc_value)
    
    def mainloop(self):
        self.startpop()
        self.main_frame.mainloop()

if __name__ == "__main__":
    win = MainWindow()
    win.mainloop()