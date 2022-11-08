#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 08.11.2022 https://t.me/CryptoCrackersUK
from tkinter import * 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
from time import strftime, sleep
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
# Bitcoin Price chart
# =============================================================================
def price(exchange=''):
    url = 'https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=GBP,USD,EUR'
    page = requests.get(url)
    data = page.json()
    return data
# ============================================================================= 
# Balance Checking
# ============================================================================= 
def get_balance(caddr):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + caddr
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    return source_code
    
def get_balance1(uaddr):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + uaddr
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code1 = html.fromstring(byte_string)
    return source_code1

def get_balance2(p2sh):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + p2sh
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code2 = html.fromstring(byte_string)
    return source_code2

def get_balance3(bech32):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + bech32
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code3 = html.fromstring(byte_string)
    return source_code3
# ============================================================================= 
# FOR Conversion TAB
# ============================================================================= 
def bin2dec(value):
    return int(value, 2)

def bin2hex(value):
    return hex(int(value, 2))
    
def bin2bit(value):
    length = len(bin(int(value, 2)))
    length -=2
    return length
    
def bit2dec(value):
    return 2**(int(value))

def bit2hex(value):
    value = 2**(int(value))
    return hex(value)
    
def bit2bin(value):
    value = 2**(int(value))
    return bin(value)

def dec2bin(value):
    return bin(int(value))

def dec2hex(value):
    return hex(int(value))
    
def dec2bit(value):
    length = len(bin(int(value)))
    length -=2
    return length

def hex2bin(value):
    return bin(int(value, 16))

def hex2dec(value):
    return int(value, 16)
    
def hex2bit(value):
    length = len(bin(int(value, 16)))
    length -=2
    return length

def addr2int(value):
    source_code = get_balance(value)
    received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid = source_code.xpath(received_id)
    totalReceived = str(receivedid[0].text_content())
    sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid = source_code.xpath(sent_id)
    totalSent = str(sentid[0].text_content())
    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid = source_code.xpath(balance_id)
    balance = str(balanceid[0].text_content())
    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid = source_code.xpath(txs_id)
    txs = str(txsid[0].text_content())
    dataadd= (f'''==================================================================================
Bitcoin Address : {value} : 
:Balance: [{balance}] :Total Received: [{totalReceived}] :TotalSent: [{totalSent}] :Transactions: [{txs}]
==================================================================================
''')
    return dataadd

def int2addr(value):
    dec=int(value)
    HEX = "%064x" % dec
    caddr = ice.privatekey_to_address(0, True, dec) #Compressed
    uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
    p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
    bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
    
    source_code = get_balance(caddr)
    received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid = source_code.xpath(received_id)
    totalReceived = str(receivedid[0].text_content())
    sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid = source_code.xpath(sent_id)
    totalSent = str(sentid[0].text_content())
    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid = source_code.xpath(balance_id)
    balance = str(balanceid[0].text_content())
    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid = source_code.xpath(txs_id)
    txs = str(txsid[0].text_content())

    source_code1 = get_balance1(uaddr)
    received_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid1 = source_code1.xpath(received_id1)
    totalReceived1 = str(receivedid1[0].text_content())
    sent_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid1 = source_code1.xpath(sent_id1)
    totalSent1 = str(sentid1[0].text_content())
    balance_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid1 = source_code1.xpath(balance_id1)
    balance1 = str(balanceid1[0].text_content())
    txs_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid1 = source_code1.xpath(txs_id1)
    txs1 = str(txsid1[0].text_content())

    source_code2 = get_balance2(p2sh)
    received_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid2 = source_code2.xpath(received_id2)
    totalReceived2 = str(receivedid2[0].text_content())
    sent_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid2 = source_code2.xpath(sent_id2)
    totalSent2 = str(sentid2[0].text_content())
    balance_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid2 = source_code2.xpath(balance_id2)
    balance2 = str(balanceid2[0].text_content())
    txs_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid2 = source_code2.xpath(txs_id2)
    txs2 = str(txsid2[0].text_content())

    source_code3 = get_balance3(bech32)
    received_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid3 = source_code3.xpath(received_id3)
    totalReceived3 = str(receivedid3[0].text_content())
    sent_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid3 = source_code3.xpath(sent_id3)
    totalSent3 = str(sentid3[0].text_content())
    balance_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid3 = source_code3.xpath(balance_id3)
    balance3 = str(balanceid3[0].text_content())
    txs_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid3 = source_code3.xpath(txs_id3)
    txs3 = str(txsid3[0].text_content())
    dataadd= (f'''====================================================:Balance:Received:Sent:TXS:
Bitcoin Address : {caddr} : [{balance}] : [{totalReceived}] : [{totalSent}] : [{txs}]
Bitcoin Address : {uaddr} : [{balance1}] : [{totalReceived1}] : [{totalSent1}] : [{txs1}]
Bitcoin Address : {p2sh} : [{balance2}] : [{totalReceived2}] : [{totalSent2}] : [{txs2}]
Bitcoin Address : {bech32} : [{balance3}] : [{totalReceived3}] : [{totalSent3}] : [{txs3}]
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
   
def opensnake():
    x =  os.system('python btcsnake.py')

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

def random_word_results(self, mnem):
    global total, totaladd, found
    seed = mnem_to_seed(mnem)
    pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
    pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
    pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
    caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
    p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
    bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
    dec = (int.from_bytes(pvk, "big"))
    HEX = "%064x" % dec
    dec2 = (int.from_bytes(pvk2, "big"))
    HEX2 = "%064x" % dec2
    dec3 = (int.from_bytes(pvk3, "big"))
    HEX3 = "%064x" % dec3
    cpath = "m/44'/0'/0'/0/0"
    ppath = "m/49'/0'/0'/0/0"
    bpath = "m/84'/0'/0'/0/0"
    source_code = get_balance(caddr)
    received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid = source_code.xpath(received_id)
    totalReceived = str(receivedid[0].text_content())
    sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid = source_code.xpath(sent_id)
    totalSent = str(sentid[0].text_content())
    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid = source_code.xpath(balance_id)
    balance = str(balanceid[0].text_content())
    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid = source_code.xpath(txs_id)
    txs = str(txsid[0].text_content())
    source_code2 = get_balance2(p2sh)
    received_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid2 = source_code2.xpath(received_id2)
    totalReceived2 = str(receivedid2[0].text_content())
    sent_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid2 = source_code2.xpath(sent_id2)
    totalSent2 = str(sentid2[0].text_content())
    balance_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid2 = source_code2.xpath(balance_id2)
    balance2 = str(balanceid2[0].text_content())
    txs_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid2 = source_code2.xpath(txs_id2)
    txs2 = str(txsid2[0].text_content())
    source_code3 = get_balance3(bech32)
    received_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
    receivedid3 = source_code3.xpath(received_id3)
    totalReceived3 = str(receivedid3[0].text_content())
    sent_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
    sentid3 = source_code3.xpath(sent_id3)
    totalSent3 = str(sentid3[0].text_content())
    balance_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    balanceid3 = source_code3.xpath(balance_id3)
    balance3 = str(balanceid3[0].text_content())
    txs_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    txsid3 = source_code3.xpath(txs_id3)
    txs3 = str(txsid3[0].text_content())
    wordvar = tkinter.StringVar()
    wordvar.set(mnem)
    wordvartext = tkinter.StringVar()
    wordvartext1 = (f'''====================================================:Balance:Received:Sent:TXS:
Bitcoin Address : {caddr} : [{balance}] : [{totalReceived}] : [{totalSent}] : [{txs}]
Hexadecimal Private Key : {HEX}

Bitcoin Address : {p2sh} : [{balance2}] : [{totalReceived2}] : [{totalSent2}] : [{txs2}]
Hexadecimal Private Key : {HEX2}

Bitcoin Address : {bech32} : [{balance3}] : [{totalReceived3}] : [{totalSent3}] : [{txs3}]
Hexadecimal Private Key : {HEX3}
==================================================================================
''')
    wordvartext.set(wordvartext1)
    self.word_update.config(textvariable = wordvar, relief='flat')
    self.word_update1.config(textvariable = wordvartext, relief='flat')
    self.word_update1.update()
    self.word_update.update()
    if int(txs) > 0 or int(txs2) > 0 or int(txs3) > 0:
        found+=1
        self.l888.config(text = f'{found}')
        WINTEXT = f'\n Mnemonic : {mnem} \n\n {wordvartext1}'
        with open('found.txt', 'a', encoding='utf-8') as f:
            f.write(WINTEXT)
    total+=1
    totaladd+=1
    self.l444.config(text = f'{total}')
    self.l666.config(text = f'{totaladd}')
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
                            Version = 1.8
                    New features added to Bitcoin Generator

                            Version = 1.7
                New Conversion BITS to HEX DEC Binary
                Plus and Minus Ranges in conversion
                Updates to brain and Words auto start input
            Input start and stop Decimal main Bitcoin Generator
        1 Brain word from list TODO make stop function on 1 Brain

                            Version = 1.6
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

                            Version = 1.2
                    Added Brain Online and Oflline
                        Added Conversion Tools
                        Added Atomic Wallet API
                Big Thanks TO @Clintsoff and CryptoCrackers
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
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        wallet = BrainWallet.base58(address_hex)
        return wallet

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        address_int = int(address_hex, 16)
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string
# ============================================================================= 
# Database Load and Files
# ============================================================================= 
mylist = []
with open('puzzle.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)
addr_count = len(bloom_filterbtc)  
addr_count_print = f'Total Bitcoin Addresses Loaded and Checking : {addr_count}'
    
# =============================================================================  
with open('files/words.txt', newline='', encoding='utf-8') as f:
    for line in f:
        mylist.append(line.strip())

max_p = 115792089237316195423570985008687907852837564279074904382605163141518161494336
totaladd = total = found =0
run = run1 = run2 = True

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
            caddr = ice.privatekey_to_address(0, True, dec)
            uaddr = ice.privatekey_to_address(0, False, dec)
            HEX = "%064x" % dec
            wifc = ice.btc_pvk_to_wif(HEX)
            wifu = ice.btc_pvk_to_wif(HEX, False)
            p2sh = ice.privatekey_to_address(1, True, dec)
            bech32 = ice.privatekey_to_address(2, True, dec)
            length = len(bin(dec))
            length -=2
            if caddr in bloom_filterbtc:
                self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}')
                found+=1
                self.l8.config(text = f'{found}')
                with open('found.txt', 'a') as result:
                    result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}")
                popwin(WINTEXT)
            if uaddr in bloom_filterbtc:
                self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
                found+=1
                self.l8.config(text = f'{found}')
                with open('found.txt', 'a') as result:
                    result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}")
                popwin(WINTEXT)
            if p2sh in bloom_filterbtc:
                self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
                found+=1
                self.l8.config(text = f'{found}')
                with open('found.txt', 'a') as result:
                    result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh} \n')
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh}")
                popwin(WINTEXT)
            if bech32 in bloom_filterbtc:
                self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
                found+=1
                self.l8.config(text = f'{found}')
                with open('found.txt', 'a') as result:
                    result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
                WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address bech32: {bech32}")
                popwin(WINTEXT)
            scantext = f'''
            *** DEC Key ***
 {dec}
        Bits {length}
        *** HEY Key ***
    {HEX}
 BTC Address Compressed: {caddr}
        WIF Compressed: {wifc}
 BTC Address Uncompressed: {uaddr}
        WIF Compressed: {wifu}
 BTC Address p2sh: {p2sh}
 BTC Address bech32: {bech32}
====================================='''
            self.l2.config(text = scantext)
            self.l2.update()
            total+=1
            totaladd+=4
            self.l4.config(text = f'{total}')
            self.l6.config(text = f'{totaladd}')

        def Random_Bruteforce_Speed():
            startdec = self._txt_inputstart.get().strip().replace(" ", "")
            stopdec = self._txt_inputstop.get().strip().replace(" ", "")
            while run:
                dec =int(RandomInteger(int(startdec), int(stopdec)))
                brute_results(dec)

        def Sequential_Bruteforce_speed():
            startdec = self._txt_inputstart.get().strip().replace(" ", "")
            stopdec = self._txt_inputstop.get().strip().replace(" ", "")
            mag = self._txt_inputmag.get().strip().replace(" ", "")
            while run:
                dec = int(startdec)
                if dec == int(stopdec):
                    stop()
                else:
                    brute_results(dec)
                    startdec = int(startdec) + int(mag)
        
        def Sequential_Bruteforce_speed_back():
            startdec = self._txt_inputstart.get().strip().replace(" ", "")
            stopdec = self._txt_inputstop.get().strip().replace(" ", "")
            mag = self._txt_inputmag.get().strip().replace(" ", "")
            while run:
                dec = int(stopdec)
                if dec == int(startdec):
                    stop()
                else:
                    brute_results(dec)
                    stopdec = int(stopdec) - int(mag)
        # ============================================================================= 
        #  Brain Program Main
        # =============================================================================
        def brain_results_online(passphrase):
            global total, totaladd, found
            wallet = BrainWallet()
            private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
            source_code = get_balance(caddr)
            received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid = source_code.xpath(received_id)
            totalReceived = str(receivedid[0].text_content())
            sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid = source_code.xpath(sent_id)
            totalSent = str(sentid[0].text_content())
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())
            brainvar = tkinter.StringVar()
            brainvar.set(passphrase)
            brainvartext = tkinter.StringVar()
            brainvartext1 = (f'\n Private Key In HEX : \n\n {private_key} \n\n Bitcoin Adress : {caddr} \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
            brainvartext.set(brainvartext1)
            self.brain_update.config(textvariable = brainvar, relief='flat')
            self.brain_update1.config(textvariable = brainvartext, relief='flat')
            if int(txs) > 0 :
                found+=1
                self.l88.config(text = f'{found}')
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
                WINTEXT = (f"Passphrase {passphrase}\n HEX Key: {private_key} \n BTC Address Compressed: {caddr}  \n \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]")
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
            for i in range(0,len(mylist)):
                passphrase = mylist[i]
                brain_results_online(passphrase)

        def brain_results_offline(passphrase):
            global total, totaladd, found
            wallet = BrainWallet()
            private_key, addr = wallet.generate_address_from_passphrase(passphrase)
            brainvar = tkinter.StringVar()
            brainvar.set(passphrase)
            brainvartext = tkinter.StringVar()
            brainvartext1 = (f'\n Private Key In HEX : \n\n {private_key} \n\n Bitcoin Adress : {addr} ')
            brainvartext.set(brainvartext1)
            self.brain_update.config(textvariable = brainvar, relief='flat')
            self.brain_update1.config(textvariable = brainvartext, relief='flat')
            if addr in bloom_filterbtc:
                found+=1
                self.l88.config(text = f'{found}')
                WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {addr}')
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
            caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
            source_code = get_balance(caddr)
            received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid = source_code.xpath(received_id)
            totalReceived = str(receivedid[0].text_content())
            sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid = source_code.xpath(sent_id)
            totalSent = str(sentid[0].text_content())
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())
            wordvar = tkinter.StringVar()
            wordvar.set(mnem)
            wordvartext = tkinter.StringVar()
            wordvartext1 = (f'\n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
            wordvartext.set(wordvartext1)
            self.word_update.config(textvariable = wordvar, relief='flat')
            self.word_update1.config(textvariable = wordvartext, relief='flat')
            if int(txs) > 0 :
                found+=1
                self.l888.config(text = f'{found}')
                WINTEXT = f'\n Mnemonic : {mnem} \n Dec Key: {dec} \n HEX Key: {HEX} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]'
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
            pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
            pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
            dec = (int.from_bytes(pvk, "big"))
            HEX = "%064x" % dec
            dec2 = (int.from_bytes(pvk2, "big"))
            HEX2 = "%064x" % dec2
            dec3 = (int.from_bytes(pvk3, "big"))
            HEX3 = "%064x" % dec3
            cpath = "m/44'/0'/0'/0/0"
            ppath = "m/49'/0'/0'/0/0"
            bpath = "m/84'/0'/0'/0/0"
            caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
            p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
            bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
            wordvar = tkinter.StringVar()
            wordvar.set(mnem)
            wordvartext = tkinter.StringVar()
            wordvartext1 = (f' Bitcoin {cpath} :  {caddr} \n Bitcoin {cpath} : Decimal Private Key \n {dec} \n Bitcoin {cpath} : Hexadecimal Private Key \n {HEX}  \n Bitcoin {ppath} :  {p2sh}\n Bitcoin {ppath} : Decimal Private Key \n {dec2} \n Bitcoin {ppath} :  Hexadecimal Private Key \n {HEX2} \n Bitcoin {bpath} : {bech32}\n Bitcoin {bpath} : Decimal Private Key \n {dec3} \n Bitcoin {bpath} : Hexadecimal Private Key \n {HEX3} ')
            wordvartext.set(wordvartext1)
            self.word_update.config(textvariable = wordvar, relief='flat')
            self.word_update1.config(textvariable = wordvartext, relief='flat')
            if caddr in bloom_filterbtc:
                found+=1
                self.l888.config(text = f'{found}')
                WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {cpath} :  {caddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            if p2sh in bloom_filterbtc:
                found+=1
                self.l888.config(text = f'{found}')
                WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {ppath} :  {p2sh}\nDecimal Private Key \n {dec2} \n Hexadecimal Private Key \n {HEX2} \n'
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            if bech32 in bloom_filterbtc:
                found+=1
                self.l888.config(text = f'{found}')
                WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {bpath} : {bech32}\n Decimal Private Key \n {dec3} \n Hexadecimal Private Key \n {HEX3} \n'
                with open("found.txt", "a", encoding="utf-8") as f:
                    f.write(WINTEXT)
                popwin(WINTEXT)
            self.word_update.update()
            self.word_update1.update()
            total+=1
            totaladd+=4
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
        self._window.title("BitcoinHunter.py @ Mizogg.co.uk")
        self._window.iconbitmap('images/miz.ico')
        self._window.config(bg="black")
        self._window.geometry("860x660")
        self._window.resizable(False, False)
        self._window.menubar = Menu(self._window)
        self._window.filemenu = Menu(self._window.menubar, tearoff=0)
        # self._window.filemenu.add_command(label="New", command=donothing)
        # self._window.filemenu.add_command(label="Edit", command=donothing)
        # self._window.filemenu.add_command(label="Save", command=donothing)
        self._window.filemenu.add_separator()
        self._window.filemenu.add_command(label="Exit", command=self._window.quit)
        self._window.menubar.add_cascade(label="File", menu=self._window.filemenu)
        self._window.helpmenu = Menu(self._window.menubar, tearoff=0)
        self._window.helpmenu.add_command(label="Help Telegram Group", command=opentelegram)
        self._window.helpmenu.add_command(label="Mizogg Website", command=openweb)
        self._window.helpmenu.add_command(label="About BitcoinHunter", command=self.startpop)
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
        self.main_frame.pack(fill="both", expand=1)
        self.bitcoin_frame.pack(fill="both", expand=1)
        self.brain_frame.pack(fill="both", expand=1)
        self.word_frame.pack(fill="both", expand=1)
        self.about_frame.pack(fill="both", expand=1)
        self.credits_frame.pack(fill="both", expand=1)
        self.my_notebook.add(self.bitcoin_frame, text="Bitcoin Hunting")
        self.my_notebook.add(self.main_frame, text="Conversion Tools ")
        self.my_notebook.add(self.brain_frame, text="Brain Hunting")
        self.my_notebook.add(self.word_frame, text="Mnemonic Hunting")
        self.my_notebook.add(self.about_frame, text="About Bitcoin")
        self.my_notebook.add(self.credits_frame, text="Credits")
        # ============================================================================= 
        #  Main Tab
        # ============================================================================= 
        label = tkinter.Label(self.main_frame, text=" Type \n Data \n Here ", font=MainWindow.C_FONT)
        label.place(x=5,y=70)
        self._txt_input = tkinter.Entry(self.main_frame, width=56, font=MainWindow.C_FONT)
        self._txt_input.insert(0, '1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF')
        self._txt_input.place(x=80,y=100)
        self._txt_input.focus()
        self._btc_bin = tkinter.Button(self.main_frame, text="Bin", font=MainWindow.C_FONT, command=self.evt_btc_bin)
        self._btc_bin.place(x=270,y=45)
        self._btc_dec = tkinter.Button(self.main_frame, text="Dec", font=MainWindow.C_FONT, command=self.evt_btc_dec)
        self._btc_dec.place(x=330,y=45)
        self._btc_bit = tkinter.Button(self.main_frame, text="Bits", font=MainWindow.C_FONT, command=self.evt_btc_bit)
        self._btc_bit.place(x=450,y=45)
        self._btc_hex = tkinter.Button(self.main_frame, text="Hex", font=MainWindow.C_FONT, command=self.evt_btc_hex)
        self._btc_hex.place(x=390,y=45)
        self._rd_dec = tkinter.Button(self.main_frame, text="Random", font=MainWindow.C_FONT, command=self.evt_rd_dec)
        self._rd_dec.place(x=15,y=150)
        self._jump_input = tkinter.Entry(self.main_frame, width=7, font=MainWindow.C_FONT)
        self._jump_input.insert(0, '1')
        self._jump_input.place(x=200,y=150)
        self._jump_input.focus()
        self._jump1_dec = tkinter.Button(self.main_frame, text=" + ", font=MainWindow.C_FONT, command=self.evt_jump1_dec)
        self._jump1_dec.place(x=300,y=150)
        self._jump_dec = tkinter.Button(self.main_frame, text=" - ", font=MainWindow.C_FONT, command=self.evt_jump_rm1_dec)
        self._jump_dec.place(x=140,y=150)
        labeladdr = tkinter.Label(self.main_frame, text=" When Searching for adress \n it will generate \n a random private key \n this will not match the address ", font=("Arial", 8))
        labeladdr.place(x=670,y=135)
        self._bt_ip = tkinter.Button(self.main_frame, text="Address", font=MainWindow.C_FONT, command=self.evt_btc_add)
        self._bt_ip.place(x=570,y=150)
        label = tkinter.Label(self.main_frame, text="  Binary ", font=MainWindow.C_FONT)
        label.place(x=5,y=200)
        self._stringvar_bin = tkinter.StringVar()
        txt_outputbin = tkinter.Entry(self.main_frame, textvariable=self._stringvar_bin, width=56, font=MainWindow.C_FONT)
        txt_outputbin.place(x=130,y=200)
        label = tkinter.Label(self.main_frame, text="  Bits ", font=MainWindow.C_FONT)
        label.place(x=730,y=240)
        self._stringvar_bit = tkinter.StringVar()
        txt_outputbit = tkinter.Entry(self.main_frame, textvariable=self._stringvar_bit, width=5, font=MainWindow.C_FONT)
        txt_outputbit.place(x=745,y=280)
        label = tkinter.Label(self.main_frame, text=" Decimal ", font=MainWindow.C_FONT)
        label.place(x=5,y=240)
        self._stringvar_dec = tkinter.StringVar()
        self.txt_outputdec = tkinter.Entry(self.main_frame, textvariable=self._stringvar_dec, width=50, font=MainWindow.C_FONT)
        self.txt_outputdec.place(x=130,y=240)
        label = tkinter.Label(self.main_frame, text="Hexadecimal ", font=MainWindow.C_FONT)
        label.place(x=2,y=280)
        self._stringvar_hex = tkinter.StringVar()
        txt_outputhex = tkinter.Entry(self.main_frame, textvariable=self._stringvar_hex, width=48, font=MainWindow.C_FONT)
        txt_outputhex.place(x=150,y=280)
        label1 = tkinter.Label(self.main_frame, text=" BTC Address ", font=MainWindow.C_FONT)
        label1.place(x=300,y=310)
        self._stringvar_addr = tkinter.StringVar()
        txt_outputaddr = tkinter.Label(self.main_frame, textvariable=self._stringvar_addr, font=("Arial", 12))
        txt_outputaddr.place(x=50,y=350)
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
        self.widgetsnake = tkinter.Button(self._window, text= "BTC Snake Game ",font=("Arial",10),bg="purple", command= opensnake)
        self.widgetsnake.place(x=30,y=590)
        self.widgetHunter = tkinter.Button(self._window, text= "16x16 BTC Hunter ",font=("Arial",10),bg="gold", command= hunter16x16)
        self.widgetHunter.place(x=690,y=590)
        lbl = tkinter.Label(self._window, font = ('calibri', 28, 'bold'), background = '#F0F0F0', foreground = 'purple')
        lbl.place(x=10,y=30)
        time()
        # =============================================================================
        # about_frame
        # =============================================================================
        about1 = tkinter.Frame(master = self.about_frame, bg = '#F0F0F0')
        about1.pack(fill='both', expand='yes')
        pricelable_data = f"Todays Bitcoin Price £ {price('BTC')} "
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
        pricelable_data = f"Todays Bitcoin Price £ {price('BTC')} "
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
        self.l33.place(x=240,y=5)
        self.l44.place(x=380,y=5)
        self.l55.place(x=240,y=25)
        self.l66.place(x=380,y=25)
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
        self._txt_inputbrain.insert(0, 'how much wood could a woodchuck chuck if a woodchuck could chuck wood')
        self._txt_inputbrain.place(x=80,y=80)
        self._txt_inputbrain.focus()
        self._btc_bin = tkinter.Button(self.brain_frame, text="Enter", font=MainWindow.C_FONT, command=self.Random_brain_single)
        self._btc_bin.place(x=545,y=75)
        self.titleb = tkinter.Label(self.brain_frame, text="Brain Wallet Words ",font=("Arial",16),bg="#F0F0F0",fg="Black")
        self.titleb.place(x=380,y=270)
        self.titleerror = tkinter.Label(self.brain_frame, text="!!! Error to be Fixed !!! \n 1 Word from list \n Not stopping  Error !!! ",font=("Arial",8),bg="#F0F0F0",fg="red")
        self.titleerror.place(x=15,y=250)
        self.title1 = tkinter.Label(self.brain_frame, text="Random Brain Wallet Generator Online Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.title1.place(x=60,y=130)
        self.title2 = tkinter.Label(self.brain_frame, text="Random Brain Wallet Generator Offline Pick Ammount of Words to Generate",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.title2.place(x=60,y=130)
        # Create our  Brain Buttons
        self.my_button = tkinter.Button(self.brain_frame, text= "1 Word ",font=("Arial",10),bg="#ee6b6e", command= Random_brain_online6)
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
        self.my_button = tkinter.Button(self.brain_frame, text= "1 Word ",font=("Arial",10),bg="#ee6b6e", command= Random_brain_offline6)
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
        # bitcoin_frame
        # =============================================================================
        self.l1 = tkinter.Label(self.bitcoin_frame, text="Bitcoin Wallet Generator ",font=("Arial",20),bg="#F0F0F0",fg="Black")
        self.l1.place(x=100,y=70)
        self.t1 = tkinter.Label(self.bitcoin_frame, text=addr_count_print,font=("Arial",14),bg="#F0F0F0",fg="Black")
        self.t1.place(x=80,y=110)
        labelstart = tkinter.Label(self.bitcoin_frame, text="Start \nDec ", font=("Arial",13))
        labelstart.place(x=5,y=140)
        self._txt_inputstart = tkinter.Entry(self.bitcoin_frame, width=50, font=MainWindow.C_FONT)
        self._txt_inputstart.insert(0, '1')
        self._txt_inputstart.place(x=65,y=145)
        self._txt_inputstart.focus()
        labelstop = tkinter.Label(self.bitcoin_frame, text="Stop \nDec ", font=("Arial",13))
        labelstop.place(x=5,y= 180)
        self._txt_inputstop = tkinter.Entry(self.bitcoin_frame, width=50, font=MainWindow.C_FONT)
        self._txt_inputstop.insert(0, max_p)
        self._txt_inputstop.place(x=65,y=185)
        self._txt_inputstop.focus()
        labelmag = tkinter.Label(self.bitcoin_frame, text="Jump \nMag ", font=("Arial",13))
        labelmag.place(x=640,y= 220)
        self._txt_inputmag = tkinter.Entry(self.bitcoin_frame, width=8, font=MainWindow.C_FONT)
        self._txt_inputmag.insert(0, '1')
        self._txt_inputmag.place(x=690,y=225)
        self._txt_inputmag.focus()
        self.r1 = tkinter.Button(self.bitcoin_frame, text=" Generate Random  ",font=("Arial",13),bg="#A3E4D7",command=Random_Bruteforce_Speed)
        self.r1.place(x=60,y=220)
        self.s1 = tkinter.Button(self.bitcoin_frame, text=" Sequential Start-Stop",font=("Arial",13),bg="#B3B4D7",command=Sequential_Bruteforce_speed)
        self.s1.place(x=240,y=220)
        self.sb1 = tkinter.Button(self.bitcoin_frame, text=" Backward Stop-Start ",font=("Arial",13),bg="#C3C4D7",command=Sequential_Bruteforce_speed_back)
        self.sb1.place(x=430,y=220)
        self.start= tkinter.Button(self.bitcoin_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start)
        self.start.place(x=690,y=180)
        self.stop= tkinter.Button(self.bitcoin_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop)
        self.stop.place(x=750,y=180)
        self.l2 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l2.place(x=50,y=270)
        self.l3 = tkinter.Label(self.bitcoin_frame, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l3.place(x=240,y=5)
        self.l4 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l4.place(x=380,y=5)
        self.l5 = tkinter.Label(self.bitcoin_frame, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l5.place(x=240,y=25)
        self.l6 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l6.place(x=380,y=25)
        self.l7 = tkinter.Label(self.bitcoin_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple")
        self.l7.place(x=680,y=70)
        self.l8 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        self.l8.place(x=740,y=120)
        pricelable_data = f"Todays Bitcoin Price £ {price('BTC')} "
        pricelable = tkinter.Label(self.bitcoin_frame, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="purple")
        pricelable.place(x=90, y=530)
        # =============================================================================
        # word_frame
        # =============================================================================
        self.l333 = tkinter.Label(self.word_frame, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l333.place(x=240,y=5)
        self.l444 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l444.place(x=380,y=5)
        self.l555 = tkinter.Label(self.word_frame, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l555.place(x=240,y=25)
        self.l666 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l666.place(x=380,y=25)
        self.l777 = tkinter.Label(self.word_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple")
        self.l777.place(x=680,y=70)
        self.l888 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",23),text="0")
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
        self._txt_inputword.insert(0, 'witch collapse practice feed shame open despair creek road again ice least')
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
        pop.title("BitcoinHunter.py")
        pop.iconbitmap('images/miz.ico')
        pop.geometry("700x250")
        widget = tkinter.Label(pop, compound='top')
        widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        widget['text'] = "© MIZOGG 2018 - 2022"
        widget['image'] = widget.miz_image_png
        widget.place(x=220,y=180)
        label = Label(pop, text='Welcome to BitHunter...... \n\n Made By Mizogg.co.uk \n\n Version 1.8 08/11/22')
        label.pack(pady=10)
        Label(pop, text= "This window will get closed after 3 seconds...", font=('Helvetica 8 bold')).pack(pady=10)
        frame = Frame(pop)
        frame.pack(pady=10)
        button1 = Button(frame, text=" Close ",
        command=self.CLOSEWINDOW)
        button1.grid(row=0, column=1)
        pop.after(3000,lambda:pop.destroy())
    
    def CLOSEWINDOW(self):
        pop.destroy()
   
    def Random_brain_single(self):
        passphrase = self._txt_inputbrain.get().strip()
        global total, totaladd, found
        wallet = BrainWallet()
        private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
        source_code = get_balance(caddr)
        received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
        receivedid = source_code.xpath(received_id)
        totalReceived = str(receivedid[0].text_content())
        sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
        sentid = source_code.xpath(sent_id)
        totalSent = str(sentid[0].text_content())
        balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
        balanceid = source_code.xpath(balance_id)
        balance = str(balanceid[0].text_content())
        txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
        txsid = source_code.xpath(txs_id)
        txs = str(txsid[0].text_content())
        brainvar = tkinter.StringVar()
        brainvar.set(passphrase)
        brainvartext = tkinter.StringVar()
        brainvartext1 = (f'\n Private Key In HEX : \n\n {private_key} \n\n Bitcoin Adress : {caddr} \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
        brainvartext.set(brainvartext1)
        self.brain_update.config(textvariable = brainvar, relief='flat')
        self.brain_update1.config(textvariable = brainvartext, relief='flat')
        if int(txs) > 0 :
            found+=1
            self.l88.config(text = f'{found}')
            with open("found.txt", "a", encoding="utf-8") as f:
                f.write(f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}] \n')
        self.brain_update.update()
        self.brain_update1.update()
        total+=1
        totaladd+=1
        self.l44.config(text = f'{total}')
        self.l66.config(text = f'{totaladd}')
        
    def Random_word_single(self):
        mnem = self._txt_inputword.get()
        random_word_results(self, mnem)
        
    def Random_word_random(self):
        lenght= ('128','256')
        rnds = random.choice(lenght)
        mnem = create_valid_mnemonics(strength=int(rnds))
        random_word_results(self, mnem)
    
    def evt_btc_bin(self):
        try:
            bin_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = bin2dec(bin_value)
            hex_value = bin2hex(bin_value)
            bit_value = bin2bit(bin_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception:
            tkinter.messagebox.showerror("Error", "Invalid Binary conversion")
            print(ex, file=sys.stderr)
            
    def evt_btc_bit(self):
        try:
            bit_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = bit2bin(bit_value)
            dec_value = bit2dec(bit_value)
            hex_value = bit2hex(bit_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception:
            tkinter.messagebox.showerror("Error", "Invalid Bits conversion")
            print(ex, file=sys.stderr)
    
    def evt_btc_dec(self):
        try:
            dec_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
            
    def evt_rd_dec(self):
        try:
            dec_value = int(random.randrange(startdec, stopdec))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
    
    def evt_jump1_dec(self):
        try:
            dec_value = int(self.txt_outputdec.get().strip().replace(" ", ""))
            dec_value += int(self._jump_input.get().strip().replace(" ", ""))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
            
    def evt_jump_rm1_dec(self):
        try:
            dec_value = int(self.txt_outputdec.get().strip().replace(" ", ""))
            dec_value -= int(self._jump_input.get().strip().replace(" ", ""))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr) 
            
    def evt_btc_hex(self):
        try:
            hex_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = hex2bin(hex_value)
            dec_value = hex2dec(hex_value)
            bit_value = hex2bit(hex_value)
            btc_value = int2addr(dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Hexadecimal conversion")
            print(ex, file=sys.stderr)
    
    def evt_btc_add(self):
        try:
            btc_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = int(random.randrange(startdec, max_p))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = addr2int(btc_value)
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
        self.main_frame.mainloop()

if __name__ == "__main__":
    win = MainWindow()
    win.mainloop()
