#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 22.10.2022 https://t.me/CryptoCrackersUK

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
# Bitcoin Price chart
# =============================================================================
def price(symbol, comparison_symbols=['GBP'], exchange=''):
    url = 'https://min-api.cryptocompare.com/data/price?fsym={}&tsyms={}'\
            .format(symbol.upper(), ','.join(comparison_symbols).upper())
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
    const = "m/44'/0'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/44'/0'/0'/0/0"
    derivation_path = parse_derivation_path(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key
    
def bip39seed_to_private_key2(bip39seed, n=1):
    const = "m/49'/0'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/49'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key3(bip39seed, n=1):
    const = "m/84'/0'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/84'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

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
                    
                        Version = 1.5
                    16x16Hunter added Offline
                    
                        Version = 1.4
                        Pop Up boxes
        1 Brain word from list TODO make stop function on 1 Brain
                    BrickHunter.py Added

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

puzzleinfo = ('''
1   0000000000000000000000000000000000000000000000000000000000000001	 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH		1
2   0000000000000000000000000000000000000000000000000000000000000003	 1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb		3
3   0000000000000000000000000000000000000000000000000000000000000007	 19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA		7
4   0000000000000000000000000000000000000000000000000000000000000008	 1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e		15
5   0000000000000000000000000000000000000000000000000000000000000015	 1E6NuFjCi27W5zoXg8TRdcSRq84zJeBW3k		31
6   0000000000000000000000000000000000000000000000000000000000000031	 1PitScNLyp2HCygzadCh7FveTnfmpPbfp8		63
7   000000000000000000000000000000000000000000000000000000000000004C	 1McVt1vMtCC7yn5b9wgX1833yCcLXzueeC		127
8   00000000000000000000000000000000000000000000000000000000000000E0	 1M92tSqNmQLYw33fuBvjmeadirh1ysMBxK		255
9   00000000000000000000000000000000000000000000000000000000000001D3	 1CQFwcjw1dwhtkVWBttNLDtqL7ivBonGPV		511
10  0000000000000000000000000000000000000000000000000000000000000202	 1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe		1023
11  0000000000000000000000000000000000000000000000000000000000000483	 1PgQVLmst3Z314JrQn5TNiys8Hc38TcXJu		2047
12  0000000000000000000000000000000000000000000000000000000000000A7B	 1DBaumZxUkM4qMQRt2LVWyFJq5kDtSZQot		4095
13  0000000000000000000000000000000000000000000000000000000000001460	 1Pie8JkxBT6MGPz9Nvi3fsPkr2D8q3GBc1		8191
14  0000000000000000000000000000000000000000000000000000000000002930	 1ErZWg5cFCe4Vw5BzgfzB74VNLaXEiEkhk		16383
15  00000000000000000000000000000000000000000000000000000000000068F3	 1QCbW9HWnwQWiQqVo5exhAnmfqKRrCRsvW		32767
16  000000000000000000000000000000000000000000000000000000000000C936	 1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY		65535
17  000000000000000000000000000000000000000000000000000000000001764F	 1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm		131071
18  000000000000000000000000000000000000000000000000000000000003080D	 1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE		262143
19  000000000000000000000000000000000000000000000000000000000005749F	 1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w		524287
20  00000000000000000000000000000000000000000000000000000000000D2C55	 1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum		1048575
21  00000000000000000000000000000000000000000000000000000000001BA534	 14oFNXucftsHiUMY8uctg6N487riuyXs4h		2097151
22  00000000000000000000000000000000000000000000000000000000002DE40F	 1CfZWK1QTQE3eS9qn61dQjV89KDjZzfNcv		4194303
23  0000000000000000000000000000000000000000000000000000000000556E52	 1L2GM8eE7mJWLdo3HZS6su1832NX2txaac		8388607
24  0000000000000000000000000000000000000000000000000000000000DC2A04	 1rSnXMr63jdCuegJFuidJqWxUPV7AtUf7		16777215
25  0000000000000000000000000000000000000000000000000000000001FA5EE5	 15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP		33554431
26  000000000000000000000000000000000000000000000000000000000340326E	 1JVnST957hGztonaWK6FougdtjxzHzRMMg		67108863
27  0000000000000000000000000000000000000000000000000000000006AC3875	 128z5d7nN7PkCuX5qoA4Ys6pmxUYnEy86k		134217727
28  000000000000000000000000000000000000000000000000000000000D916CE8	 12jbtzBb54r97TCwW3G1gCFoumpckRAPdY		268435455
29  0000000000000000000000000000000000000000000000000000000017E2551E	 19EEC52krRUK1RkUAEZmQdjTyHT7Gp1TYT		536870911
30  000000000000000000000000000000000000000000000000000000003D94CD64	 1LHtnpd8nU5VHEMkG2TMYYNUjjLc992bps		1073741823
31  000000000000000000000000000000000000000000000000000000007D4FE747	 1LhE6sCTuGae42Axu1L1ZB7L96yi9irEBE		2147483647
32  00000000000000000000000000000000000000000000000000000000B862A62E	 1FRoHA9xewq7DjrZ1psWJVeTer8gHRqEvR		4294967295
33  00000000000000000000000000000000000000000000000000000001A96CA8D8	 187swFMjz1G54ycVU56B7jZFHFTNVQFDiu		8589934591
34  000000000000000000000000000000000000000000000000000000034A65911D	 1PWABE7oUahG2AFFQhhvViQovnCr4rEv7Q		17179869183
35  00000000000000000000000000000000000000000000000000000004AED21170	 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb		34359738367
36  00000000000000000000000000000000000000000000000000000009DE820A7C	 1Be2UF9NLfyLFbtm3TCbmuocc9N1Kduci1		68719476735
37  0000000000000000000000000000000000000000000000000000001757756A93	 14iXhn8bGajVWegZHJ18vJLHhntcpL4dex		137438953471
38  00000000000000000000000000000000000000000000000000000022382FACD0	 1HBtApAFA9B2YZw3G2YKSMCtb3dVnjuNe2		274877906943
39  0000000000000000000000000000000000000000000000000000004B5F8303E9	 122AJhKLEfkFBaGAd84pLp1kfE7xK3GdT8		549755813887
40  000000000000000000000000000000000000000000000000000000E9AE4933D6	 1EeAxcprB2PpCnr34VfZdFrkUWuxyiNEFv		1099511627775
41  00000000000000000000000000000000000000000000000000000153869ACC5B	 1L5sU9qvJeuwQUdt4y1eiLmquFxKjtHr3E		2199023255551
42  000000000000000000000000000000000000000000000000000002A221C58D8F	 1E32GPWgDyeyQac4aJxm9HVoLrrEYPnM4N		4398046511103
43  000000000000000000000000000000000000000000000000000006BD3B27C591	 1PiFuqGpG8yGM5v6rNHWS3TjsG6awgEGA1		8796093022207
44  00000000000000000000000000000000000000000000000000000E02B35A358F	 1CkR2uS7LmFwc3T2jV8C1BhWb5mQaoxedF		17592186044415
45  0000000000000000000000000000000000000000000000000000122FCA143C05	 1NtiLNGegHWE3Mp9g2JPkgx6wUg4TW7bbk		35184372088831
46  00000000000000000000000000000000000000000000000000002EC18388D544	 1F3JRMWudBaj48EhwcHDdpeuy2jwACNxjP		70368744177663
47  00000000000000000000000000000000000000000000000000006CD610B53CBA	 1Pd8VvT49sHKsmqrQiP61RsVwmXCZ6ay7Z		140737488355327
48  0000000000000000000000000000000000000000000000000000ADE6D7CE3B9B	 1DFYhaB2J9q1LLZJWKTnscPWos9VBqDHzv		281474976710655
49  000000000000000000000000000000000000000000000000000174176B015F4D	 12CiUhYVTTH33w3SPUBqcpMoqnApAV4WCF		562949953421311
50  00000000000000000000000000000000000000000000000000022BD43C2E9354	 1MEzite4ReNuWaL5Ds17ePKt2dCxWEofwk		1125899906842623
51  00000000000000000000000000000000000000000000000000075070A1A009D4	 1NpnQyZ7x24ud82b7WiRNvPm6N8bqGQnaS		2251799813685247
52  000000000000000000000000000000000000000000000000000EFAE164CB9E3C	 15z9c9sVpu6fwNiK7dMAFgMYSK4GqsGZim		4503599627370495
53  00000000000000000000000000000000000000000000000000180788E47E326C	 15K1YKJMiJ4fpesTVUcByoz334rHmknxmT		9007199254740991
54  00000000000000000000000000000000000000000000000000236FB6D5AD1F43	 1KYUv7nSvXx4642TKeuC2SNdTk326uUpFy		18014398509481983
55  000000000000000000000000000000000000000000000000006ABE1F9B67E114	 1LzhS3k3e9Ub8i2W1V8xQFdB8n2MYCHPCa		36028797018963967
56  000000000000000000000000000000000000000000000000009D18B63AC4FFDF	 17aPYR1m6pVAacXg1PTDDU7XafvK1dxvhi		72057594037927935
57  00000000000000000000000000000000000000000000000001EB25C90795D61C	 15c9mPGLku1HuW9LRtBf4jcHVpBUt8txKz		144115188075855871
58  00000000000000000000000000000000000000000000000002C675B852189A21	 1Dn8NF8qDyyfHMktmuoQLGyjWmZXgvosXf		288230376151711743
59  00000000000000000000000000000000000000000000000007496CBB87CAB44F	 1HAX2n9Uruu9YDt4cqRgYcvtGvZj1rbUyt		576460752303423487
60  0000000000000000000000000000000000000000000000000FC07A1825367BBE	 1Kn5h2qpgw9mWE5jKpk8PP4qvvJ1QVy8su		1152921504606846975
61  00000000000000000000000000000000000000000000000013C96A3742F64906	 1AVJKwzs9AskraJLGHAZPiaZcrpDr1U6AB		2305843009213693951
62  000000000000000000000000000000000000000000000000363d541eb611abee	 1Me6EfpwZK5kQziBwBfvLiHjaPGxCKLoJi		4611686018427387903
63  0000000000000000000000000000000000000000000000007CCE5EFDACCF6808	 1NpYjtLira16LfGbGwZJ5JbDPh3ai9bjf4		9223372036854775807
64  000000000000000000000000000000000000000000000000F7051F27B09112D4	 16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN		18446744073709551615
65  000000000000000000000000000000000000000000000001A838B13505B26867	 18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe		36893488147419103231
66  (	Unsolved	Unsolved	Unsolved	)	 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so		73786976294838206463
67  (	Unsolved	Unsolved	Unsolved	)	 1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9		147573952589676412927
68  (	Unsolved	Unsolved	Unsolved	)	 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ		295147905179352825855
69  (	Unsolved	Unsolved	Unsolved	)	 19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG		590295810358705651711
70  0000000000000000000000000000000000000000000000349B84B6431A6C4EF1	 19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR		1180591620717411303423
71  (	Unsolved	Unsolved	Unsolved	)	 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU		2361183241434822606847
72  (	Unsolved	Unsolved	Unsolved	)	 1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR		4722366482869645213695
73  (	Unsolved	Unsolved	Unsolved	)	 12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4		9444732965739290427391
74  (	Unsolved	Unsolved	Unsolved	)	 1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv		18889465931478580854783
75  0000000000000000000000000000000000000000000004C5CE114686A1336E07	 1J36UjUByGroXcCvmj13U6uwaVv9caEeAt		37778931862957161709567
76  (	Unsolved	Unsolved	Unsolved	)	 1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF		75557863725914323419135
77  (	Unsolved	Unsolved	Unsolved	)	 1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE		151115727451828646838271
78  (	Unsolved	Unsolved	Unsolved	)	 15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb		302231454903657293676543
79  (	Unsolved	Unsolved	Unsolved	)	 1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8		604462909807314587353087
80  00000000000000000000000000000000000000000000EA1A5C66DCC11B5AD180	 1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe		1208925819614629174706175
81  (	Unsolved	Unsolved	Unsolved	)	 15qsCm78whspNQFydGJQk5rexzxTQopnHZ		2417851639229258349412351
82  (	Unsolved	Unsolved	Unsolved	)	 13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC		4835703278458516698824703
83  (	Unsolved	Unsolved	Unsolved	)	 14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2		9671406556917033397649407
84  (	Unsolved	Unsolved	Unsolved	)	 1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D		19342813113834066795298815
85  00000000000000000000000000000000000000000011720C4F018D51B8CEBBA8	 1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr		38685626227668133590597631
86  (	Unsolved	Unsolved	Unsolved	)	 1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK		77371252455336267181195263
87  (	Unsolved	Unsolved	Unsolved	)	 1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq		154742504910672534362390527
88  (	Unsolved	Unsolved	Unsolved	)	 16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf		309485009821345068724781055
89  (	Unsolved	Unsolved	Unsolved	)	 19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt		618970019642690137449562111
90  000000000000000000000000000000000000000002CE00BB2136A445C71E85BF	 1L12FHH2FHjvTviyanuiFVfmzCy46RRATU		1237940039285380274899124223
91  (	Unsolved	Unsolved	Unsolved	)	 1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74		2475880078570760549798248447
92  (	Unsolved	Unsolved	Unsolved	)	 1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5		4951760157141521099596496895
93  (	Unsolved	Unsolved	Unsolved	)	 17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad		9903520314283042199192993791
94  (	Unsolved	Unsolved	Unsolved	)	 1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL		19807040628566084398385987583
95  0000000000000000000000000000000000000000527a792b183c7f64a0e8b1f4	 19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC		39614081257132168796771975167
96  (	Unsolved	Unsolved	Unsolved	)	 15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b		79228162514264337593543950335
97  (	Unsolved	Unsolved	Unsolved	)	 18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8		158456325028528675187087900671
98  (	Unsolved	Unsolved	Unsolved	)	 1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX		316912650057057350374175801343
99  (	Unsolved	Unsolved	Unsolved	)	 1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL		633825300114114700748351602687
100 000000000000000000000000000000000000000af55fc59c335c8ec67ed24826	 1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F		1267650600228229401496703205375
101 (	Unsolved	Unsolved	Unsolved	)	 1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n		2535301200456458802993406410751
102 (	Unsolved	Unsolved	Unsolved	)	 1PXv28YxmYMaB8zxrKeZBW8dt2HK7RkRPX		5070602400912917605986812821503
103 (	Unsolved	Unsolved	Unsolved	)	 1AcAmB6jmtU6AiEcXkmiNE9TNVPsj9DULf		10141204801825835211973625643007
104 (	Unsolved	Unsolved	Unsolved	)	 1EQJvpsmhazYCcKX5Au6AZmZKRnzarMVZu		20282409603651670423947251286015
105 000000000000000000000000000000000000016f14fc2054cd87ee6396b33df3	 1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib		40564819207303340847894502572031
106 (	Unsolved	Unsolved	Unsolved	)	 18KsfuHuzQaBTNLASyj15hy4LuqPUo1FNB		81129638414606681695789005144063
107 (	Unsolved	Unsolved	Unsolved	)	 15EJFC5ZTs9nhsdvSUeBXjLAuYq3SWaxTc		162259276829213363391578010288127
108 (	Unsolved	Unsolved	Unsolved	)	 1HB1iKUqeffnVsvQsbpC6dNi1XKbyNuqao		324518553658426726783156020576255
109 (	Unsolved	Unsolved	Unsolved	)	 1GvgAXVCbA8FBjXfWiAms4ytFeJcKsoyhL		649037107316853453566312041152511
110 00000000000000000000000000000000000035c0d7234df7deb0f20cf7062444	 12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg		1298074214633706907132624082305023
111 (	Unsolved	Unsolved	Unsolved	)	 1824ZJQ7nKJ9QFTRBqn7z7dHV5EGpzUpH3		2596148429267413814265248164610047
112 (	Unsolved	Unsolved	Unsolved	)	 18A7NA9FTsnJxWgkoFfPAFbQzuQxpRtCos		5192296858534827628530496329220095
113 (	Unsolved	Unsolved	Unsolved	)	 1NeGn21dUDDeqFQ63xb2SpgUuXuBLA4WT4		10384593717069655257060992658440191
114 (	Unsolved	Unsolved	Unsolved	)	 174SNxfqpdMGYy5YQcfLbSTK3MRNZEePoy		20769187434139310514121985316880383
115 0000000000000000000000000000000000060f4d11574f5deee49961d9609ac6	 1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv		41538374868278621028243970633760767
116 (	Unsolved	Unsolved	Unsolved	)	 1MnJ6hdhvK37VLmqcdEwqC3iFxyWH2PHUV		83076749736557242056487941267521535
117 (	Unsolved	Unsolved	Unsolved	)	 1KNRfGWw7Q9Rmwsc6NT5zsdvEb9M2Wkj5Z		166153499473114484112975882535043071
118 (	Unsolved	Unsolved	Unsolved	)	 1PJZPzvGX19a7twf5HyD2VvNiPdHLzm9F6		332306998946228968225951765070086143
119 (	Unsolved	Unsolved	Unsolved	)	 1GuBBhf61rnvRe4K8zu8vdQB3kHzwFqSy7		664613997892457936451903530140172287
120 (	Unsolved	Unsolved	Unsolved	)	 17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT		1329227995784915872903807060280344575
121 (	Unsolved	Unsolved	Unsolved	)	 1GDSuiThEV64c166LUFC9uDcVdGjqkxKyh		2658455991569831745807614120560689151
122 (	Unsolved	Unsolved	Unsolved	)	 1Me3ASYt5JCTAK2XaC32RMeH34PdprrfDx		5316911983139663491615228241121378303
123 (	Unsolved	Unsolved	Unsolved	)	 1CdufMQL892A69KXgv6UNBD17ywWqYpKut		10633823966279326983230456482242756607
124 (	Unsolved	Unsolved	Unsolved	)	 1BkkGsX9ZM6iwL3zbqs7HWBV7SvosR6m8N		21267647932558653966460912964485513215
125 (	Unsolved	Unsolved	Unsolved	)	 1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5		42535295865117307932921825928971026431
126 (	Unsolved	Unsolved	Unsolved	)	 1AWCLZAjKbV1P7AHvaPNCKiB7ZWVDMxFiz		85070591730234615865843651857942052863
127 (	Unsolved	Unsolved	Unsolved	)	 1G6EFyBRU86sThN3SSt3GrHu1sA7w7nzi4		170141183460469231731687303715884105727
128 (	Unsolved	Unsolved	Unsolved	)	 1MZ2L1gFrCtkkn6DnTT2e4PFUTHw9gNwaj		340282366920938463463374607431768211455
129 (	Unsolved	Unsolved	Unsolved	)	 1Hz3uv3nNZzBVMXLGadCucgjiCs5W9vaGz		680564733841876926926749214863536422911
130 (	Unsolved	Unsolved	Unsolved	)	 1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua		1361129467683753853853498429727072845823
131 (	Unsolved	Unsolved	Unsolved	)	 16zRPnT8znwq42q7XeMkZUhb1bKqgRogyy		2722258935367507707706996859454145691647
132 (	Unsolved	Unsolved	Unsolved	)	 1KrU4dHE5WrW8rhWDsTRjR21r8t3dsrS3R		5444517870735015415413993718908291383295
133 (	Unsolved	Unsolved	Unsolved	)	 17uDfp5r4n441xkgLFmhNoSW1KWp6xVLD		10889035741470030830827987437816582766591
134 (	Unsolved	Unsolved	Unsolved	)	 13A3JrvXmvg5w9XGvyyR4JEJqiLz8ZySY3		16333553612205046246241981156724874149887
135 (	Unsolved	Unsolved	Unsolved	)	 16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v		21778071482940061661655974875633165533183
136 (	Unsolved	Unsolved	Unsolved	)	 1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq		43556142965880123323311949751266331066367
137 (	Unsolved	Unsolved	Unsolved	)	 15nf31J46iLuK1ZkTnqHo7WgN5cARFK3RA		87112285931760246646623899502532662132735
138 (	Unsolved	Unsolved	Unsolved	)	 1Ab4vzG6wEQBDNQM1B2bvUz4fqXXdFk2WT		174224571863520493293247799005065324265471
139 (	Unsolved	Unsolved	Unsolved	)	 1Fz63c775VV9fNyj25d9Xfw3YHE6sKCxbt		348449143727040986586495598010130648530943
140 (	Unsolved	Unsolved	Unsolved	)	 1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo		696898287454081973172991196020261297061887
141 (	Unsolved	Unsolved	Unsolved	)	 1CD91Vm97mLQvXhrnoMChhJx4TP9MaQkJo		1393796574908163946345982392040522594123775
142 (	Unsolved	Unsolved	Unsolved	)	 15MnK2jXPqTMURX4xC3h4mAZxyCcaWWEDD		2787593149816327892691964784081045188247551
143 (	Unsolved	Unsolved	Unsolved	)	 13N66gCzWWHEZBxhVxG18P8wyjEWF9Yoi1		5575186299632655785383929568162090376495103
144 (	Unsolved	Unsolved	Unsolved	)	 1NevxKDYuDcCh1ZMMi6ftmWwGrZKC6j7Ux		11150372599265311570767859136324180752990207
145 (	Unsolved	Unsolved	Unsolved	)	 19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg		22300745198530623141535718272648361505980415
146 (	Unsolved	Unsolved	Unsolved	)	 1M7ipcdYHey2Y5RZM34MBbpugghmjaV89P		44601490397061246283071436545296723011960831
147 (	Unsolved	Unsolved	Unsolved	)	 18aNhurEAJsw6BAgtANpexk5ob1aGTwSeL		89202980794122492566142873090593446023921663
148 (	Unsolved	Unsolved	Unsolved	)	 1FwZXt6EpRT7Fkndzv6K4b4DFoT4trbMrV		178405961588244985132285746181186892047843327
149 (	Unsolved	Unsolved	Unsolved	)	 1CXvTzR6qv8wJ7eprzUKeWxyGcHwDYP1i2		356811923176489970264571492362373784095686655
150 (	Unsolved	Unsolved	Unsolved	)	 1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy		713623846352979940529142984724747568191373311
151 (	Unsolved	Unsolved	Unsolved	)	 13Q84TNNvgcL3HJiqQPvyBb9m4hxjS3jkV		1427247692705959881058285969449495136382746623
152 (	Unsolved	Unsolved	Unsolved	)	 1LuUHyrQr8PKSvbcY1v1PiuGuqFjWpDumN		2854495385411919762116571938898990272765493247
153 (	Unsolved	Unsolved	Unsolved	)	 18192XpzzdDi2K11QVHR7td2HcPS6Qs5vg		5708990770823839524233143877797980545530986495
154 (	Unsolved	Unsolved	Unsolved	)	 1NgVmsCCJaKLzGyKLFJfVequnFW9ZvnMLN		11417981541647679048466287755595961091061972991
155 (	Unsolved	Unsolved	Unsolved	)	 1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ		22835963083295358096932575511191922182123945983
156 (	Unsolved	Unsolved	Unsolved	)	 1FTpAbQa4h8trvhQXjXnmNhqdiGBd1oraE		45671926166590716193865151022383844364247891967
157 (	Unsolved	Unsolved	Unsolved	)	 14JHoRAdmJg3XR4RjMDh6Wed6ft6hzbQe9		91343852333181432387730302044767688728495783935
158 (	Unsolved	Unsolved	Unsolved	)	 19z6waranEf8CcP8FqNgdwUe1QRxvUNKBG		182687704666362864775460604089535377456991567871
159 (	Unsolved	Unsolved	Unsolved	)	 14u4nA5sugaswb6SZgn5av2vuChdMnD9E5		365375409332725729550921208179070754913983135743
160 (	Unsolved	Unsolved	Unsolved	)	 1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv		730750818665451459101842416358141509827966271487
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
        # Add bitcoin byte
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
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
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        # Double SHA256 to get checksum
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        # Concatenate public key and checksum to get the address
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
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
# BrickHunter Game
# ============================================================================= 
class GameObject(object):
    def __init__(self, canvas, item):
        self.canvas = canvas
        self.item = item

    def get_position(self):
        return self.canvas.coords(self.item)

    def move(self, x, y):
        self.canvas.move(self.item, x, y)

    def delete(self):
        self.canvas.delete(self.item)


class Ball(GameObject):
    def __init__(self, canvas, x, y):
        self.radius = 10
        self.direction = [1, -1]
        # increase the below value to increase the speed of ball
        self.speed = 8
        item = canvas.create_oval(x-self.radius, y-self.radius,
                                  x+self.radius, y+self.radius,
                                  fill='white')
        super(Ball, self).__init__(canvas, item)

    def update(self):
        coords = self.get_position()
        width = self.canvas.winfo_width()
        if coords[0] <= 0 or coords[2] >= width:
            self.direction[0] *= -1
        if coords[1] <= 0:
            self.direction[1] *= -1
        x = self.direction[0] * self.speed
        y = self.direction[1] * self.speed
        self.move(x, y)

    def collide(self, game_objects):
        coords = self.get_position()
        x = (coords[0] + coords[2]) * 0.5
        if len(game_objects) > 1:
            self.direction[1] *= -1
        elif len(game_objects) == 1:
            game_object = game_objects[0]
            coords = game_object.get_position()
            if x > coords[2]:
                self.direction[0] = 1
            elif x < coords[0]:
                self.direction[0] = -1
            else:
                self.direction[1] *= -1

        for game_object in game_objects:
            if isinstance(game_object, Brick):
                game_object.hit()


class Paddle(GameObject):
    def __init__(self, canvas, x, y):
        self.width = 80
        self.height = 10
        self.ball = None
        item = canvas.create_rectangle(x - self.width / 2,
                                       y - self.height / 2,
                                       x + self.width / 2,
                                       y + self.height / 2,
                                       fill='#FFB643')
        super(Paddle, self).__init__(canvas, item)

    def set_ball(self, ball):
        self.ball = ball

    def move(self, offset):
        coords = self.get_position()
        width = self.canvas.winfo_width()
        if coords[0] + offset >= 0 and coords[2] + offset <= width:
            super(Paddle, self).move(offset, 0)
            if self.ball is not None:
                self.ball.move(offset, 0)


class Brick(GameObject):
    COLORS = {1: '#4535AA', 2: '#ED639E', 3: '#8FE1A2'}

    def __init__(self, canvas, x, y, hits):
        self.width = 75
        self.height = 20
        self.hits = hits
        color = Brick.COLORS[hits]
        item = canvas.create_rectangle(x - self.width / 2,
                                       y - self.height / 2,
                                       x + self.width / 2,
                                       y + self.height / 2,
                                       fill=color, tags='brick')
        super(Brick, self).__init__(canvas, item)

    def hit(self):
        self.hits -= 1
        if self.hits == 0:
            self.delete()
        else:
            self.canvas.itemconfig(self.item,
                                   fill=Brick.COLORS[self.hits])


class Game(tkinter.Frame):
    def __init__(self, master):
        super(Game, self).__init__(master)
        self.lives = 3
        self.width = 610
        self.height = 400
        self.canvas = tkinter.Canvas(self, bg='#D6D1F5',
                                width=self.width,
                                height=self.height,)
        self.canvas.pack()
        self.pack()

        self.items = {}
        self.ball = None
        self.paddle = Paddle(self.canvas, self.width/2, 326)
        self.items[self.paddle.item] = self.paddle
        # adding brick with different hit capacities - 3,2 and 1
        for x in range(5, self.width - 5, 75):
            self.add_brick(x + 37.5, 50, 3)
            self.add_brick(x + 37.5, 70, 2)
            self.add_brick(x + 37.5, 90, 1)

        self.hud = None
        self.setup_game()
        self.canvas.focus_set()
        self.canvas.bind('<Left>',
                         lambda _: self.paddle.move(-10))
        self.canvas.bind('<Right>',
                         lambda _: self.paddle.move(10))

    def setup_game(self):
           self.add_ball()
           self.update_lives_text()
           self.text = self.draw_text(300, 200,
                                      'Press Space to start')
           self.canvas.bind('<space>', lambda _: self.start_game())

    def add_ball(self):
        if self.ball is not None:
            self.ball.delete()
        paddle_coords = self.paddle.get_position()
        x = (paddle_coords[0] + paddle_coords[2]) * 0.5
        self.ball = Ball(self.canvas, x, 310)
        self.paddle.set_ball(self.ball)

    def add_brick(self, x, y, hits):
        brick = Brick(self.canvas, x, y, hits)
        self.items[brick.item] = brick

    def draw_text(self, x, y, text, size='40'):
        font = ('Forte', size)
        return self.canvas.create_text(x, y, text=text,
                                       font=font)

    def update_lives_text(self):
        text = 'Lives: %s' % self.lives
        if self.hud is None:
            self.hud = self.draw_text(50, 20, text, 15)
        else:
            self.canvas.itemconfig(self.hud, text=text)

    def start_game(self):
        self.canvas.unbind('<space>')
        self.canvas.delete(self.text)
        self.paddle.ball = None
        self.game_loop()

    def game_loop(self):
        self.check_collisions()
        num_bricks = len(self.canvas.find_withtag('brick'))
        if num_bricks == 0: 
            self.ball.speed = None
            self.draw_text(300, 200, 'You win! You the Breaker of Bricks.')
        elif self.ball.get_position()[3] >= self.height: 
            self.ball.speed = None
            self.lives -= 1
            if self.lives < 0:
                self.draw_text(300, 200, 'You Lose! Game Over!')
            else:
                self.after(1000, self.setup_game)
        else:
            self.ball.update()
            self.after(50, self.game_loop)

    def check_collisions(self):
        ball_coords = self.ball.get_position()
        items = self.canvas.find_overlapping(*ball_coords)
        objects = [self.items[x] for x in items if x in self.items]
        self.ball.collide(objects)
        
def start_brickhunter():
    root = tkinter.Tk()
    root.title('BrickHunter Break Those Bricks!')
    root.iconbitmap('images/miz.ico')
    game = Game(root)
    game.mainloop()

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

run= True
run1= True
run2= True

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
        
        def Random_Bruteforce_Speed():
            global total, totaladd, found
            while run:
                dec =int(RandomInteger(startdec, stopdec))
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
                    self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}')
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
                    WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}")
                    popwin(WINTEXT)
                if uaddr in bloom_filterbtc:
                    self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
                    WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}")
                    popwin(WINTEXT)
                if p2sh in bloom_filterbtc:
                    self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh} \n')
                    WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh}")
                    popwin(WINTEXT)
                if bech32 in bloom_filterbtc:
                    self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
                    WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address bech32: {bech32}")
                    popwin(WINTEXT)
                self.l2.config(text = f' Instance: Random_Bruteforce \n\n DEC Key: {dec}\n Bits {length} \n\n HEX Key: {HEX} \n\n BTC Address Compressed: {caddr} \n WIF Compressed: {wifc} \n\n BTC Address Uncompressed: {uaddr} \n WIF Compressed: {wifu} \n\n BTC Address p2sh: {p2sh} \n\n BTC Address bech32: {bech32}')
                self.l2.update()
                total+=1
                totaladd+=4
                self.l4.config(text = f'{total}')
                self.l6.config(text = f'{totaladd}')
               
        def Sequential_Bruteforce_speed():
            global total, totaladd, found
            while run:
                global startdec
                START = startdec
                STOP = stopdec
                dec = int(START)
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
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
                    WINTEXT = f'DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {caddr} \nWIF Uncompressed: {wifc}'
                    popwin(WINTEXT)
                if uaddr in bloom_filterbtc:
                    self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Sequential_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
                    WINTEXT =(f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}")
                    popwin(WINTEXT)
                if p2sh in bloom_filterbtc:
                    self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Sequential_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}\n')
                    WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh}")
                    popwin(WINTEXT)
                if bech32 in bloom_filterbtc:
                    self.l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Sequential_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
                    found+=1
                    self.l8.config(text = f'{found}')
                    with open('found.txt', 'a') as result:
                        result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}\n')
                    WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address bech32: {bech32}")
                    popwin(WINTEXT)
                self.l2.config(text = f' Instance: Sequential_Bruteforce \n\n DEC Key: {dec}\n Bits {length} \n\n HEX Key: {HEX} \n\n BTC Address Compressed: {caddr} \n WIF Compressed: {wifc} \n\n BTC Address Uncompressed: {uaddr} \n WIF Compressed: {wifu} \n\n BTC Address p2sh: {p2sh} \n\n BTC Address bech32: {bech32}')

                with open('startdec.txt', 'w') as save:
                    save.write(str(startdec))
                startdec = startdec +1
                self.l2.update()
                total+=1
                totaladd+=4
                self.l4.config(text = f'{total}')
                self.l6.config(text = f'{totaladd}')
        # ============================================================================= 
        #  Brain Program Main
        # ============================================================================= 
        def Random_brain_online():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(1,3)))
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
                
        def Random_brain_online1():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(3,9)))
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

        def Random_brain_online2():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(9,15)))
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
                
        def Random_brain_online3():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(15,18)))
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

        def Random_brain_online4():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(18,21)))
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

        def Random_brain_online5():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(21,24)))
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
        
        def Random_brain_online6():
            global total, totaladd, found
            while run1:
                for i in range(0,len(mylist)):
                    passphrase = mylist[i]
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

        def Random_brain_offline():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(1,3)))
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

        def Random_brain_offline1():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(3,9)))
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

        def Random_brain_offline2():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(9,15)))
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

        def Random_brain_offline3():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(15,18)))
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

        def Random_brain_offline4():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(18,21)))
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
                
        def Random_brain_offline5():
            global total, totaladd, found
            while run1:
                passphrase = ' '.join(random.sample(mylist, random.randint(21,24)))
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
                    l88.config(text = f'{found}')
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
                
        def Random_brain_offline6():
            global total, totaladd, found
            while run1:
                for i in range(0,len(mylist)):
                    passphrase = mylist[i]
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
                        l88.config(text = f'{found}')
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
        # ============================================================================= 
        #  Mnemonic Program Main
        # ============================================================================= 
        def Random_word_online():
            global total, totaladd, found
            while run2:
                rnds = '16'
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
        def Random_word_online1():
            global total, totaladd, found
            while run2:
                rnds = '32'
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
        def Random_word_online2():
            global total, totaladd, found
            while run2:
                rnds = '64'
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
        def Random_word_online3():
            global total, totaladd, found
            while run2:
                rnds = '96'
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
        def Random_word_online4():
            global total, totaladd, found
            while run2:
                rnds = '128'
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
        def Random_word_online5():
            global total, totaladd, found
            while run2:
                rnds = '160'
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
        def Random_word_online6():
            global total, totaladd, found
            while run2:
                rnds = '192'
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
        def Random_word_online7():
            global total, totaladd, found
            while run2:
                rnds = '224'
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
        def Random_word_online8():
            global total, totaladd, found
            while run2:
                rnds = '256'
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

        def Random_word_offline():
            global total, totaladd, found
            while run2:
                rnds = '16'
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
        def Random_word_offline1():
            global total, totaladd, found
            while run2:
                rnds = '32'
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
        def Random_word_offline2():
            global total, totaladd, found
            while run2:
                rnds = '64'
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
        def Random_word_offline3():
            global total, totaladd, found
            while run2:
                rnds = '96'
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
        def Random_word_offline4():
            global total, totaladd, found
            while run2:
                rnds = '128'
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
        def Random_word_offline5():
            global total, totaladd, found
            while run2:
                rnds = '160'
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
        def Random_word_offline6():
            global total, totaladd, found
            while run2:
                rnds = '192'
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
        def Random_word_offline7():
            global total, totaladd, found
            while run2:
                rnds = '224'
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
        def Random_word_offline8():
            global total, totaladd, found
            while run2:
                rnds = '256'
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
        # self._window.filemenu.add_command(label="Edit Start DEC", command=donothing)
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
        self.puzzle_frame = Frame(self.my_notebook, width=840, height=620)
        self.credits_frame = Frame(self.my_notebook, width=840, height=620)

        self.main_frame.pack(fill="both", expand=1)
        self.bitcoin_frame.pack(fill="both", expand=1)
        self.brain_frame.pack(fill="both", expand=1)
        self.word_frame.pack(fill="both", expand=1)
        self.about_frame.pack(fill="both", expand=1)
        self.puzzle_frame.pack(fill="both", expand=1)
        self.credits_frame.pack(fill="both", expand=1)

        # Add our Tabs and Order of them
        self.my_notebook.add(self.bitcoin_frame, text="Bitcoin Hunting")
        self.my_notebook.add(self.main_frame, text="Conversion Tools ")
        self.my_notebook.add(self.brain_frame, text="Brain Hunting")
        self.my_notebook.add(self.word_frame, text="Mnemonic Hunting")
        self.my_notebook.add(self.about_frame, text="About Bitcoin")
        self.my_notebook.add(self.puzzle_frame, text="Bitcoin Puzzles")
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
        
        label1 = tkinter.Label(self.main_frame, text=" BTC Address ", font=MainWindow.C_FONT)
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
        self.widgetsnake = tkinter.Button(self._window, text= "BTC Snake Game ",font=("Arial",10),bg="purple", command= opensnake)
        self.widgetsnake.place(x=15,y=590)
        self.widgetbrick = tkinter.Button(self._window, text= "BTC Block Game ",font=("Arial",10),bg="purple", command= start_brickhunter)
        self.widgetbrick.place(x=730,y=590)
        self.widgetHunter = tkinter.Button(self._window, text= "16x16 BTC Hunter ",font=("Arial",10),bg="gold", command= hunter16x16)
        self.widgetHunter.place(x=330,y=590)
        lbl = tkinter.Label(self._window, font = ('calibri', 40, 'bold'), background = '#F0F0F0', foreground = 'purple')
        lbl.place(x=10,y=30)
        time()
        # =============================================================================
        # about_frame
        # =============================================================================
        about1 = tkinter.Frame(master = self.about_frame, bg = '#F0F0F0')
        about1.pack(fill='both', expand='yes')
        pricelable_data = f"Todays Bitcoin Price £ {price('BTC')} "
        pricelable = tkinter.Label(master = about1, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="Black")
        pricelable.place(x=220, y=530)
        editArea = tkst.ScrolledText(master = about1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        editArea.insert(tkinter.INSERT, information)
        # =============================================================================
        # credits_frame
        # =============================================================================
        credits1 = tkinter.Frame(master = self.credits_frame, bg = '#F0F0F0')
        credits1.pack(fill='both', expand='yes')
        pricelable_data = f"Todays Bitcoin Price £ {price('BTC')} "
        pricelable = tkinter.Label(master = credits1, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="Black")
        pricelable.place(x=220, y=530)
        editArea = tkst.ScrolledText(master = credits1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        editArea.insert(tkinter.INSERT, creditsinfo)
        # =============================================================================
        # puzzle_frame
        # =============================================================================
        frame1 = tkinter.Frame(master = self.puzzle_frame, bg = '#F0F0F0')
        frame1.pack(fill='both', expand='yes')
        pricelable_data = f"Todays Bitcoin Price £ {price('BTC')} "
        pricelable = tkinter.Label(master = frame1, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="Black")
        pricelable.place(x=220, y=530)
        editArea = tkst.ScrolledText(master = frame1, wrap = tkinter.WORD, width  = 40, height = 16,font=("Arial",12))
        editArea.pack(padx=10, pady=90, fill=tkinter.BOTH, expand=True)
        editArea.insert(tkinter.INSERT, puzzleinfo)
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
        # ## # # #
        labelbrain = tkinter.Label(self.brain_frame, text="Brain \nWords ", font=("Arial",13))
        labelbrain.place(x=5,y=75)
        
        self._txt_inputbrain = tkinter.Entry(self.brain_frame, width=36, font=MainWindow.C_FONT)
        self._txt_inputbrain.place(x=80,y=80)
        self._txt_inputbrain.focus()
        
        self._bt_bin = tkinter.Button(self.brain_frame, text="Enter", font=MainWindow.C_FONT, command=self.Random_brain_single)
        self._bt_bin.place(x=545,y=75)
        # # # # ## 
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
        # bitcoin_frame
        # =============================================================================
        self.l1 = tkinter.Label(self.bitcoin_frame, text="Random Wallet Generator ",font=("Arial",20),bg="#F0F0F0",fg="Black")
        self.t1 = tkinter.Label(self.bitcoin_frame, text=addr_count_print,font=("Arial",14),bg="#F0F0F0",fg="Black")
        self.r1 = tkinter.Button(self.bitcoin_frame, text="Generate Random Wallets ",font=("Arial",15),bg="#A3E4D7",command=Random_Bruteforce_Speed)
        self.s1 = tkinter.Button(self.bitcoin_frame, text="Generate Sequential Wallets ",font=("Arial",15),bg="#A3E4D7",command=Sequential_Bruteforce_speed)
        self.start= tkinter.Button(self.bitcoin_frame, text= "Start",font=("Arial",13),bg="#F0F0F0", command= start)
        self.stop= tkinter.Button(self.bitcoin_frame, text= "Stop",font=("Arial",13),bg="#F0F0F0", command= stop)
        self.l2 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l3 = tkinter.Label(self.bitcoin_frame, text="Total Private Keys : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l4 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l5 = tkinter.Label(self.bitcoin_frame, text="Total Addresses   : ",font=("Arial",12),bg="#F0F0F0",fg="Black")
        self.l6 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",12),text="")
        self.l7 = tkinter.Label(self.bitcoin_frame, text="Total Found ",font=("Arial",18),bg="#F0F0F0",fg="purple")
        self.l8 = tkinter.Label(self.bitcoin_frame, bg="#F0F0F0",font=("Arial",23),text="0")
        pricelable_data = f"Todays Bitcoin Price £ {price('BTC')} "
        pricelable = tkinter.Label(self.bitcoin_frame, text=pricelable_data, font=("Arial",14),bg="#F0F0F0",fg="Black")
        pricelable.place(x=220, y=530)
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
        # ## # # #
        labelword = tkinter.Label(self.word_frame, text="Mnemonic", font=("Arial",13))
        labelword.place(x=5,y=75)
        
        self._txt_inputword = tkinter.Entry(self.word_frame, width=36, font=MainWindow.C_FONT)
        self._txt_inputword.place(x=90,y=80)
        self._txt_inputword.focus()
        
        self._word_bin = tkinter.Button(self.word_frame, text="Enter", font=MainWindow.C_FONT, command=self.Random_word_single)
        self._word_bin.place(x=545,y=75)
        # # # # ## 
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
        # Create a Label Text
        label = Label(pop, text='Welcome to BitHunter...... \n\n Made By Mizogg.co.uk \n\n Version 1.4 20/10/22')
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
        self.brain_update.update()
        self.brain_update1.update()
        
    def Random_word_single(self):
        mnem = self._txt_inputword.get()
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
        
    def Random_word_random(self):
        lenght= ('128','256')
        rnds = random.choice(lenght)
        mnem = create_valid_mnemonics(strength=int(rnds))
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