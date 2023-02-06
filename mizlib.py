#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 06.02.2023 https://t.me/CryptoCrackersUK
import hmac, struct, codecs, sys, os, binascii, hashlib
import webbrowser
import random
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import secp256k1 as ice
import string
import re
import smtplib
try:
    import base58
    import ecdsa
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    import requests
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import numpy as np
    import trotter

except ImportError:
    import subprocess
    subprocess.check_call(["python", '-m', 'pip', 'install', 'base58'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'ecdsa'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'simplebloomfilter'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bitarray==1.9.2'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'requests'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bit'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'numpy'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'trotter'])
    import base58
    import ecdsa
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    import requests
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import numpy as np
    import trotter

gmail_user = 'youremail'
gmail_password = 'youremailpassword'

def send_email(message_in):
    sent_from = gmail_user
    to = ['youremail']
    subject = 'OMG Super Important Message'
    body = f"  {message_in}"
    
    email_text = """\
        From: %s
        To: %s
        Subject: %s

        %s
        """ % (sent_from, ", ".join(to), subject, body)

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_password)
        server.sendmail(sent_from, to, email_text)
        server.close()
    
        print ('Email sent!')
    except:
        print('Something went wrong...')
        
fShutdown = False
listfThreadRunning = [False] * 2
local_height = 0
nHeightDiff = {}
updatedPrevHash = None
job_id = None
prevhash = None
coinb1 = None
coinb2 = None
merkle_branch = None
version = None
nbits = None
ntime = None
clean_jobs = None
sub_details = None
extranonce1 = None
extranonce2_size = None
    
with open('puzzle.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)

with open('eth.bf', "rb") as fp:
    bloom_filtereth = BloomFilter.load(fp)
    
def countadd():
    addr_count = len(bloom_filterbtc) + len(bloom_filtereth)
    addr_count_print = (f'Total BTC & ETH Addresses Loaded and Checking : {addr_count}')
    return addr_count_print

lines = '=' * 70
# For Menu
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
# Bitcoin Price chart
def price():
    url = 'https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=GBP,USD,EUR'
    page = requests.get(url)
    data = page.json()
    return data
# Balance Checking 
def get_balance(caddr):
    response = requests.get("https://blockstream.info/api/address/" + str(caddr))
    balance = float(response.json()['chain_stats']['funded_txo_sum'])
    totalSent = float(response.json()['chain_stats']['spent_txo_sum'])
    txs = response.json()['chain_stats']['funded_txo_count']
    source_code = f'TotalReceived = [{balance}] : TotalSent =  [{totalSent}] : Transactions = [{txs}]'
    return source_code
    
def get_balance1(uaddr):
    response = requests.get("https://blockstream.info/api/address/" + str(uaddr))
    balance = float(response.json()['chain_stats']['funded_txo_sum'])
    totalSent = float(response.json()['chain_stats']['spent_txo_sum'])
    txs = response.json()['chain_stats']['funded_txo_count']
    source_code1 = f'TotalReceived = [{balance}] : TotalSent =  [{totalSent}] : Transactions = [{txs}]'
    return source_code1

def get_balance2(p2sh):
    response = requests.get("https://blockstream.info/api/address/" + str(p2sh))
    balance = float(response.json()['chain_stats']['funded_txo_sum'])
    totalSent = float(response.json()['chain_stats']['spent_txo_sum'])
    txs = response.json()['chain_stats']['funded_txo_count']
    source_code2 = f'TotalReceived = [{balance}] : TotalSent =  [{totalSent}] : Transactions = [{txs}]'
    return source_code2

def get_balance3(bech32):
    response = requests.get("https://blockstream.info/api/address/" + str(bech32))
    balance = float(response.json()['chain_stats']['funded_txo_sum'])
    totalSent = float(response.json()['chain_stats']['spent_txo_sum'])
    txs = response.json()['chain_stats']['funded_txo_count']
    source_code3 = f'TotalReceived = [{balance}] : TotalSent =  [{totalSent}] : Transactions = [{txs}]'
    return source_code3
# FOR Conversion TAB 
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
    dataadd= (f'''==================================================================================
Bitcoin Address : {value} : 
{source_code}
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
    source_code1 = get_balance1(uaddr)
    source_code2 = get_balance2(p2sh)
    source_code3 = get_balance3(bech32)
    dataadd= (f'''==================================================================================
Bitcoin Address : {caddr} : 
{source_code}
Bitcoin Address : {uaddr} : 
{source_code1}
Bitcoin Address : {p2sh} : 
{source_code2}
Bitcoin Address : {bech32} : 
{source_code3}
==================================================================================
''')
    return dataadd
# BrainWallet
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
        sha256_bdec = hashlib.sha256(public_key_bytes)
        sha256_bdec_digest = sha256_bdec.digest()
        ripemd160_bdec = hashlib.new('ripemd160')
        ripemd160_bdec.update(sha256_bdec_digest)
        ripemd160_bdec_digest = ripemd160_bdec.digest()
        ripemd160_bdec_hex = codecs.encode(ripemd160_bdec_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bdec_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        sha256_nbdec = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbdec_digest = sha256_nbdec.digest()
        sha256_2_nbdec = hashlib.sha256(sha256_nbdec_digest)
        sha256_2_nbdec_digest = sha256_2_nbdec.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbdec_digest, 'hex')
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

def rwonline(self, mnem):
    seed = mnem_to_seed(mnem)
    for r in range (1,2):
        pvk = bip39seed_to_private_key(seed, r)
        pvk2 = bip39seed_to_private_key2(seed, r)
        pvk3 = bip39seed_to_private_key3(seed, r)
        #pvk4 = bip39seed_to_private_key4(seed, r)
        dec = (int.from_bytes(pvk, "big"))
        HEX = "%064x" % dec
        dec2 = (int.from_bytes(pvk2, "big"))
        HEX2 = "%064x" % dec2
        dec3 = (int.from_bytes(pvk3, "big"))
        HEX3 = "%064x" % dec3
        #dec4 = (int.from_bytes(pvk4, "big"))
        #HEX4 = "%064x" % dec4
        cpath = f"m/44'/0'/0'/0/{r}"
        ppath = f"m/49'/0'/0'/0/{r}"
        bpath = f"m/84'/0'/0'/0/{r}"
        #epath = f"m/44'/60'/0'/0/{r}"
        caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
        p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
        bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
        #ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
        response = requests.get("https://blockstream.info/api/address/" + str(caddr))
        balance = float(response.json()['chain_stats']['funded_txo_sum'])
        totalSent = float(response.json()['chain_stats']['spent_txo_sum'])
        txs = response.json()['chain_stats']['funded_txo_count']
        
        response2 = requests.get("https://blockstream.info/api/address/" + str(p2sh))
        balance2 = float(response2.json()['chain_stats']['funded_txo_sum'])
        totalSent2 = float(response2.json()['chain_stats']['spent_txo_sum'])
        txs2 = response2.json()['chain_stats']['funded_txo_count']
        
        response3 = requests.get("https://blockstream.info/api/address/" + str(bech32))
        balance3 = float(response3.json()['chain_stats']['funded_txo_sum'])
        totalSent3 = float(response3.json()['chain_stats']['spent_txo_sum'])
        txs3 = response3.json()['chain_stats']['funded_txo_count']

        wordvartext = (f'''==================================================================================
    Bitcoin Address : {caddr} :
    TotalReceived = [{balance}] : TotalSent =  [{totalSent}] : Transactions = [{txs}]
    Hexadecimal Private Key : {HEX}

    Bitcoin Address : {p2sh} : 
    TotalReceived = [{balance2}] : TotalSent =  [{totalSent2}] : Transactions = [{txs2}]
    Hexadecimal Private Key : {HEX2}

    Bitcoin Address : {bech32} :
    TotalReceived = [{balance3}] : TotalSent =  [{totalSent3}] : Transactions = [{txs3}]
    Hexadecimal Private Key : {HEX3}
    ==================================================================================
    ''')
        if int(txs) > 0 or int(txs2) > 0 or int(txs3) > 0:
            self.found+=1
            self.foundword.config(text = f'{self.found}')
            self.WINTEXT = f'\n Mnemonic : {mnem} \n\n {wordvartext}'
            with open('found.txt', 'a', encoding='utf-8') as f:
                f.write(self.WINTEXT)
            self.popwinner()
            send_email(self.WINTEXT)
        r+=1
        return wordvartext

def rwoffline(self, mnem):
    seed = mnem_to_seed(mnem)
    for r in range (1,5):
        pvk = bip39seed_to_private_key(seed, r)
        pvk2 = bip39seed_to_private_key2(seed, r)
        pvk3 = bip39seed_to_private_key3(seed, r)
        pvk4 = bip39seed_to_private_key4(seed, r)
        dec = (int.from_bytes(pvk, "big"))
        HEX = "%064x" % dec
        dec2 = (int.from_bytes(pvk2, "big"))
        HEX2 = "%064x" % dec2
        dec3 = (int.from_bytes(pvk3, "big"))
        HEX3 = "%064x" % dec3
        dec4 = (int.from_bytes(pvk4, "big"))
        HEX4 = "%064x" % dec4
        cpath = f"m/44'/0'/0'/0/{r}"
        ppath = f"m/49'/0'/0'/0/{r}"
        bpath = f"m/84'/0'/0'/0/{r}"
        epath = f"m/44'/60'/0'/0/{r}"
        caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
        p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
        bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
        ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
        wordvartext = (f' Bitcoin {cpath} :  {caddr} \n Dec : {dec} \n   Hex : {HEX}  \n Bitcoin {ppath} :  {p2sh}\n Dec : {dec2} \n  Hex : {HEX2} \n Bitcoin {bpath} : {bech32}\n  Dec : {dec3} \n  Hex : {HEX3} \n ETH {epath} :  {ethaddr} \n Dec : {dec4} \n Hex: {HEX4}  ')
        if caddr in bloom_filterbtc:
            self.found+=1
            self.foundword.config(text = f'{self.found}')
            self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {cpath} :  {caddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
            with open("foundcaddr.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            send_email(self.WINTEXT)
        if p2sh in bloom_filterbtc:
            self.found+=1
            self.foundword.config(text = f'{self.found}')
            self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {ppath} :  {p2sh}\nDecimal Private Key \n {dec2} \n Hexadecimal Private Key \n {HEX2} \n'
            with open("foundp2sh.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            send_email(self.WINTEXT)
        if bech32 in bloom_filterbtc:
            self.found+=1
            self.foundword.config(text = f'{self.found}')
            self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {bpath} : {bech32}\n Decimal Private Key \n {dec3} \n Hexadecimal Private Key \n {HEX3} \n'
            with open("foundbech32.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            send_email(self.WINTEXT)
        if ethaddr[2:] in bloom_filtereth:
            self.found+=1
            self.foundword.config(text = f'{self.found}')
            self.WINTEXT = f'\n Mnemonic: {mnem} \n ETH {epath} : {ethaddr}\n Decimal Private Key \n {dec4} \n Hexadecimal Private Key \n {HEX4} \n'
            with open("foundeth.txt", "a") as f:
                f.write(self.WINTEXT)
            self.popwinner()
            send_email(self.WINTEXT)
        r+=1
        return wordvartext
    
def brute_btc(self, dec):
    caddr = ice.privatekey_to_address(0, True, dec)
    uaddr = ice.privatekey_to_address(0, False, dec)
    HEX = "%064x" % dec
    wifc = ice.btc_pvk_to_wif(HEX)
    wifu = ice.btc_pvk_to_wif(HEX, False)
    p2sh = ice.privatekey_to_address(1, True, dec)
    bech32 = ice.privatekey_to_address(2, True, dec)
    ethaddr = ice.privatekey_to_ETH_address(dec)
    length = len(bin(dec))
    length -=2
    if caddr in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('foundcaddr.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}")
        self.popwinner()
        send_email(self.WINTEXT)
    if uaddr in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('founduaddr.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}")
        self.popwinner()
        send_email(self.WINTEXT)
    if p2sh in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('foundp2sh.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh} \n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh}")
        self.popwinner()
        send_email(self.WINTEXT)
    if bech32 in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('foundbech32.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address bech32: {bech32}")
        self.popwinner()
    if ethaddr[2:] in bloom_filtereth:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('foundeth.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nETH Address : {ethaddr}')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nETH Address : {ethaddr}")
        self.popwinner()
        send_email(self.WINTEXT)
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
 ETH Address : {ethaddr}
{lines}'''

    return scantext

def get_page(self, page):
    #max = 904625697166532776746648320380374280100293470930272690489102837043110636675
    num = page

    startPrivKey = (page - 1) * 128 + 1
    for i in range(0, 128):
        dec = int(startPrivKey)
        starting_key_hex = hex(startPrivKey)[2:].zfill(64)
        if startPrivKey == 115792089237316195423570985008687907852837564279074904382605163141518161494336:
            break
        caddr = ice.privatekey_to_address(0, True, dec)
        uaddr = ice.privatekey_to_address(0, False, dec)
        p2sh = ice.privatekey_to_address(1, True, dec)
        bech32 = ice.privatekey_to_address(2, True, dec)
        ethaddr = ice.privatekey_to_ETH_address(dec)
        length = len(bin(dec))
        length -=2
        if caddr in bloom_filterbtc:
            output = f'''\n
  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Compressed : {caddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc_page.config(text = f'{self.found}')
            with open('foundcaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
            send_email(self.WINTEXT)

        if uaddr in bloom_filterbtc:
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Uncompressed : {uaddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc_page.config(text = f'{self.found}')
            with open('founduaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
            send_email(self.WINTEXT)
        if p2sh in bloom_filterbtc:
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Segwit : {p2sh}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc_page.config(text = f'{self.found}')
            with open('foundp2sh.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
            send_email(self.WINTEXT)

        if bech32 in bloom_filterbtc:
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Bc1 : {bech32}
{lines}
'''

            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc_page.config(text = f'{self.found}')
            with open('foundbech32.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
            send_email(self.WINTEXT)
            
        if ethaddr[2:] in bloom_filtereth:
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : ETH Address : {ethaddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc_page.config(text = f'{self.found}')
            with open('foundeth.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
            send_email(self.WINTEXT)
        startPrivKey += 1
    scantext = f'''
  : Private Key Page : 
  {num}
  : Private Key DEC :
  {startPrivKey} 
  Bits : {length}
  : Private Key HEX : 
  {starting_key_hex}
{lines}
 BTC Address Compressed: {caddr}
 BTC Address Uncompressed: {uaddr}
 BTC Address p2sh: {p2sh}
 BTC Address bech32: {bech32}
 ETH Address : {ethaddr}
{lines}'''
    return scantext

def rbonline(self, passphrase):
    wallet = BrainWallet()
    private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
    response = requests.get("https://blockstream.info/api/address/" + str(caddr))
    balance = float(response.json()['chain_stats']['funded_txo_sum'])
    totalSent = float(response.json()['chain_stats']['spent_txo_sum'])
    txs = response.json()['chain_stats']['funded_txo_count']
    brainvartext = (f'\n Private Key In HEX : \n {private_key} \n Bitcoin Adress : {caddr} \n TotalReceived  [{balance}] TotalSent : [{totalSent}] Transactions : [{txs}]')
    if int(txs) > 0 :
        self.found+=1
        self.foundbw.config(text = f'{self.found}')
        with open("found.txt", "a") as f:
            f.write(brainvartext)
        self.WINTEXT = (brainvartext)
        self.popwinner()
        send_email(brainvartext)
    return brainvartext
    
def rboffline(self, passphrase):
    wallet = BrainWallet()
    private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
    brainvartext = (f'\n Private Key In HEX : \n\n {private_key} \n\n Bitcoin Adress : {caddr} ')
    if caddr in bloom_filterbtc:
        self.found+=1
        self.foundbw.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {caddr}')
        with open("found.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
        send_email(self.WINTEXT)
    return brainvartext

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
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBinary Data: \n {binstring}")
        with open("foundcaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
        send_email(self.WINTEXT)
    if uaddr in bloom_filterbtc:
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu} \nBinary Data: \n {binstring}")
        with open("found.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
        send_email(self.WINTEXT)
    if p2sh in bloom_filterbtc:
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh} \nBinary Data: \n {binstring}")
        with open("found.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
        send_email(self.WINTEXT)
    if bech32 in bloom_filterbtc:
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Bc1: {bech32} \nBinary Data: \n {binstring}")
        with open("found.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
        send_email(self.WINTEXT)

def hexhunter(self, dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18):
    dec= int(dec)
    dec0= int(dec0)
    dec1= int(dec1)
    dec2= int(dec2)
    dec3= int(dec3)
    dec4= int(dec4)
    dec5= int(dec5)
    dec6= int(dec6)
    dec7= int(dec7)
    dec8= int(dec8)
    dec9= int(dec9)
    dec10= int(dec10)
    dec11= int(dec11)
    dec12= int(dec12)
    dec13= int(dec13)
    dec14= int(dec14)
    dec15= int(dec15)
    dec16= int(dec16)
    dec17= int(dec17)
    dec18= int(dec18)
    for r in range(0, 128):
        btcC = ice.privatekey_to_address(0, True, dec)
        btcC0 = ice.privatekey_to_address(0, True, dec0)
        btcC1 = ice.privatekey_to_address(0, True, dec1)
        btcC2 = ice.privatekey_to_address(0, True, dec2)
        btcC3 = ice.privatekey_to_address(0, True, dec3)
        btcC4 = ice.privatekey_to_address(0, True, dec4)
        btcC5 = ice.privatekey_to_address(0, True, dec5)
        btcC6 = ice.privatekey_to_address(0, True, dec6)
        btcC7 = ice.privatekey_to_address(0, True, dec7)
        btcC8 = ice.privatekey_to_address(0, True, dec8)
        btcC9 = ice.privatekey_to_address(0, True, dec9)
        btcC10 = ice.privatekey_to_address(0, True, dec10)
        btcC11 = ice.privatekey_to_address(0, True, dec11)
        btcC12 = ice.privatekey_to_address(0, True, dec12)
        btcC13 = ice.privatekey_to_address(0, True, dec13)
        btcC14 = ice.privatekey_to_address(0, True, dec14)
        btcC15 = ice.privatekey_to_address(0, True, dec15)
        btcC16 = ice.privatekey_to_address(0, True, dec16)
        btcC17 = ice.privatekey_to_address(0, True, dec17)
        btcC18 = ice.privatekey_to_address(0, True, dec18)
        btcU = ice.privatekey_to_address(0, False, dec)
        btcU0 = ice.privatekey_to_address(0, False, dec0)
        btcU1 = ice.privatekey_to_address(0, False, dec1)
        btcU2 = ice.privatekey_to_address(0, False, dec2)
        btcU3 = ice.privatekey_to_address(0, False, dec3)
        btcU4 = ice.privatekey_to_address(0, False, dec4)
        btcU5 = ice.privatekey_to_address(0, False, dec5)
        btcU6 = ice.privatekey_to_address(0, False, dec6)
        btcU7 = ice.privatekey_to_address(0, False, dec7)
        btcU8 = ice.privatekey_to_address(0, False, dec8)
        btcU9 = ice.privatekey_to_address(0, False, dec9)
        btcU10 = ice.privatekey_to_address(0, False, dec10)
        btcU11 = ice.privatekey_to_address(0, False, dec11)
        btcU12 = ice.privatekey_to_address(0, False, dec12)
        btcU13 = ice.privatekey_to_address(0, False, dec13)
        btcU14 = ice.privatekey_to_address(0, False, dec14)
        btcU15 = ice.privatekey_to_address(0, False, dec15)
        btcU16 = ice.privatekey_to_address(0, False, dec16)
        btcU17 = ice.privatekey_to_address(0, False, dec17)
        btcU18 = ice.privatekey_to_address(0, False, dec18)
        btcP = ice.privatekey_to_address(1, True, dec)
        btcP0 = ice.privatekey_to_address(1, True, dec0)
        btcP1 = ice.privatekey_to_address(1, True, dec1)
        btcP2 = ice.privatekey_to_address(1, True, dec2)
        btcP3 = ice.privatekey_to_address(1, True, dec3)
        btcP4 = ice.privatekey_to_address(1, True, dec4)
        btcP5 = ice.privatekey_to_address(1, True, dec5)
        btcP6 = ice.privatekey_to_address(1, True, dec6)
        btcP7 = ice.privatekey_to_address(1, True, dec7)
        btcP8 = ice.privatekey_to_address(1, True, dec8)
        btcP9 = ice.privatekey_to_address(1, True, dec9)
        btcP10 = ice.privatekey_to_address(1, True, dec10)
        btcP11 = ice.privatekey_to_address(1, True, dec11)
        btcP12 = ice.privatekey_to_address(1, True, dec12)
        btcP13 = ice.privatekey_to_address(1, True, dec13)
        btcP14 = ice.privatekey_to_address(1, True, dec14)
        btcP15 = ice.privatekey_to_address(1, True, dec15)
        btcP16 = ice.privatekey_to_address(1, True, dec16)
        btcP17 = ice.privatekey_to_address(1, True, dec17)
        btcP18 = ice.privatekey_to_address(1, True, dec18)
        btcB = ice.privatekey_to_address(2, True, dec)
        btcB0 = ice.privatekey_to_address(2, True, dec0)
        btcB1 = ice.privatekey_to_address(2, True, dec1)
        btcB2 = ice.privatekey_to_address(2, True, dec2)
        btcB3 = ice.privatekey_to_address(2, True, dec3)
        btcB4 = ice.privatekey_to_address(2, True, dec4)
        btcB5 = ice.privatekey_to_address(2, True, dec5)
        btcB6 = ice.privatekey_to_address(2, True, dec6)
        btcB7 = ice.privatekey_to_address(2, True, dec7)
        btcB8 = ice.privatekey_to_address(2, True, dec8)
        btcB9 = ice.privatekey_to_address(2, True, dec9)
        btcB10 = ice.privatekey_to_address(2, True, dec10)
        btcB11 = ice.privatekey_to_address(2, True, dec11)
        btcB12 = ice.privatekey_to_address(2, True, dec12)
        btcB13 = ice.privatekey_to_address(2, True, dec13)
        btcB14 = ice.privatekey_to_address(2, True, dec14)
        btcB15 = ice.privatekey_to_address(2, True, dec15)
        btcB16 = ice.privatekey_to_address(2, True, dec16)
        btcB17 = ice.privatekey_to_address(2, True, dec17)
        btcB18 = ice.privatekey_to_address(2, True, dec18)
        scantext =f'''
        
{hex(dec)[2:].zfill(64)}    |   {hex(dec9)[2:].zfill(64)}
{hex(dec0)[2:].zfill(64)}    |   {hex(dec10)[2:].zfill(64)}
{hex(dec1)[2:].zfill(64)}    |   {hex(dec11)[2:].zfill(64)}
{hex(dec2)[2:].zfill(64)}    |   {hex(dec12)[2:].zfill(64)}
{hex(dec3)[2:].zfill(64)}    |   {hex(dec13)[2:].zfill(64)}
{hex(dec4)[2:].zfill(64)}    |   {hex(dec14)[2:].zfill(64)}
{hex(dec5)[2:].zfill(64)}    |   {hex(dec15)[2:].zfill(64)}
{hex(dec6)[2:].zfill(64)}    |   {hex(dec16)[2:].zfill(64)}
{hex(dec7)[2:].zfill(64)}    |   {hex(dec17)[2:].zfill(64)}
{hex(dec8)[2:].zfill(64)}    |   {hex(dec18)[2:].zfill(64)}
'''
        if  btcC in bloom_filterbtc or btcU in bloom_filterbtc or btcP in bloom_filterbtc or btcB in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex):  {hex(dec)[2:].zfill(64)}
Decimal     (dec): {dec}
BTCc        : {btcC}
BTCu        : {btcU}
BTC p2sh    : {btcP}
BTC BC1     : {btcB}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC0 in bloom_filterbtc or btcU0 in bloom_filterbtc or btcP0 in bloom_filterbtc or btcB0 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec0)[2:].zfill(64)}
Decimal     (dec): {dec0}
BTCc        : {btcC0}
BTCu        : {btcU0}
BTC p2sh    : {btcP0}
BTC BC1     : {btcB0}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC1 in bloom_filterbtc or btcU1 in bloom_filterbtc or btcP1 in bloom_filterbtc or btcB1 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec1)[2:].zfill(64)}
Decimal     (dec): {dec1}
BTCc        : {btcC1}
BTCu        : {btcU1}
BTC p2sh    : {btcP1}
BTC BC1     : {btcB1}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC2 in bloom_filterbtc or btcU2 in bloom_filterbtc or btcP2 in bloom_filterbtc or btcB2 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec2)[2:].zfill(64)}
Decimal     (dec): {dec2}
BTCc        : {btcC2}
BTCu        : {btcU2}
BTC p2sh    : {btcP2}
BTC BC1     : {btcB2}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC3 in bloom_filterbtc or btcU3 in bloom_filterbtc or btcP3 in bloom_filterbtc or btcB3 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec3)[2:].zfill(64)}
Decimal     (dec): {dec3}
BTCc        : {btcC3}
BTCu        : {btcU3}
BTC p2sh    : {btcP3}
BTC BC1     : {btcB3}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC4 in bloom_filterbtc or btcU4 in bloom_filterbtc or btcP4 in bloom_filterbtc or btcB4 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec4)[2:].zfill(64)}
Decimal     (dec): {dec4}
BTCc        : {btcC4}
BTCu        : {btcU4}
BTC p2sh    : {btcP4}
BTC BC1     : {btcB4}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC5 in bloom_filterbtc or btcU5 in bloom_filterbtc or btcP5 in bloom_filterbtc or btcB5 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec5)[2:].zfill(64)}
Decimal     (dec): {dec5}
BTCc        : {btcC5}
BTCu        : {btcU5}
BTC p2sh    : {btcP5}
BTC BC1     : {btcB5}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC6 in bloom_filterbtc or btcU6 in bloom_filterbtc or btcP6 in bloom_filterbtc or btcB6 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec6)[2:].zfill(64)}
Decimal     (dec): {dec6}
BTCc        : {btcC6}
BTCu        : {btcU6}
BTC p2sh    : {btcP6}
BTC BC1     : {btcB6}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC7 in bloom_filterbtc or btcU7 in bloom_filterbtc or btcP7 in bloom_filterbtc or btcB7 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec7)[2:].zfill(64)}
Decimal     (dec): {dec7}
BTCc        : {btcC7}
BTCu        : {btcU7}
BTC p2sh    : {btcP7}
BTC BC1     : {btcB7}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC8 in bloom_filterbtc or btcU8 in bloom_filterbtc or btcP8 in bloom_filterbtc or btcB8 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec8)[2:].zfill(64)}
Decimal     (dec): {dec8}
BTCc        : {btcC8}
BTCu        : {btcU8}
BTC p2sh    : {btcP8}
BTC BC1     : {btcB8}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC9 in bloom_filterbtc or btcU9 in bloom_filterbtc or btcP9 in bloom_filterbtc or btcB9 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec9)[2:].zfill(64)}
Decimal     (dec): {dec9}
BTCc        : {btcC9}
BTCu        : {btcU9}
BTC p2sh    : {btcP9}
BTC BC1     : {btcB9}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC10 in bloom_filterbtc or btcU10 in bloom_filterbtc or btcP10 in bloom_filterbtc or btcB10 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec10)[2:].zfill(64)}
Decimal     (dec): {dec10}
BTCc        : {btcC10}
BTCu        : {btcU10}
BTC p2sh    : {btcP10}
BTC BC1     : {btcB10}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC11 in bloom_filterbtc or btcU11 in bloom_filterbtc or btcP11 in bloom_filterbtc or btcB11 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec11)[2:].zfill(64)}
Decimal     (dec): {dec11}
BTCc        : {btcC11}
BTCu        : {btcU11}
BTC p2sh    : {btcP11}
BTC BC1     : {btcB11}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC12 in bloom_filterbtc or btcU12 in bloom_filterbtc or btcP12 in bloom_filterbtc or btcB12 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec12)[2:].zfill(64)}
Decimal     (dec): {dec12}
BTCc        : {btcC12}
BTCu        : {btcU12}
BTC p2sh    : {btcP12}
BTC BC1     : {btcB12}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC13 in bloom_filterbtc or btcU13 in bloom_filterbtc or btcP13 in bloom_filterbtc or btcB13 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec13)[2:].zfill(64)}
Decimal     (dec): {dec13}
BTCc        : {btcC13}
BTCu        : {btcU13}
BTC p2sh    : {btcP13}
BTC BC1     : {btcB13}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC14 in bloom_filterbtc or btcU14 in bloom_filterbtc or btcP14 in bloom_filterbtc or btcB14 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec14)[2:].zfill(64)}
Decimal     (dec): {dec14}
BTCc        : {btcC14}
BTCu        : {btcU14}
BTC p2sh    : {btcP14}
BTC BC1     : {btcB14}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC15 in bloom_filterbtc or btcU15 in bloom_filterbtc or btcP15 in bloom_filterbtc or btcB15 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec15)[2:].zfill(64)}
Decimal     (dec): {dec15}
BTCc        : {btcC15}
BTCu        : {btcU15}
BTC p2sh    : {btcP15}
BTC BC1     : {btcB15}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC16 in bloom_filterbtc or btcU16 in bloom_filterbtc or btcP16 in bloom_filterbtc or btcB16 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec16)[2:].zfill(64)}
Decimal     (dec): {dec16}
BTCc        : {btcC16}
BTCu        : {btcU16}
BTC p2sh    : {btcP16}
BTC BC1     : {btcB16}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC17 in bloom_filterbtc or btcU17 in bloom_filterbtc or btcP17 in bloom_filterbtc or btcB17 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec17)[2:].zfill(64)}
Decimal     (dec): {dec17}
BTCc        : {btcC17}
BTCu        : {btcU17}
BTC p2sh    : {btcP17}
BTC BC1     : {btcB17}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if btcC18 in bloom_filterbtc or btcU18 in bloom_filterbtc or btcP18 in bloom_filterbtc or btcB18 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {hex(dec18)[2:].zfill(64)}
Decimal     (dec): {dec18}
BTCc        : {btcC18}
BTCu        : {btcU18}
BTC p2sh    : {btcP18}
BTC BC1     : {btcB18}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundbtc_rot.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        dec+=r 
        dec0+=r
        dec1+=r
        dec2+=r
        dec3+=r
        dec4+=r
        dec5+=r
        dec6+=r
        dec7+=r
        dec8+=r
        dec9+=r
        dec10+=r
        dec11+=r
        dec12+=r
        dec13+=r
        dec14+=r
        dec15+=r
        dec16+=r
        dec17+=r
        dec18+=r
        return scantext

# Recovery Program
def complete_key(rec_IN_string, missing_letters):
    for letter in missing_letters:
        rec_IN_string = rec_IN_string.replace('*', letter, 1)
    return rec_IN_string

def btc_address_from_private_key(my_secret, secret_type):
    assert secret_type in ['WIF', 'HEX', 'DEC', 'mnemonic']
    match secret_type:
        case 'WIF':
            if my_secret.startswith('5H') or my_secret.startswith('5J') or my_secret.startswith('5K') or my_secret.startswith('K') or my_secret.startswith('L'):
                if my_secret.startswith('5H') or my_secret.startswith('5J') or my_secret.startswith('5K'):
                    first_encode = base58.b58decode(my_secret)
                    private_key_full = binascii.hexlify(first_encode)
                    private_key = private_key_full[2:-8]
                    private_key_hex = private_key.decode("utf-8")
                    dec = int(private_key_hex,16)
                elif my_secret.startswith('K') or my_secret.startswith('L'):
                    first_encode = base58.b58decode(my_secret)
                    private_key_full = binascii.hexlify(first_encode)
                    private_key = private_key_full[2:-8]
                    private_key_hex = private_key.decode("utf-8")
                    dec = int(private_key_hex[0:64],16)
        case 'HEX':
            dec = int(my_secret[0:64],16)
        case 'mnemonic':
            raise "Mnemonic secrets not implemented"
        case 'DEC':
            dec = int(my_secret)
        case _:
            raise "I don't know how to handle this type."

    return dec

def recovery_main(self, scan_IN, rec_IN, mode):
    add_find = self._txt_inputadd_look.get()
    missing_length = rec_IN.count('*')
    key_length = len(rec_IN)
    recoverytext = f'Looking for {missing_length} characters in {rec_IN}'
    self.labelWIF1.config(text = recoverytext)
    self.labelWIF1.update()
    match scan_IN:
        case 'WIF':
            secret_type = 'WIF'
            allowed_characters = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        case 'HEX':
            secret_type = 'HEX'
            allowed_characters = '0123456789abcdef'
        case 'DEC':
            secret_type = 'DEC'
            allowed_characters = '0123456789'
        case _:
            secret_type = 'mnemonic'
            allowed_characters = wordlist

    missing_letters_master_list = trotter.Amalgams(missing_length, allowed_characters)
    try:
        self.labelWIF2.config(text = missing_letters_master_list)
        self.labelWIF2.update()
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
                pvk = bip39seed_to_private_key(seed, 1)
                pvk2 = bip39seed_to_private_key2(seed, 1)
                pvk3 = bip39seed_to_private_key3(seed, 1)
                pvk4 = bip39seed_to_private_key4(seed, i)
                caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
                uaddr = ice.privatekey_to_address(0, False, (int.from_bytes(pvk, "big")))
                p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
                bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
                ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
                print(f" Path m/44'/60'/0'/0/{i} mnemonic: {potential_key}", end='\r')
        else:
            dec = btc_address_from_private_key(potential_key, secret_type=secret_type)
            uaddr = ice.privatekey_to_address(0, False, dec)
            caddr = ice.privatekey_to_address(0, True, dec)
            p2sh = ice.privatekey_to_address(1, True, dec)
            bech32 = ice.privatekey_to_address(2, True, dec)
            ethaddr = ice.privatekey_to_ETH_address(dec)
        self.labelWIF3.config(text = potential_key)
        self.labelWIF3.update()
        remaining -= 1
        self.labelWIF4.config(text = remaining)
        self.labelWIF4.update()
        if caddr in bloom_filterbtc or caddr in add_find:
            wintext = f"\n key: {potential_key} address: {caddr}"
            f=open('foundcaddr.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundbtc_recovery.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if uaddr in bloom_filterbtc or uaddr in add_find:
            wintext = f"\n key: {potential_key} address: {uaddr}"
            f=open('founduaddr.txt','a')
            self.found+=1
            self.foundbtc_recovery.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if p2sh in bloom_filterbtc or p2sh in add_find:
            wintext = f"\n key: {potential_key} address: {p2sh}"
            f=open('foundp2sh.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundbtc_recovery.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if bech32 in bloom_filterbtc or bech32 in add_find:
            wintext = f"\n key: {potential_key} address: {bech32}"
            f=open('foundbech32.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundbtc_recovery.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
        if ethaddr[2:] in bloom_filtereth or ethaddr in add_find.lower():
            wintext = f"\n key: {potential_key} address: {ethaddr}"
            f=open('foundeth.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundbtc_recovery.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            send_email(self.WINTEXT)
            
#############################################################################################
def super_bal(self, dec):
    caddr = ice.privatekey_to_address(0, True, dec)
    response = requests.get("https://blockstream.info/api/address/" + str(caddr))
    balance = float(response.json()['chain_stats']['funded_txo_sum'])
    totalSent = float(response.json()['chain_stats']['spent_txo_sum'])
    txs = response.json()['chain_stats']['funded_txo_count']
    #uaddr = ice.privatekey_to_address(0, False, dec)
    HEX = "%064x" % dec
    wifc = ice.btc_pvk_to_wif(HEX)
    #wifu = ice.btc_pvk_to_wif(HEX, False)
    #p2sh = ice.privatekey_to_address(1, True, dec)
    #bech32 = ice.privatekey_to_address(2, True, dec)
    length = len(bin(dec))
    length -=2
    baltext = f'''==================================================================================
Bits: {length}
Dec : {dec}
Hex : {HEX}
WIF : {wifc}
Bitcoin Address : {caddr} :
TotalReceived = [{balance}] : TotalSent =  [{totalSent}] : Transactions = [{txs}]
==================================================================================
'''
    if int(txs) > 0:
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        self.WINTEXT = baltext
        with open('found.txt', 'a', encoding='utf-8') as f:
            f.write(f' \n {baltext}')
        self.popwinner()
        send_email(self.WINTEXT)
    return baltext
