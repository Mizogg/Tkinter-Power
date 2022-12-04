#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 04.12.2022 https://t.me/CryptoCrackersUK
import hmac, struct, codecs, sys, os, binascii, hashlib
import webbrowser
import random
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import secp256k1 as ice
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
    
with open('puzzle.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)
def countadd():
    addr_count = len(bloom_filterbtc)
    addr_count_print = (f'Total Bitcoin Addresses Loaded and Checking : {addr_count}')
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

derivation_total_path_to_check = 1
def rwonline(self, mnem):
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
    wordvartext = (f'''====================================================:Balance:Received:Sent:TXS:
Bitcoin Address : {caddr} : [{balance}] : [{totalReceived}] : [{totalSent}] : [{txs}]
Hexadecimal Private Key : {HEX}

Bitcoin Address : {p2sh} : [{balance2}] : [{totalReceived2}] : [{totalSent2}] : [{txs2}]
Hexadecimal Private Key : {HEX2}

Bitcoin Address : {bech32} : [{balance3}] : [{totalReceived3}] : [{totalSent3}] : [{txs3}]
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
    return wordvartext

def rwoffline(self, mnem):
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
    wordvartext = (f' Bitcoin {cpath} :  {caddr} \n Bitcoin {cpath} : Decimal Private Key \n {dec} \n Bitcoin {cpath} : Hexadecimal Private Key \n {HEX}  \n Bitcoin {ppath} :  {p2sh}\n Bitcoin {ppath} : Decimal Private Key \n {dec2} \n Bitcoin {ppath} :  Hexadecimal Private Key \n {HEX2} \n Bitcoin {bpath} : {bech32}\n Bitcoin {bpath} : Decimal Private Key \n {dec3} \n Bitcoin {bpath} : Hexadecimal Private Key \n {HEX3} ')
    if caddr in bloom_filterbtc:
        self.found+=1
        self.foundword.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {cpath} :  {caddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if p2sh in bloom_filterbtc:
        self.found+=1
        self.foundword.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {ppath} :  {p2sh}\nDecimal Private Key \n {dec2} \n Hexadecimal Private Key \n {HEX2} \n'
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.found+=1
        self.foundword.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {bpath} : {bech32}\n Decimal Private Key \n {dec3} \n Hexadecimal Private Key \n {HEX3} \n'
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    return wordvartext
    
def brute_btc(self, dec):
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
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('found.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}")
        self.popwinner()
    if uaddr in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('found.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}")
        self.popwinner()
    if p2sh in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('found.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh} \n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh}")
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.found+=1
        self.foundbtc.config(text = f'{self.found}')
        with open('found.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address bech32: {bech32}")
        self.popwinner()
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
            print(output)
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            with open('foundcaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()

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
            print(output)
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            with open('founduaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
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
            print(output)
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            with open('foundp2sh.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()

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
            print(output)
            self.page_brute.config(text = output)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            with open('foundbech32.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
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
{lines}'''
    return scantext

def rbonline(self, passphrase):
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
    brainvartext = (f'\n Private Key In HEX : \n {private_key} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
    if int(txs) > 0 :
        self.found+=1
        self.foundbw.config(text = f'{self.found}')
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(f'\n BrainWallet : {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
        self.WINTEXT = (f"BrainWallet : {passphrase}\n HEX Key: {private_key} \n BTC Address Compressed: {caddr}  \n \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]")
        self.popwinner()
    return brainvartext
    
def rboffline(self, passphrase):
    wallet = BrainWallet()
    private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
    brainvartext = (f'\n Private Key In HEX : \n\n {private_key} \n\n Bitcoin Adress : {caddr} ')
    if caddr in bloom_filterbtc:
        self.found+=1
        self.foundbw.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {caddr}')
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
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
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if uaddr in bloom_filterbtc:
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu} \nBinary Data: \n {binstring}")
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if p2sh in bloom_filterbtc:
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh} \nBinary Data: \n {binstring}")
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Bc1: {bech32} \nBinary Data: \n {binstring}")
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()

def hexhunter(self, dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18):
    s = (hex(dec)[2:]).zfill(64)
    s0 = (hex(dec0)[2:]).zfill(64) # P64
    s1 = (hex(dec1)[2:]).zfill(64)
    s2 = (hex(dec2)[2:]).zfill(64)
    s3 = (hex(dec3)[2:]).zfill(64)
    s4 = (hex(dec4)[2:]).zfill(64)
    s5 = (hex(dec5)[2:]).zfill(64)
    s6 = (hex(dec6)[2:]).zfill(64)
    s7 = (hex(dec7)[2:]).zfill(64)
    s8 = (hex(dec8)[2:]).zfill(64)
    s9 = (hex(dec9)[2:]).zfill(64)
    s10 = (hex(dec10)[2:]).zfill(64)
    s11 = (hex(dec11)[2:]).zfill(64)
    s12 = (hex(dec12)[2:]).zfill(64)
    s13 = (hex(dec13)[2:]).zfill(64)
    s14 = (hex(dec14)[2:]).zfill(64)
    s15 = (hex(dec15)[2:]).zfill(64)
    s16 = (hex(dec16)[2:]).zfill(64)
    s17 = (hex(dec17)[2:]).zfill(64)
    s18 = (hex(dec18)[2:]).zfill(64)
    for r in range(64):
        pk= int((s[r:] + s[:r]),16)
        pk0= int((s0[r:] + s0[:r]),16)
        pk1= int((s1[r:] + s1[:r]),16)
        pk2= int((s2[r:] + s2[:r]),16)
        pk3= int((s0[r:] + s1[:r]),16)
        pk4= int((s1[r:] + s0[:r]),16)
        pk5= int((s3[r:] + s3[:r]),16)
        pk6= int((s4[r:] + s4[:r]),16)
        pk7= int((s5[r:] + s5[:r]),16)
        pk8= int((s6[r:] + s6[:r]),16)
        pk9= int((s7[r:] + s7[:r]),16)
        pk10= int((s8[r:] + s8[:r]),16)
        pk11= int((s9[r:] + s9[:r]),16)
        pk12= int((s10[r:] + s10[:r]),16)
        pk13= int((s11[r:] + s11[:r]),16)
        pk14= int((s12[r:] + s12[:r]),16)
        pk15= int((s13[r:] + s13[:r]),16)
        pk14= int((s14[r:] + s14[:r]),16)
        pk15= int((s15[r:] + s15[:r]),16)
        pk16= int((s16[r:] + s16[:r]),16)
        pk17= int((s17[r:] + s17[:r]),16)
        pk18= int((s18[r:] + s17[:r]),16)
        btcC = ice.privatekey_to_address(0, True, pk)
        btcC0 = ice.privatekey_to_address(0, True, pk0)
        btcC1 = ice.privatekey_to_address(0, True, pk1)
        btcC2 = ice.privatekey_to_address(0, True, pk2)
        btcC3 = ice.privatekey_to_address(0, True, pk3)
        btcC4 = ice.privatekey_to_address(0, True, pk4)
        btcC5 = ice.privatekey_to_address(0, True, pk5)
        btcC6 = ice.privatekey_to_address(0, True, pk6)
        btcC7 = ice.privatekey_to_address(0, True, pk7)
        btcC8 = ice.privatekey_to_address(0, True, pk8)
        btcC9 = ice.privatekey_to_address(0, True, pk9)
        btcC10 = ice.privatekey_to_address(0, True, pk10)
        btcC11 = ice.privatekey_to_address(0, True, pk11)
        btcC12 = ice.privatekey_to_address(0, True, pk12)
        btcC13 = ice.privatekey_to_address(0, True, pk13)
        btcC14 = ice.privatekey_to_address(0, True, pk14)
        btcC15 = ice.privatekey_to_address(0, True, pk15)
        btcC16 = ice.privatekey_to_address(0, True, pk16)
        btcC17 = ice.privatekey_to_address(0, True, pk17)
        btcC18 = ice.privatekey_to_address(0, True, pk18)
        btcU = ice.privatekey_to_address(0, False, pk)
        btcU0 = ice.privatekey_to_address(0, False, pk0)
        btcU1 = ice.privatekey_to_address(0, False, pk1)
        btcU2 = ice.privatekey_to_address(0, False, pk2)
        btcU3 = ice.privatekey_to_address(0, False, pk3)
        btcU4 = ice.privatekey_to_address(0, False, pk4)
        btcU5 = ice.privatekey_to_address(0, False, pk5)
        btcU6 = ice.privatekey_to_address(0, False, pk6)
        btcU7 = ice.privatekey_to_address(0, False, pk7)
        btcU8 = ice.privatekey_to_address(0, False, pk8)
        btcU9 = ice.privatekey_to_address(0, False, pk9)
        btcU10 = ice.privatekey_to_address(0, False, pk10)
        btcU11 = ice.privatekey_to_address(0, False, pk11)
        btcU12 = ice.privatekey_to_address(0, False, pk12)
        btcU13 = ice.privatekey_to_address(0, False, pk13)
        btcU14 = ice.privatekey_to_address(0, False, pk14)
        btcU15 = ice.privatekey_to_address(0, False, pk15)
        btcU16 = ice.privatekey_to_address(0, False, pk16)
        btcU17 = ice.privatekey_to_address(0, False, pk17)
        btcU18 = ice.privatekey_to_address(0, False, pk18)
        btcP = ice.privatekey_to_address(1, True, pk)
        btcP0 = ice.privatekey_to_address(1, True, pk0)
        btcP1 = ice.privatekey_to_address(1, True, pk1)
        btcP2 = ice.privatekey_to_address(1, True, pk2)
        btcP3 = ice.privatekey_to_address(1, True, pk3)
        btcP4 = ice.privatekey_to_address(1, True, pk4)
        btcP5 = ice.privatekey_to_address(1, True, pk5)
        btcP6 = ice.privatekey_to_address(1, True, pk6)
        btcP7 = ice.privatekey_to_address(1, True, pk7)
        btcP8 = ice.privatekey_to_address(1, True, pk8)
        btcP9 = ice.privatekey_to_address(1, True, pk9)
        btcP10 = ice.privatekey_to_address(1, True, pk10)
        btcP11 = ice.privatekey_to_address(1, True, pk11)
        btcP12 = ice.privatekey_to_address(1, True, pk12)
        btcP13 = ice.privatekey_to_address(1, True, pk13)
        btcP14 = ice.privatekey_to_address(1, True, pk14)
        btcP15 = ice.privatekey_to_address(1, True, pk15)
        btcP16 = ice.privatekey_to_address(1, True, pk16)
        btcP17 = ice.privatekey_to_address(1, True, pk17)
        btcP18 = ice.privatekey_to_address(1, True, pk18)
        btcB = ice.privatekey_to_address(2, True, pk)
        btcB0 = ice.privatekey_to_address(2, True, pk0)
        btcB1 = ice.privatekey_to_address(2, True, pk1)
        btcB2 = ice.privatekey_to_address(2, True, pk2)
        btcB3 = ice.privatekey_to_address(2, True, pk3)
        btcB4 = ice.privatekey_to_address(2, True, pk4)
        btcB5 = ice.privatekey_to_address(2, True, pk5)
        btcB6 = ice.privatekey_to_address(2, True, pk6)
        btcB7 = ice.privatekey_to_address(2, True, pk7)
        btcB8 = ice.privatekey_to_address(2, True, pk8)
        btcB9 = ice.privatekey_to_address(2, True, pk9)
        btcB10 = ice.privatekey_to_address(2, True, pk10)
        btcB11 = ice.privatekey_to_address(2, True, pk11)
        btcB12 = ice.privatekey_to_address(2, True, pk12)
        btcB13 = ice.privatekey_to_address(2, True, pk13)
        btcB14 = ice.privatekey_to_address(2, True, pk14)
        btcB15 = ice.privatekey_to_address(2, True, pk15)
        btcB16 = ice.privatekey_to_address(2, True, pk16)
        btcB17 = ice.privatekey_to_address(2, True, pk17)
        btcB18 = ice.privatekey_to_address(2, True, pk18)
        if  btcC in bloom_filterbtc or btcU in bloom_filterbtc or btcP in bloom_filterbtc or btcB in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex):  {s}
Decimal     (dec): {str(pk)}
BTCc        : {btcC}
BTCu        : {btcU}
BTC p2sh    : {btcP}
BTC BC1     : {btcB}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC0 in bloom_filterbtc or btcU0 in bloom_filterbtc or btcP0 in bloom_filterbtc or btcB0 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s0}
Decimal     (dec): {str(pk0)}
BTCc        : {btcC0}
BTCu        : {btcU0}
BTC p2sh    : {btcP0}
BTC BC1     : {btcB0}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC1 in bloom_filterbtc or btcU1 in bloom_filterbtc or btcP1 in bloom_filterbtc or btcB1 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s1}
Decimal     (dec): {str(pk1)}
BTCc        : {btcC1}
BTCu        : {btcU1}
BTC p2sh    : {btcP1}
BTC BC1     : {btcB1}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC2 in bloom_filterbtc or btcU2 in bloom_filterbtc or btcP2 in bloom_filterbtc or btcB2 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s2}
Decimal     (dec): {str(pk2)}
BTCc        : {btcC2}
BTCu        : {btcU2}
BTC p2sh    : {btcP2}
BTC BC1     : {btcB2}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC3 in bloom_filterbtc or btcU3 in bloom_filterbtc or btcP3 in bloom_filterbtc or btcB3 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s3}
Decimal     (dec): {str(pk3)}
BTCc        : {btcC3}
BTCu        : {btcU3}
BTC p2sh    : {btcP3}
BTC BC1     : {btcB3}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC4 in bloom_filterbtc or btcU4 in bloom_filterbtc or btcP4 in bloom_filterbtc or btcB4 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s4}
Decimal     (dec): {str(pk4)}
BTCc        : {btcC4}
BTCu        : {btcU4}
BTC p2sh    : {btcP4}
BTC BC1     : {btcB4}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC5 in bloom_filterbtc or btcU5 in bloom_filterbtc or btcP5 in bloom_filterbtc or btcB5 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s5}
Decimal     (dec): {str(pk5)}
BTCc        : {btcC5}
BTCu        : {btcU5}
BTC p2sh    : {btcP5}
BTC BC1     : {btcB5}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC6 in bloom_filterbtc or btcU6 in bloom_filterbtc or btcP6 in bloom_filterbtc or btcB6 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s6}
Decimal     (dec): {str(pk6)}
BTCc        : {btcC6}
BTCu        : {btcU6}
BTC p2sh    : {btcP6}
BTC BC1     : {btcB6}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC7 in bloom_filterbtc or btcU7 in bloom_filterbtc or btcP7 in bloom_filterbtc or btcB7 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s7}
Decimal     (dec): {str(pk7)}
BTCc        : {btcC7}
BTCu        : {btcU7}
BTC p2sh    : {btcP7}
BTC BC1     : {btcB7}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC8 in bloom_filterbtc or btcU8 in bloom_filterbtc or btcP8 in bloom_filterbtc or btcB8 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s8}
Decimal     (dec): {str(pk8)}
BTCc        : {btcC8}
BTCu        : {btcU8}
BTC p2sh    : {btcP8}
BTC BC1     : {btcB8}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC9 in bloom_filterbtc or btcU9 in bloom_filterbtc or btcP9 in bloom_filterbtc or btcB9 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s9}
Decimal     (dec): {str(pk9)}
BTCc        : {btcC9}
BTCu        : {btcU9}
BTC p2sh    : {btcP9}
BTC BC1     : {btcB9}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC10 in bloom_filterbtc or btcU10 in bloom_filterbtc or btcP10 in bloom_filterbtc or btcB10 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s10}
Decimal     (dec): {str(pk10)}
BTCc        : {btcC10}
BTCu        : {btcU10}
BTC p2sh    : {btcP10}
BTC BC1     : {btcB10}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC11 in bloom_filterbtc or btcU11 in bloom_filterbtc or btcP11 in bloom_filterbtc or btcB11 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s11}
Decimal     (dec): {str(pk11)}
BTCc        : {btcC11}
BTCu        : {btcU11}
BTC p2sh    : {btcP11}
BTC BC1     : {btcB11}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC12 in bloom_filterbtc or btcU12 in bloom_filterbtc or btcP12 in bloom_filterbtc or btcB12 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s12}
Decimal     (dec): {str(pk12)}
BTCc        : {btcC12}
BTCu        : {btcU12}
BTC p2sh    : {btcP12}
BTC BC1     : {btcB12}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC13 in bloom_filterbtc or btcU13 in bloom_filterbtc or btcP13 in bloom_filterbtc or btcB13 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s13}
Decimal     (dec): {str(pk13)}
BTCc        : {btcC13}
BTCu        : {btcU13}
BTC p2sh    : {btcP13}
BTC BC1     : {btcB13}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC14 in bloom_filterbtc or btcU14 in bloom_filterbtc or btcP14 in bloom_filterbtc or btcB14 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s14}
Decimal     (dec): {str(pk14)}
BTCc        : {btcC14}
BTCu        : {btcU14}
BTC p2sh    : {btcP14}
BTC BC1     : {btcB14}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC15 in bloom_filterbtc or btcU15 in bloom_filterbtc or btcP15 in bloom_filterbtc or btcB15 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s15}
Decimal     (dec): {str(pk15)}
BTCc        : {btcC15}
BTCu        : {btcU15}
BTC p2sh    : {btcP15}
BTC BC1     : {btcB15}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC16 in bloom_filterbtc or btcU16 in bloom_filterbtc or btcP16 in bloom_filterbtc or btcB16 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s16}
Decimal     (dec): {str(pk16)}
BTCc        : {btcC16}
BTCu        : {btcU16}
BTC p2sh    : {btcP16}
BTC BC1     : {btcB16}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC17 in bloom_filterbtc or btcU17 in bloom_filterbtc or btcP17 in bloom_filterbtc or btcB17 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s17}
Decimal     (dec): {str(pk17)}
BTCc        : {btcC17}
BTCu        : {btcU17}
BTC p2sh    : {btcP17}
BTC BC1     : {btcB17}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC18 in bloom_filterbtc or btcU18 in bloom_filterbtc or btcP18 in bloom_filterbtc or btcB18 in bloom_filterbtc:
            wintext = f'''
PrivateKey  (hex): {s18}
Decimal     (dec): {str(pk18)}
BTCc        : {btcC18}
BTCu        : {btcU18}
BTC p2sh    : {btcP18}
BTC BC1     : {btcB18}
=================================
'''
            f=open('Winner.txt','a')
            f.write(wintext)
            self.hex_brute.config(text = wintext)
            self.found+=1
            self.foundbtc.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        scantext =f'''
        
{hex(pk)[2:].zfill(64)}    |   {hex(pk9)[2:].zfill(64)}
{hex(pk0)[2:].zfill(64)}    |   {hex(pk10)[2:].zfill(64)}
{hex(pk1)[2:].zfill(64)}    |   {hex(pk11)[2:].zfill(64)}
{hex(pk2)[2:].zfill(64)}    |   {hex(pk12)[2:].zfill(64)}
{hex(pk3)[2:].zfill(64)}    |   {hex(pk13)[2:].zfill(64)}
{hex(pk4)[2:].zfill(64)}    |   {hex(pk14)[2:].zfill(64)}
{hex(pk5)[2:].zfill(64)}    |   {hex(pk15)[2:].zfill(64)}
{hex(pk6)[2:].zfill(64)}    |   {hex(pk16)[2:].zfill(64)}
{hex(pk7)[2:].zfill(64)}    |   {hex(pk17)[2:].zfill(64)}
{hex(pk8)[2:].zfill(64)}    |   {hex(pk18)[2:].zfill(64)}
'''
        return scantext
