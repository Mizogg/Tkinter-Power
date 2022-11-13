#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Created by @Mizogg 13.11.2022 https://t.me/CryptoCrackersUK
import hmac, struct, codecs, sys, os, binascii, hashlib
import webbrowser
import random
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
def rwr(self, mnem):
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
    wordvartext1 = (f'''====================================================:Balance:Received:Sent:TXS:
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
        WINTEXT = f'\n Mnemonic : {mnem} \n\n {wordvartext1}'
        with open('found.txt', 'a', encoding='utf-8') as f:
            f.write(WINTEXT)
    return wordvartext1

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
====================================='''

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
    brainvartext1 = (f'\n Private Key In HEX : \n\n {private_key} \n\n Bitcoin Adress : {caddr} \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
    if int(txs) > 0 :
        self.found+=1
        self.foundbw.config(text = f'{self.found}')
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(f'\n BrainWallet : {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
        self.WINTEXT = (f"BrainWallet : {passphrase}\n HEX Key: {private_key} \n BTC Address Compressed: {caddr}  \n \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]")
        self.popwinner()
    return brainvartext1
    
def rboffline(self, passphrase):
    wallet = BrainWallet()
    private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
    brainvartext1 = (f'\n Private Key In HEX : \n\n {private_key} \n\n Bitcoin Adress : {caddr} ')
    if caddr in bloom_filterbtc:
        self.found+=1
        self.foundbw.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress : {caddr}')
        with open("found.txt", "a", encoding="utf-8") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    return brainvartext1

def rwonline(self, mnem):
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
    wordvartext1 = (f'\n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] \n TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]')
    if int(txs) > 0 :
        self.found+=1
        self.foundword.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic : {mnem} \n Dec Key: {dec} \n HEX Key: {HEX} \n Bitcoin Adress : {caddr} \n Balance  [{balance}] TotalReceived : [{totalReceived}] TotalSent : [{totalSent}] Transactions : [{txs}]'
        with open('found.txt', 'a', encoding='utf-8') as f:
            f.write(self.WINTEXT)
        self.popwinner()
    return wordvartext1

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
    wordvartext1 = (f' Bitcoin {cpath} :  {caddr} \n Bitcoin {cpath} : Decimal Private Key \n {dec} \n Bitcoin {cpath} : Hexadecimal Private Key \n {HEX}  \n Bitcoin {ppath} :  {p2sh}\n Bitcoin {ppath} : Decimal Private Key \n {dec2} \n Bitcoin {ppath} :  Hexadecimal Private Key \n {HEX2} \n Bitcoin {bpath} : {bech32}\n Bitcoin {bpath} : Decimal Private Key \n {dec3} \n Bitcoin {bpath} : Hexadecimal Private Key \n {HEX3} ')
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
    return wordvartext1
