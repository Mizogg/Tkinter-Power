import secp256k1 as ice
import random
from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
import tkinter as tk
from tkinter import * 
from tkinter.ttk import *
from time import strftime, sleep
from pathlib import Path
import webbrowser

window = tk.Tk()
window.geometry("820x500")
window.config(bg="#F39C12")
window.resizable(width=True,height=True)
window.title('Bitcoin Wallet Generator @Mizogg2022')

run= True


def donothing():
   x = 0


def openweb():
   x = webbrowser.open("https://mizogg.co.uk")
   
def opentelegram():
   x = webbrowser.open("https://t.me/CryptoCrackersUK")
   
def time():
    string = strftime('%H:%M:%S %p')
    lbl.config(text = string)
    lbl.after(1000, time)
  
# clock
lbl = Label(font = ('calibri', 40, 'bold'),
            background = 'purple',
            foreground = 'white')
  
with open('puzzle.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)
addr_count = len(bloom_filterbtc)  
addr_count_print = f'Total Bitcoin Addresses Loaded and Checking : {addr_count}'
print(addr_count_print)  

max_p = 115792089237316195423570985008687907852837564279074904382605163141518161494336
totaladd = total = found =0

# SAVE and Sart
filename = 'startdec.txt'
path = Path(filename)


if path.is_file():
    with open(filename, newline='', encoding='utf-8') as f:
        contents = f.readline()
        startdec = int(contents)
        print (startdec)
else:
    startdec = 1
stopdec = max_p


def start():
   global run
   run= True

def stop():
   global run
   run= False
   

def RandomInteger(minN, maxN):
    return random.randrange(minN, maxN)

        
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
            print(f' Instance: Random_Bruteforce - Found: {caddr}')
            l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
        if uaddr in bloom_filterbtc:
            print(f' Instance: Random_Bruteforce - Found: {uaddr}')
            l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
        if p2sh in bloom_filterbtc:
            print(f' Instance: Random_Bruteforce - Found: {p2sh}')
            l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh} \n')
        if bech32 in bloom_filterbtc:
            print(f' Instance: Random_Bruteforce - Found: {bech32}')
            l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Random_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        l2.config(text = f' Instance: Random_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBTC Address Uncompressed: {uaddr} \nWIF Compressed: {wifu} \nBTC Address p2sh: {p2sh} \nBTC Address bech32: {bech32}')
        l2.update()
        total+=1
        totaladd+=4
        l4.config(text = f'{total}')
        l6.config(text = f'{totaladd}')
    
    
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
            print(f' Instance: Sequential_Bruteforce - Found: {caddr}')
            print(f' WINNER WINNER Check found.txt \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
        if uaddr in bloom_filterbtc:
            print(f' Instance: Sequential_Bruteforce - Found: {uaddr}')
            l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Sequential_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
        if p2sh in bloom_filterbtc:
            print(f' Instance: Sequential_Bruteforce - Found: {p2sh}')
            l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Sequential_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}\n')
        if bech32 in bloom_filterbtc:
            print(f' Instance: Sequential_Bruteforce - Found: {bech32}')
            l2.config(text = f' WINNER WINNER Check found.txt \n Instance: Sequential_Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
            found+=1
            l8.config(text = f'{found}')
            with open('found.txt', 'a') as result:
                result.write(f'\n Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}\n')
        l2.config(text = f' Instance: Sequential_Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc} \nBTC Address Uncompressed: {uaddr} \nWIF Compressed: {wifu} \nBTC Address p2sh: {p2sh} \nBTC Address bech32: {bech32}')
        with open('startdec.txt', 'w') as save:
            save.write(str(startdec))
        startdec = startdec +1
        l2.update()
        total+=1
        totaladd+=4
        l4.config(text = f'{total}')
        l6.config(text = f'{totaladd}')
        
menubar = Menu(window)
filemenu = Menu(menubar, tearoff=0)
# filemenu.add_command(label="New", command=donothing)
# filemenu.add_command(label="Open", command=donothing)
# filemenu.add_command(label="Save", command=donothing)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=window.quit)
menubar.add_cascade(label="File", menu=filemenu)

helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="Help Telegram", command=opentelegram)
helpmenu.add_command(label="About Mizogg...", command=openweb)
menubar.add_cascade(label="Help", menu=helpmenu)
window.config(menu=menubar)
l1 = tk.Label(text="Random Wallet Generator Made by Mizogg @ 2022",font=("Arial",20),bg="Black",fg="White")

t1 = tk.Label(text=addr_count_print,font=("Arial",14),bg="Black",fg="White")

r1 = tk.Button(text="Click on me to generate Random Wallets in a Range ",font=("Arial",15),bg="#A3E4D7",command=Random_Bruteforce_Speed)

s1 = tk.Button(text="Click on me to generate Sequential Wallets in a Range",font=("Arial",15),bg="#A3E4D7",command=Sequential_Bruteforce_speed)

start= tk.Button(text= "Start",font=("Arial",15),bg="#A3E4D7", command= start)
stop= tk.Button(text= "Stop",font=("Arial",15),bg="#A3E4D7", command= stop)

l2 = tk.Label(bg="#F39C12",font=("Arial",12),text="")

l3 = tk.Label(text="Total Private Keys : ",font=("Arial",12),bg="Black",fg="White")
l4 = tk.Label(bg="#F39C12",font=("Arial",12),text="")

l5 = tk.Label(text="Total Addresses   : ",font=("Arial",12),bg="Black",fg="White")
l6 = tk.Label(bg="#F39C12",font=("Arial",12),text="")

l7 = tk.Label(text="Total Found ",font=("Arial",18),bg="purple",fg="white")
l8 = tk.Label(bg="purple",font=("Arial",12),text="0")

lbl.pack(anchor = 'center')
l1.place(x=100,y=70)
t1.place(x=100,y=110)
r1.place(x=170,y=140)
s1.place(x=170,y=190)
start.place(x=230,y=230)
stop.place(x=330,y=230)
l2.place(x=30,y=270)
l3.place(x=430,y=230)
l4.place(x=570,y=230)
l5.place(x=430,y=250)
l6.place(x=570,y=250)
l7.place(x=600,y=5)
l8.place(x=660,y=40)

time()

window.mainloop()