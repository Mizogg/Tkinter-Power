
# ============================================================================= 
information = ('''
                Creating Bloom File (bloomfilter creation tool CBloom.py)
                
    Put Cbloom.py and your txt file you want to make a bloom from in the same folder then run cmd, 
        navigate to the script folder with CD FOLDERNAME then use command example :

                                python Cbloom.py btc.txt btc.bf
            
                                Cbloom.py can be found in the files folder...
            
                                pip install simplebloomfilter
            
                                pip install bitarray==1.9.2

                    Main Version from Evgeny Unholy for Cbloom
                https://github.com/evgenyunholy/UnholyMegaBrut
            
        THIS IS NOT where the main database file is kept to run Bitcoinhunter.py.

                                    !!!    Database File   !!!
                                        
            This is called puzzle.bf and is in the top main folder with the python program.
        
    This needs to be replaced with your own bloomfilter database using the bloomfilter creation tool CBloom.py
        (Make sure you call your file puzzle.bf or change it's name in the mizlib.py file)


            About Bitcoin : https://en.wikipedia.org/wiki/Bitcoin

    Bitcoin (Abbreviation: BTC; sign: ₿) is a decentralized digital currency that can be transferred 
    on the peer-to-peer bitcoin network.Bitcoin transactions are verified by network nodes through 
    cryptography and recorded in a public distributed ledger called a blockchain. 
    The cryptocurrency was invented in 2008 by an unknown person or group of people using the name Satoshi Nakamoto.

    The currency began use in 2009, when its implementation was released as open-source software.

    Bitcoin has been described as an economic bubble,
    by at least eight Nobel Memorial Prize in Economic Sciences recipients.

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
    which is the smallest possible division, and named in homage to bitcoin's creator, 
    representing 1⁄100000000 (one hundred millionth) bitcoin.
     100,000 satoshis are one mBTC.
 
                 Look for Bitcoin with tkinter and python in GUI.
                        Made By Mizogg.co.uk
                    Version = 1.13  (1810 Lines of code)
        New Recovery Tools Added Hunt for WIF DEC HEX Missing characters.
            
                    Version = 1.12  (1727 Lines of code) 
        Added Bitcoin Miner (TEST Work in Progress) Add you own wallet to miner Page.
    Start the miner and hunt for Bitcoin. the Miner will run in the CMD window Behind
            Fixed error in rotaion4 report to file
            Fixed error with starting private key in Pages Sequential
            
                    Version = 1.11  (1450 Lines of code) 
            Added Rotation4Bit @AlphaCentury, 28.04.22 
     Script to print all rotations of a randomly generated string.(EDITED)
        20 Ranges 64 private keys per range 4 addresses per key.
                        
                    Version = 1.10
    Added Seach by Pages 128 Private keys per page 512 Addresses (Much Faster)
               Memory leak Fixed on Brain, Mnemonic and 16x16
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
# =============================================================================
infocal = '''
 1.Write number and select operator at first, then click on equal(=) sign.
 
 2.For single digit operation(e.g. rad,exponent,Reciprocal(1/x),
 square,cube,square root,cube root,log,factorial(n!),exponent etc.)
 
 only write number input in the 'Number1' but not write
 input in 'Number2' .After that select favourable operator and go.
 
 3.For single no. operation,if there is present two no. in 'Number1'
 and 'Number2', only input number in 'Number1' will taken.
 
 Covert Sum to brain wallet !!! Good Luck
 '''
 # =============================================================================
infoROT = '''

Rotation4 Bitcoin 20 Scans 64 private keys per scan Total of 6800 Addresses.

They are 20 ranges in bits 1-256 you can set them to scan within that range.

This looks for Bitcoin Addresses 1 Compressed, Uncompressed, 
    Adresses startingwith 3 and Addresses starting bc1.
    
                Offline Scan for Bitcoin

!!!!!!   Best for speed in Random Ranges    !!!!!
 '''
 # =============================================================================
infoREC = '''

WIF HEX DEC Recovery Tools 

INFO COMING
 '''
 # =============================================================================
infoPAGE = '''
 
                Based on https://keys.lol
    The seeds used to generate the private keys are derived from the page number. 
    For example, on page 10, the first seed is:
    (10 - 1) * 128 + 0 = 1152
    pages contain 128 keys each, so the last seed on page 10 is:
    (10 - 1) * 128 + 127 = 1279
    This simple formula is repeated for each page, until the maximum seed of 2^256 is reached.
    
            Pages 128 Private Keys 512 Addresses per page.
            
                    Minimum  Page = 
                        1
                    Maximum Page = 
904625697166532776746648320380374280100293470930272690489102837043110636675

    This looks for Bitcoin Addresses 1 Compressed, Uncompressed, 
    Adresses startingwith 3 and Addresses starting bc1.
    
                Offline Scan for Bitcoin
!!!!!!   Best for Control Ranges Fast than Bitcoin Generator Single !!!!!
 '''
 # =============================================================================
infoMAIN = '''


                Offline Scan for Bitcoin
    This looks for Bitcoin Addresses 1 Compressed, Uncompressed, 
    Adresses startingwith 3 and Addresses starting bc1.
    
                Online Scan for Bitcoin
        This looks for Bitcoin Addresses 1 Compressed.
            Slower than the offline scan.
!!!!!!   Best for Control Ranges Online and Offline Bitcoin Generator !!!!!
 '''
 # =============================================================================
infoBRAIN = '''
                    Brainwallet Generator
A brainwallet refers to the concept of storing Bitcoins in one's own mind by memorizing a seed phrase.
If the seed is not recorded anywhere, the Bitcoins can be thought of as being held only in the mind of the owner.
If a brainwallet is forgotten or the person dies or is permanently incapacitated, the Bitcoins are lost forever. 
Using memory techniques allow them to be memorized and recalled easily.

Bitcoin brain wallet generator allows its users to key in random words/symbols
 (i.e. 4,6,8,12, or 24 words long) which is called a passphrase.
 
    ON LINE OFF LINE Brainwallet Bitcoin Hunting.

 '''
 # =============================================================================
infoWORD = '''
                Mnemonic Wallet Generator

What is mnemonic wallet?
Instead of having to deal with that long string of characters, the wallet seed phrase, 
also known as a mnemonic phrase, is made up of 12, 18, or 24 words that the wallet 
originally relies on to initially generate your private key.

            ON LINE OFF LINE Mnemonic Wallet Generator

 '''
 # =============================================================================
infoMINE = '''

!!!!!   (Out-put Display not working yet you can see it running in CMD)     !!!!!

Solo Mining in python for BTC Block Reward, Pure luck

This is a solominer random noncences between 0-4294967295 or regular noncences
starting from 0 are checked to see if you could accidently solve the mining problem
 using Python and Get BTC Block Reward, this miner requests job from solockpool and 
start hashing the block header using random noncences, or regular noncences, 
while a new block is detected on network. 
The miner restarts automatically in order to request new job from ckpool, 
if a nonce is found the blockheader data is submited to ckpool automatically.

It is based on Luck giving so much hashrate all around the world, but still possible.

The Script will store in miner.log file those hashes having more than 7 zeros in the beginning. 
Although the current difficulty for getting mining reward is 19 zeros. 
All events is stored in a file called miner.log.

You should replace the existing bitcoin adress in Bitcoinhunter with your own bitcoin address.
    
 '''
 # =============================================================================