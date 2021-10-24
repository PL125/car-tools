# coding: utf-8

# (C) Dennis Noermann 2020-2021
# This is free for all
# You are free to support me via Paypal dennis.noermann@noernet.de

####################################################
# 24 Oktober 2021 V0.3
# -- Initial commit
# -- Works for me, code is very unsorted
# -- Mor information https://forums.ross-tech.com/index.php?threads/15548/post-193146
# -- Example Command with Example Data to decode CP Data 
#     - From Eeprom Address 0x1500: 75EAA74A2644F96B4BA379F14666081B45EA0E0A
#     - With CP Key Decrypted from Flash of Source Cluster: 0x10034 8D7BA4B0923E84941C74D36B8EFAFE27
#     - With CP Key Encrypted from Flash of   Dest Cluster: 0x10034 8D7BA4B0923E84941C74D36B8EFAFE27
#
#  python3 cp_transfer1.py --EepromDecodeArgs 75EAA74A2644F96B4BA379F14666081B45EA0E0A 8D7BA4B0923E84941C74D36B8EFAFE27 8D7BA4B0923E84941C74D36B8EFAFE27
#  cp_transfer1.py V0.3 Oktober 2021
#  Decrypting ...
#  CRC Check ... CRC is OK
#  Decrypted CP Data: b'48bdcd5a1a315609a015eaa745ea0e0a'
#  For the Target encrypted CP Data: b'75eaa74a2644f96b4ba379f14666081b' + b'45ea0e0a'
####################################################

## pip3 install udsoncan
## pip3 install can-isotp

# pip3 install python-can
# pip3 install pyaes

from __future__ import print_function

#import can
import binascii
import pyaes
import codecs
from datetime import datetime
import sys
from time import sleep
from binascii import unhexlify
import struct
import os

def DecodeAndEncode(DonerCpAesEepromKey,TargetCpAesEepromKey,DonerEepromDataCp):
    ivhex=   '00000000000000000000000000000000'
    iv= codecs.decode(ivhex, 'hex')
    
    print ("Decrypting ...")
    
    aes3 = pyaes.AESModeOfOperationCBC(DonerCpAesEepromKey, iv = iv)
    EepromDataDecrypted = aes3.decrypt(DonerEepromDataCp[0:16])
    
    EepromDataDecryptedCompleete = bytearray(EepromDataDecrypted) + bytearray(DonerEepromDataCp[16:21])
    
    print ("CRC Check ... ",end="")
    
    Mycrc32 = ( binascii.crc32(EepromDataDecryptedCompleete[4:21]) % (1<<32) )
    Mycrc32Array = bytearray(Mycrc32.to_bytes(4, byteorder = 'little'))
    
    if ( (Mycrc32Array[0] == EepromDataDecryptedCompleete[0]) & (Mycrc32Array[1] == EepromDataDecryptedCompleete[1]) &  
         (Mycrc32Array[2] == EepromDataDecryptedCompleete[2]) & (Mycrc32Array[3] == EepromDataDecryptedCompleete[3]) ):
      print ("CRC is OK")
    else:
      print ("CRC NOT OK")
      #sys.exit()
    
    print("Decrypted CP Data: %s" % (str(binascii.hexlify(EepromDataDecryptedCompleete[4:21]))))
    
    aes4 = pyaes.AESModeOfOperationCBC(TargetCpAesEepromKey, iv = iv)
    encrypted4 = aes4.encrypt(codecs.decode(binascii.hexlify(EepromDataDecryptedCompleete[0:16]),'hex'))
    
    print ("For the Target encrypted CP Data: "+str(binascii.hexlify(encrypted4))+ " + " + str(binascii.hexlify(DonerEepromDataCp[16:21])) )

def DumpCpAesEepromKeyFromFlashFile(Filename):
    Flash = open(Filename, 'rb')
    FlashData = Flash.read() 
    Addr = FlashData.find(codecs.decode('00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000','hex'))
    CpAesEepromKey = FlashData[Addr+36+4:Addr+36+4+16]     
    print("%s \n\t CP Eeprom Key Found @ Addr: 0x%x Key: %s" % (Filename,Addr+36+4, str(binascii.hexlify(CpAesEepromKey)) ) )
    return CpAesEepromKey

def DumpCpAesUdsKeyFromFlashFile(Filename):
    Flash = open(Filename, 'rb')
    FlashData = Flash.read() 
    Addr = FlashData.find(codecs.decode('001540156016A016201560158016C016FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF','hex'))
    CpAesUdsKeyFlash = FlashData[Addr+36:Addr+36+16]     
    print("%s \t CP Uds Key Found @ Addr: 0x%x Key: %s" % (Filename,Addr+36, str(binascii.hexlify(CpAesUdsKeyFlash)) ) )
    return Addr+36

def FindCpAesUdsKeyRamAddr(Filename,AddrOfCpAesUdsKey):
    Flash = open(Filename, 'rb')
    FlashData = Flash.read()
    #0x3945c '5c9403'

    #for byte in AddrOfCpAesUdsKey:
    # print (hex(byte))

    #searchPattern = '0112461710002706' + str(hex(AddrOfCpAesUdsKey[0])) +str(hex(AddrOfCpAesUdsKey[1]))+ str(hex(AddrOfCpAesUdsKey[2])) + '002046100080FF'
    searchPattern = "%s%2.2x%2.2x%2.2x%s" % ('0112461710002706',AddrOfCpAesUdsKey[0],AddrOfCpAesUdsKey[1],AddrOfCpAesUdsKey[2],'002046100080FF')
    #print (searchPattern)
    Addr = FlashData.find(codecs.decode(searchPattern,'hex')) - 4
    AddrInRam = int.from_bytes(FlashData[Addr:Addr+4],byteorder='little') & 0x3FFFFFF 

    print("%s \t CP Uds Key Ram Found @ AddrInFlash: 0x%x AddrValueInRam 0x%x" % (Filename,Addr,AddrInRam ) )
    return AddrInRam

def FindImmoCanIdArray(Filename):
    Flash = open(Filename, 'rb')
    FlashData = Flash.read()
    Addr = FlashData.find(codecs.decode("D2050800F30508FF",'hex'))
    print("%s \t CAN Id's Immo Found @ AddrInFlash: 0x%x" % (Filename,Addr) )
    return

def ReadCpDataFromEeprom(Filename,Offset):
    Eeprom = open(Filename, 'rb')
    EepromData = Eeprom.read()
    print("%s \n\t CP Eeprom Data: %s Offset: %x" % (Filename, str(binascii.hexlify(EepromData[Offset:Offset+20])) ,Offset) )
    return (EepromData[Offset:Offset+20])

def FindSA2key(Filename):
    Flash = open(Filename, 'rb')
    FlashData = Flash.read()
    if FlashData[0xffc6] == 0x45 and FlashData[0xffc7] == 0x56:
     #print("OK")
     #print("SA2 Key: %s File: %s " % (str(binascii.hexlify(FlashData[0x7f84:0x7f84+75])),Filename) )
     print("SA2 Key: %s " % (str(binascii.hexlify(FlashData[0x7f84:0x7f84+75]))) )
    else:
     print("\033[31m %s \t\t\t not Tacho Flash\033[0m" % (Filename))

    return
    

def PrintUsage():
    print ("Usage:   python3 cp_transfer1.py --FromHexString  Doner-Eeprom-Key Doner-Eeprom-Data-0x1540-0x154F Doner-Eeprom-Data-0x1550-0x1553 Target-Eeprom-Key")
    print ("         All Data as Hex Strings")
    print ("Example: python3 cp_transfer1.py --FromHexString 04988F7F6C11D5C757D9BD3B285B2ACA 230098085B751E4D522F2BBFA9F75AE4 6B601A5B 5B57A2078D118A647411C48C2A248685")
    print ("")   
    print ("Usage:   python3 cp_transfer1.py --FromFiles Doner-Flash.bin Target-Flash.bin Doner-Eeprom.bin Target-Eeprom.bin")
    print ("Usage:   python3 cp_transfer1.py --DumpKeys file.bin")
    print ("Usage:   python3 cp_transfer1.py --EepromDecodeArgs 75EAA74A2644F96B4BA379F14666081B45EA0E0A 8D7BA4B0923E84941C74D36B8EFAFE27 8D7BA4B0923E84941C74D36B8EFAFE27")

    print("")
    sys.exit() 
    

print("cp_transfer1.py V0.3 Oktober 2021")

if sys.argv[1] == "--DumpSA2key":
    if os.path.isdir(sys.argv[2]):
     for root, dirs, files in os.walk(sys.argv[2]):
      for file in files:
       FindSA2key(sys.argv[2] + str(file))
    else:
       FindSA2key(sys.argv[2])
    sys.exit()



if sys.argv[1] == "--DumpCanIds":
    if os.path.isdir(sys.argv[2]):
     for root, dirs, files in os.walk(sys.argv[2]):
      for file in files:
       FindImmoCanIdArray(sys.argv[2] + str(file))
    else:
       FindImmoCanIdArray(sys.argv[2])
    sys.exit()


if sys.argv[1] == "--DumpKeys":
    if os.path.isdir(sys.argv[2]):
     for root, dirs, files in os.walk(sys.argv[2]):
      for file in files:
       addr= DumpCpAesUdsKeyFromFlashFile(str(sys.argv[2]) + str(file))
       FindCpAesUdsKeyRamAddr(sys.argv[2] + str(file),addr.to_bytes(3,byteorder = 'little') )
    else:
     addr= DumpCpAesUdsKeyFromFlashFile(sys.argv[2])    
     FindCpAesUdsKeyRamAddr(sys.argv[2],addr.to_bytes(3,byteorder = 'little') )
    sys.exit()

if sys.argv[1] == "--DecodeUdsData":
    UdsDataCp = codecs.decode(sys.argv[2], 'hex')
    UdsDataCpSwapped = bytearray(32)
    i = 31
    for byte in UdsDataCp[0:32]:
     UdsDataCpSwapped[i] = byte
     i = i - 1
     

    UdsDataCpSwappedFinal = bytes(UdsDataCpSwapped)

    ivhex=   '00000000000000000000000000000000'
    iv= codecs.decode(ivhex, 'hex')
    
    #UdsKeyFromRamhex = 'b1d2a37be34a3a7e70bf890433bfa207'
    #UdsKeyFromRam = codecs.decode(UdsKeyFromRamhex, 'hex')
    UdsKeyFromRam = codecs.decode(sys.argv[3], 'hex') 

    aes10 = pyaes.AESModeOfOperationCBC(UdsKeyFromRam, iv = iv)
    UdsDataDecrypted0 = aes10.decrypt(UdsDataCpSwappedFinal[0:16])
    UdsDataDecrypted0Invert = bytearray(16)

    i=0
    for byte in UdsDataDecrypted0:
      UdsDataDecrypted0Invert[i] = (~byte &0xFF)
      i=i+1 

    aes11 = pyaes.AESModeOfOperationCBC(UdsKeyFromRam, iv = iv)
    UdsDataDecrypted1 = aes11.decrypt(UdsDataCpSwappedFinal[16:32])


    print("UdsKeyFromRam       : %s" % (str(binascii.hexlify(UdsKeyFromRam))))
    print("UdsDataCp           : %s" % (str(binascii.hexlify(UdsDataCp))))
    print("UdsDataDecrypted0   : %s" % (str(binascii.hexlify(UdsDataDecrypted0))))
    print("UdsDataDecrypted0Inv: %s" % (str(binascii.hexlify(UdsDataDecrypted0Invert))))
    print("UdsDataDecrypted1   : %s" % (str(binascii.hexlify(UdsDataDecrypted1)))) 
    if UdsDataDecrypted0Invert == UdsDataDecrypted1:
     print ("      0..15 == ~ 16..31 ==> OK")
    else:
     print ("      Error")
    sys.exit()

if sys.argv[1] == "--EncodeUdsData":
    # arg2 = HexString of Decrypted Eeprom Data
    # arg3 = HexString UDS Aes Key from RAM 
    
    UDSByteArray = bytearray(32)

    HexBytesEepromDataDecrypted = bytes(bytearray.fromhex(sys.argv[2]))
    UdsKeyFromRam = bytes(bytearray.fromhex(sys.argv[3]))

    ivhex=   '00000000000000000000000000000000'
    iv= codecs.decode(ivhex, 'hex')
    aes10 = pyaes.AESModeOfOperationCBC(UdsKeyFromRam, iv = iv)
    DataEncrypted_15To0 = aes10.encrypt(HexBytesEepromDataDecrypted)
   
    UDSByteArray[16:32] = DataEncrypted_15To0

    HexBytesEepromDataDecryptedInv = bytearray(16)
    i=0
    for byte in HexBytesEepromDataDecrypted:
      HexBytesEepromDataDecryptedInv[i] = (~byte &0xFF)
      i=i+1 

    aes11 = pyaes.AESModeOfOperationCBC(UdsKeyFromRam, iv = iv)
    DataEncrypted_31To16 = aes11.encrypt(bytes(HexBytesEepromDataDecryptedInv))
    UDSByteArray[0:16] = DataEncrypted_31To16

    UDSByteArraySwapped = bytearray(32)
    i = 31
    for byte in UDSByteArray[0:32]:
     UDSByteArraySwapped[i] = byte
     i = i - 1

    print("DataEncrypted_15To0       : %s" % (str(binascii.hexlify(DataEncrypted_15To0))))
    print("DataEncrypted_31To16      : %s" % (str(binascii.hexlify(DataEncrypted_31To16))))
    print("32 Bytes                  : %s" % (str(binascii.hexlify(UDSByteArray))))
    print("32 Btes swapped (UDS)     : %s" % (str(binascii.hexlify(UDSByteArraySwapped))))

    sys.exit()


if sys.argv[1] == "--EepromDecodeArgs":
   # arg2 = HexStringEepromData
   # arg3 = HexStringCPKeySource
   # arg4 = HexStringCPKeyDest

   HexStringEepromData = bytes(bytearray.fromhex(sys.argv[2]))
   CpAesEepromKeySrc = bytes(bytearray.fromhex(sys.argv[3]))
   CpAesEepromKeyDest = bytes(bytearray.fromhex(sys.argv[4]))
  
   DecodeAndEncode(CpAesEepromKeySrc,CpAesEepromKeyDest,HexStringEepromData)


if sys.argv[1] == "--EepromDecode":
   # arg2 = HexString
   # arg3 = FlashDump.bin
   HexStringEepromData = bytes(bytearray.fromhex(sys.argv[2]))
   CpAesEepromKey = DumpCpAesEepromKeyFromFlashFile(sys.argv[3])
   DecodeAndEncode(CpAesEepromKey,CpAesEepromKey,HexStringEepromData)

if sys.argv[1] == "--FromFiles":
    if len(sys.argv) != 6:
        PrintUsage()
        
    DonerCpAesEepromKey = DumpCpAesEepromKeyFromFlashFile(sys.argv[2])
    TargetCpAesEepromKey = DumpCpAesEepromKeyFromFlashFile(sys.argv[3])
    print("\nUDS:")
    DonerEepromDataCp = ReadCpDataFromEeprom(sys.argv[4],0x1500)
    DecodeAndEncode(DonerCpAesEepromKey,TargetCpAesEepromKey,DonerEepromDataCp)
    print("\nACC:")
    DonerEepromDataCp = ReadCpDataFromEeprom(sys.argv[4],0x1540)
    DecodeAndEncode(DonerCpAesEepromKey,TargetCpAesEepromKey,DonerEepromDataCp)
    print("\nDM:")
    DonerEepromDataCp = ReadCpDataFromEeprom(sys.argv[4],0x1660)
    DecodeAndEncode(DonerCpAesEepromKey,TargetCpAesEepromKey,DonerEepromDataCp)

    
if sys.argv[1] == "--FromHexString":
    if len(sys.argv) != 6:
        PrintUsage()    
        
    Decode()
