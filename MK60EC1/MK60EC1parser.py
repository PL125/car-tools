# -*- coding: utf-8 -*-
"""
Created on 29.05.2022

@author: Dennis Nörmann


"""

import sys
import re
import os

def printData(filename):

    with open(filename, "rb") as f:
        bytes_read = f.read()
        
    pat = re.search(b'\x41\x42\x53\x00',bytes_read)
    #print (pat)
    addr = pat.start()
    #print ("ABS Table an Adresse: ",end='')                                    
    #print (hex(addr))
    print (filename,end="")
    print ("\t",end="")
    
    while (True):
     print ("%s 0x%8.8x 0x%6.6x " % ((bytes_read[addr:addr+3]).decode(),int.from_bytes(bytes_read[addr+4:addr+4+4],byteorder='big', signed=False),int.from_bytes(bytes_read[addr+4+4:addr+4+4+4],byteorder='big', signed=False)  ),end="" )
     addr=addr+4+4+4
     if(bytes_read[addr:addr+3]==b'\x41\x42\x53'):
       print("")
       break


print ("Filename SWModuleName AbsoluteAddress Size ....." )

if os.path.isfile(sys.argv[1]):
    filename=sys.argv[1]
    printData(filename)
else:
    for file in os.listdir(sys.argv[1]):
     if file.endswith(".bin"):
      printData(file)

