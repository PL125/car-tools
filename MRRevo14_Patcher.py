# -*- coding: utf-8 -*-

# (C) Dennis Noermann 2023
# This is free for all
# You are free to support me via Paypal dennis.noermann@noernet.de


############################################################
# 29.04.2023: Created 
#
# 31.08.2023: Documentation added
############################################################

"""
What it does:

This Script does 2 things for the Bosch MRRevo14 ACC Sensors used in PQ25/PQ35 Cars Fokus is only on the PQ SW of that Bosch Radars
- Changes the Key used for SWAP Code validation to the Development Key from the 5Q0_MRR PQ26 Radar so that the SWAP Code can calculated offlince 
- Disables the Errors which normly occurs when Componenten Protection is activated cause Radar does not Match to the Car
  Meaning CP is disabled
  
History of development:

In 2020 someone started this thread in MHHAuto Forum https://mhhauto.com/Thread-How-to-read-radar-MRREVO14F
And the biggest information was directly in Post 2, were someone found the Shematics for a similar Bosch Radar on the FCC Homepage https://fccid.io/NF3-MRR1CRN/
From Shematics it was now clear what Prozessor is used and that it does have a JTAG Debug Interface.
MPC5675K from freescale, now NXP.
The used CPU from NXP does support the  "Censorship protection scheme" to prevent flash content visibility.
So even with connecting via JTAG to the CPU the potential that Bosch enabled the Censorship Feature is very hight.
So a 32 Bit password would be needed to enable JTAG debugging and flash access. ==> Dead End ..... 

Luckyly the Developers at Bosch did not enable this Feature, this was discovered sometime around End 2021 beginning of 2022 from some Polish Guys.
 B I G  C R E D I T S out to them  
Using the right Development tools from Freescale/NXP everything is possible, like creating Ram and Flash Dumps which helped a lot with reversing

Howto:
- get an JTAG Debugger and the supporting SW Tools to be able to Read/Write Flash and Ram of the MPC55xx/MPC56xx Powerpc MCU's
  One Solution is Original Freescale SW "CodeWarrior® Development Studio for MPC55xx/MPC56xx" which is available as 1 Month Evaluation Version
  And a Supported JTAG Debugger 
  - Multilink FX from https://www.pemicro.com/products/product_viewDetails.cfm?product_id=15320180&productTab=2
  - Chinease Copy Clones from the Original old frescale debugger: Just Search for "spc5 mpc 56xx 55xx freescale" on your favorite Chinease website 

- Open Radar the Jtag THT Connectors are on the RadarPCB directly accesable after the Pastic Cover is removed
  Standart RM 2,54mm pin header can be inserted, but not to deep, on the other side is the Metal casing
  Pinning is from Left to rigth GND TMS RESET TDI TDO TCK VREF JCOMP (with left is nearest to the left down corner of ACC)
  See Picture MRRevo14_Pinning.jpg
  
- Radar needs 12V and Canbus connected to your favorite Bench Setup so that you can talk to Radar via CAN
  - I use my own python Scripts with CAN UDS implementation running on raspberry pi with can header
  - Odis Engeneering or VCP should be able to send the same Data 

- Update Radar to latest 0211 FW
  
- Read Flash out
  NXP Tools do save as .s19 Format, this needs to be converted to binary  
  "objcopy --input-target=srec --output-target=binary flash.S19 flash.bin" would be the Linux command line to convert

- Patch file with this script "python3 MRRevo14_Patcher.py YourMamasAccFlash.bin"
  Console should look like this:
  -----------------------------------------------------------------
  python3 MRRevo14_Patcher.py YourMamasAccFlash.bin 
  File: YourMamasAccFlash.bin Size: 2097152
  Looks like Valid 0211 FW
  Series Key @ 0x3aa00 
  Changing Public Key
  Patching CP
  Ready YourMamasAccFlash.bin_Patched.bin is saved
  srec_cat YourMamasAccFlash.bin_Patched.bin -binary -offset 0x0 -o YourMamasAccFlash.bin_Patched.S19
  0
  ------------------------------------------------------------------
  After that you have a Patched.bin and Patched.S19, the S19 can be flashed back to ACC
  
- Newly match CP, this needed to activate the new Key used for Swap calculation, to be able to use the private key from the Leaked VW Documents for the MQB Variants of the Radar
  - Get the Actual 16 Byte IKA Key for that Radar, its stored in RAM at Address 0x31888 which is Physically mapped to Address 0x40031888 on the MPC5675K
    Power on the Radar than Start NXP Codewarier and simply Break the actual running code, than do a RAM Read and extract to file
  - With that IKA Key you can calculate the Data needed to Offlince newly Match CP of that Radar

- Calculate IKA and GFA Key for Offline CP matching
  Use cp_transfer1.py from same git repo to do it
  Fot this IKA Key: 0102030405060708090A0B0C0D0E0F Console should look like this:
  -----------------------------------------------------------------  
  python3 cp_transfer1.py --EncodeUdsData 000102030405060708090A0B0C0D0E0F 000102030405060708090A0B0C0D0E0F
  cp_transfer1.py V0.3 Oktober 2021
  DataEncrypted_15To0       : b'0a940bb5416ef045f1c39458c653ea5a'
  DataEncrypted_31To16      : b'b384eca4b39915a723f582e920854459'
  32 Bytes                  : b'b384eca4b39915a723f582e9208544590a940bb5416ef045f1c39458c653ea5a'
  32 Btes swapped (UDS)     : b'5aea53c65894c3f145f06e41b50b940a59448520e982f523a71599b3a4ec84b3'
  -----------------------------------------------------------------
  The Last line is the Data with "0B57" added at the end is needed to be written to ACC as IKA Key via UDSWriteDataByidetifier to Address 0xBE in ACC which is Address 0757 on CanBus
  I use my Python Script
  Console should look like this for IKA Key:
  -----------------------------------------------------------------
  can_send12.py -WriteCPdata 5aea53c65894c3f145f06e41b50b940a59448520e982f523a71599b3a4ec84b30B57 0x757 0xBE
  -WriteCPdata
  Device: 1879 757
  CPID: 190 be
  ReadDataByIdentifier ID: 0xf19e -0x1 bytearray(b'\xf1\x9eEV_ACCBEGVW361\x00')b'f19e45565f414343424547565733363100'
  ReadDataByIdentifier ID: 0xf1a2 -0x1 bytearray(b'\xf1\xa2001006')b'f1a2303031303036'
  ReadDataByIdentifier ID: 0xf17c -0x1 bytearray(b'\xf1|BPV-07819.11.1577171362')b'f17c4250562d30373831392e31312e31353737313731333632'
   b'03003201f4'
    repeat   Write CP Data OK
  -----------------------------------------------------------------  
  
  Write the same Key as GEFA Key to ACC its Address 0xBD

  -----------------------------------------------------------------   
  can_send12.py -WriteCPdata 5aea53c65894c3f145f06e41b50b940a59448520e982f523a71599b3a4ec84b30B57 0x757 0xBD
  -WriteCPdata
  Device: 1879 757
  CPID: 189 bd
  ReadDataByIdentifier ID: 0xf19e -0x1 bytearray(b'\xf1\x9eEV_ACCBEGVW361\x00')b'f19e45565f414343424547565733363100'
  ReadDataByIdentifier ID: 0xf1a2 -0x1 bytearray(b'\xf1\xa2001006')b'f1a2303031303036'
  ReadDataByIdentifier ID: 0xf17c -0x1 bytearray(b'\xf1|BPV-07819.11.1577171362')b'f17c4250562d30373831392e31312e31353737313731333632'
   b'03003201f4'
    repeat  
  -----------------------------------------------------------------    
  The OK is missing here thats normal, still it worked

- Powercycle the ACC
  Now the whell Known Public Key for Swap is Available, you can check in meassure Channels, it must start with "8f514a9a0f38ba40 ...."
  
- From here its the same way as with MQB Acc, use your Prefered tool to calculate the SWAP Key
  - use the PQ26 Radar type 
  - only enable one SWAP Code (more is not Supported by PQ Radar FW)
  - It must be the VIN Used that is Stored inside the ACC
    Thats the last VIN this ACC did Sucsesfully do CP matching
    It can be seen in Advaned Information
    This VIN is Used for Dataset VIN Check, too
    
  And write the SWAP Code to ACC
  My script supports Writing with python, too
  python3 can_send10.py -3QFSwap "put here the 342 Bytes output from the Calculation"

  Console looks like this
  -----------------------------------------------------------------
  python3 can_send12.py -3QFSwap verylongstringnotdisclosedbecauseihadnosamplewhichiliketosharecausetheVINisinside...............................................
  -3QFSwap
  ReadDataByIdentifier ID: 0xf187 -0x1 7N0907572C 
  ReadDataByIdentifier ID: 0xf189 -0x1 0211
  ReadDataByIdentifier ID: 0xf191 -0x1 7E0907572  
  ReadDataByIdentifier ID: 0xf197 -0x1 ACC Bosch PQx
  ReadDataByIdentifier ID: 0xf19e -0x1 EV_ACCBEGVW361
    Enter Diagnostic Session Control VW EOL
  OK Enter Diagnostic Session Control VW EOL
  UDS_SecurityAccess 0x3725 ... got Seed: 0xbf157efe ... Answer: 0xbf15b623 ... Security Access OK
  ReadDataByIdentifier ID: 0x3c01 -0x1 b'00'
   ReadDataByIdentifier ID: 0x3c01 -0x1  b'03c001020001'
   b'03c001020001'
   b'03c001020001'
   b'03c001020001'
   b'03c001020001'
    b'03c001010001'
   b'03c001010001'
   b'03c001010001'
   b'03c001010001' 
   b'03c00102ffff'
  Ready
  -----------------------------------------------------------------

"""


import os
import sys
import re
import codecs
import binascii

DevelPublicKeyHex = '8F514A9A0F38BA407DA15F3B4AC0E55FA97C8C3E7C7DED9790541C958767C91BC794723AB6C9B90349DA6B399D46C01CC60E4125037AC76BE5E99BCE66E3BE36C0ADB33CF2F197BA8FEFED150C93BFD61FC35F83BDBD40C8A94B029FB4F9E6B33EA881766629AFAE152422BD7762D915E322CC2149522AA1858D00F8EBFD05370000000000000000000000000000000000000000000000000000000000000003'
SeriesPublicKeyHex = '866d6fd1b145754f117e6cc7cce75645bfe986d71bfe183b1bec4b4c2b0f0398349a4e27cd09854d508e6ac1f566790f1f9c9723a1191c9a9d83c2f1fbfc6ea3c08180341eb3c1059aef0dc1ca0845928eaf819fa08a28b747cfffcb307ec0176a768828165538028354b5dae08239bc41c735fa88975224545db9795d95820d0000000000000000000000000000000000000000000000000000000000000003'

DevelPublicKey = codecs.decode(DevelPublicKeyHex, 'hex')
SeriesPublicKey = codecs.decode(SeriesPublicKeyHex, 'hex')

AddrPublicKey = 0x3aa00
SizePublicKey = 128

AddrCPPatch01 = 0xec023
AddrCPPatch02 = 0xec08b

# 
# objcopy --input-target=srec --output-target=binary Eeprom_orig.S19 Eeprom_orig.bin
# srec_cat flash_0211_orig_patched.bin -binary -offset 0x0 -o flash_0211_orig_patched.S19

#if sys.argv[1].endswith(".bin"):
#    print("bin")
#    
#
#if sys.argv[1].endswith(".S19"):
#    print("S19")

#sys.exit(0)

with open(sys.argv[1] , "rb") as f:
 bytes_read = f.read()
bytes_read_list = list(bytes_read) # list for later modifiying
size = len(bytes_read)
print("File: %s Size: %d" % (sys.argv[1],size))
    
pat = re.search(b'SYSB_PLUS_R19.4.1_VW_PQx_0211',bytes_read)                                    
if pat == None:
    print(" Flash does not look right! Probably it's not FW 0211 ?")
else:
    print(" Looks like Valid 0211 FW")

#print("Public Key: ",end='')
#for i in range (0,128):
# print("%2.2x" %(bytes_read[AddrPublicKey+i]),end='')
#print("")

Addr = bytes_read.find(codecs.decode(SeriesPublicKeyHex,'hex'))
print (" Series Key @ 0x%x "%(Addr))
if Addr != AddrPublicKey:
    print(" Key is at wrong position aborting")
    sys.exit(0)

# Public Key change
print (" Changing Public Key")
count=0
for byte in DevelPublicKey:
    bytes_read_list[AddrPublicKey+count] = byte
    count=count+1

# CP Off
print (" Patching CP")
if bytes_read_list[AddrCPPatch01] == 0xCE:
 bytes_read_list[AddrCPPatch01] = 0x0E
else:
 print(" Looks like it is not 0211 FW or its already patched")
    
if bytes_read_list[AddrCPPatch02] == 0xC6:
 bytes_read_list[AddrCPPatch02] = 0x06
else:
 print(" Looks like it is not 0211 FW or its already patched")


#save
out_bytes = bytes(bytes_read_list[0:size]) 
with open(sys.argv[1] + "_Patched.bin", 'wb') as f:
    f.write(out_bytes)
    
    
print (" Ready %s is saved"%(sys.argv[1] + "_Patched.bin"))    

CMD = 'srec_cat ' + sys.argv[1] + '_Patched.bin ' +'-binary -offset 0x0 -o ' + sys.argv[1] + '_Patched.S19'
print (CMD)
print (os.system(CMD))

sys.exit(0)
