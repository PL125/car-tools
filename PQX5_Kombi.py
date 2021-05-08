# coding: utf-8

# (C) Dennis Noermann 2020-2021
# This is free for all

####################################################
# 06 April 2020
# -- Initial commit
# -- Works for me, code is very unsorted
# -- Is only working with my Test Cluster a VDD-02417.01.1719012300
# 08 April 2020
# -- CAN1 and bus1 removed
# 08 May 2021
#    Bootloader SecurityAccess SA2 algo from Bootloader added, with some SA2 Keys
#    -JumpToBootloader till SA2 should now work on most PQ Clusters
#    But Download Payload only works on some 
####################################################

# prequisites:
# raspberry pi with a 1 oder 2 Channel CAN Header for example PiCAN 2
# any socket can interface will work
# Start the Can Interface with something like this:
# ip link set can0 up type can bitrate 500000
# can0 connected to the ODB-Port is used for almost everything
#      Frame receive separation is not implemented, so only connect it allone to the ODB-Port, else it will fail
# can1 connected to Engine Can for Sniffing ACC Communication is used for one Test ...

# pip3 install udsoncan
# pip3 install can-isotp
# pip3 install python-can
# pip3 install pyaes

from __future__ import print_function

import can
import binascii
import pyaes
import codecs
from datetime import datetime
import sys
from time import sleep
import numpy as np

SendSeedRequest = [0x03,0x23,0x5A,0x3F,0x3A,0xA1,0xBD,0x01,0xEE,0xBB,0x32,0xF7,0xC9,0x88,0xB4,0xAC,0x2E,0x65,0x2F,0xB1,0xDE,0x2A,0x2B,0xFF,0xFF,0x07]

# This are the 16 lower Bytes of the AES key which 32 Bytes are stored @ adrress 0x10100 inside Cluster Flash
# Whith they key you can enable engeneering "god" mode, even without car keys .....
# There are tools that can extract this AES-KEY this code will do that too, in the future, need time to crack the last algo for this

keyhex = 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF' 

# Without this key you only can read / write the eeprom via can, right now
# write is missing in the code ...
# Everything else needs the AES-KEY !

# HOWTO:
# 1. -JumpToBootloader
# 2. -BootloaderReadEeprom
# 3. -ExitBl

key = codecs.decode(keyhex, 'hex')

def SplitToBytes(integer):
    return divmod(integer, 0x100)

def FillUpCanFrame(WorkingFrame):
    DataToFill = 8 - len(WorkingFrame)
    while DataToFill > 0: # Fill up to Full 8 Byte Can Frame with 0xAA
       DataToFill = DataToFill - 1
       WorkingFrame = WorkingFrame + [0xAA]
    return WorkingFrame

def UDS_Boot_ExitBl(bus,CanID):
        WorkingFrame = [0x55,0xAA,0x01,0x0C,0x11,0x22,0x33,0x03]

        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)
        recv_message = bus.recv(2.0) # 2 s Timeout   

def TachoReset(bus,CanID):
        msg = can.Message(arbitration_id=CanID,data=[0x02, 0x10, 0x60, 0xAA, 0xAA, 0xAA,0xAA,0xAA],is_extended_id=False)
        bus.send(msg)
        recv_message = bus.recv(2.0) # 2 s Timeout
        #print (recv_message)    

def UDS_ReceiveDecodeAndRemovePadding(SeedVomTacho):
        CountFrames=int(len(SeedVomTacho)/8)
        CountFrameTmp=CountFrames
        #print ("Frames: " + str(CountFrames))

        while CountFrames > 1: # Erste Byte der Frames x bis 2 löschen
         ByteToDel=((CountFrames-1)*8)
         #print("Byte Del Nr: " + str(ByteToDel))
         del SeedVomTacho[ByteToDel]
         CountFrames = CountFrames -1

        if CountFrameTmp == 1:
         UDSSize = SeedVomTacho[0]
         del SeedVomTacho[0:2] # die ersten 2 Bytes des ersten Frames löschen
        else:
         UDSSize = SeedVomTacho[1]
         del SeedVomTacho[0:3] # die ersten 3 Bytes des ersten Frames löschen

        return SeedVomTacho[0:UDSSize-1]

def UDS_DiagnosticSessionControl(bus,CanID):
        WorkingFrame = [0x02,0x10,0x03]
        WorkingFrame = FillUpCanFrame(WorkingFrame)
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)
        recv_message = bus.recv(2.0) # 2 s Timeout
        print (recv_message.data)        

def UDS_DiagnosticSessionControl(bus,CanID,diagnosticSessionType):
        # 0x01 Default Session
        # 0x02 Programming session
        # 0x03 Extended diagnostic session
        # 0x60 ???
        WorkingFrame = [0x02,0x10,diagnosticSessionType]
        WorkingFrame = FillUpCanFrame(WorkingFrame)
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)        
        print (str( codecs.encode( bytearray(UDS_Receive(bus,CanID)) ,'hex')) )
            
        #for receive_counter in range (0,10): # 10 frames empfangen
        #    recv_message = bus.recv(0.01) # 0.2 s Timeout
        #    if recv_message != None:
        #        if recv_message.data[1] == 0x7F and recv_message.data[2] == 0x10:
        #            #print("ID 0x%3.3x " % (CanID),end='')
        #            print ("error: diagnosticSessionType: 0x%x " % (diagnosticSessionType),end='')
        #            print (str( codecs.encode( bytearray(recv_message.data) ,'hex')) ) 
        #            break    


def UDS_RoutineControl(bus,CanID):
        # 0x01 Default Session
        # 0x02 Programming session
        # 0x03 Extended diagnostic session
        # 0x60 ???
        WorkingFrame = [0x04,0x31,0x01,0x02,0x03]
        WorkingFrame = FillUpCanFrame(WorkingFrame)
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)        
        for receive_counter in range (0,10): # 10 frames empfangen
            recv_message = bus.recv(0.01) # 0.2 s Timeout
            if recv_message != None:
                if recv_message.data[1] == 0x7F and recv_message.data[2] == 0x10:
                    #print("ID 0x%3.3x " % (CanID),end='')
                    print ("error: diagnosticSessionType: 0x%x " % (diagnosticSessionType),end='')
                    print (str( codecs.encode( bytearray(recv_message.data) ,'hex')) ) 
                    break    

def UDS_SecurityAccess_SA2(bus,CanID):
        
        SA2_ARRAY = [
                    ['814a246807814a0d87371ab7aa8184a2a371e84a0a879567b455931a38d24749932849ac5d4a1e681293057cd35e4a0d939135faac8703f941784a0781879ade3580814981877d9ab4674c' , '',''],
                    ['814a24680d814a0d8753040384818476cd4b4e4a0a874973b5f193bd4ebe4d4993d39e4afb4a1e681193b05da7404a0d93a47d9fab87534586ea4a07818740a3111f8149818735db54ec4c' , '',''],
                    ['814a24680d814a0d87653040388184f76cd4b44a0a8724973b5f93ebd4ebe44993cd39e4af4a1e6811931b05da744a0d93ca47d9fa87b534586e4a078187040a311181498187d35db54e4c' , '',''],
                    ['814a24680d814a0d879653040381845f76cd4b4a0a87024973b5935ebd4ebe49930cd39e4a4a1e68119351b05da74a0d87fb53458693bca47d9f4a0781872040a31181498187fd35db544c' , '',''],
                    ['814a24680f814a0d87063bc8068184a2a371e84a0a878f44926c931a38d24749932849ac5d4a1e68089303f6459a4a0d939135faac8703f941784a07818757ad9e238149818736e40b3c4c' , '',''],
                    ['814a246812814a0d872fb67a9c8184356584534a0a8720142bcd93bfb83250499353acefd24a1e680b93dae7823c4a0d873dcee87393489045324a0781870d68a42b81498187a16532cd4c' , '7E0920970S', 'SW1104'],
                    ['814a246812814a0d87fb67a9c18184565845324a0a870142bcd193fb83250a49933acefd244a1e680b93ae7823cc4a0d938904532287dcee87324a078187d68a42bf8149818716532cd94c' , '','' ],
                    ['814a246817814a0d87a312d9e9819339c72acf4a0a87ed9b72a784fad16b7a49932c88d9c84a1e680a93a2acad914a0d841d0796ef87c1a2f9e44a07818730a83c2e81498187bec2dee54c' , '7E0920880J', 'SW0509'],
                    ['814a246817814a0d87a8312d9e81933e9c72ac4a0a87e6d9b72a84f9ad16b7499327c88d9c4a1e680a93a02acad94a0d841ed0796e87c31a2f9e4a0781873d0a83c281498187b4ec2dee4c' , '',''],
                    ['814a246817814a0d87aa312d9e8193039c72ac4a0a878ed9b72a84bfad16b749932c88d9c84a1e680a932a2acad94a0d875c1a2f9e8401d0796e4a078187f30a83c2814981876bec2dee4c' , '7E0920880S 7E0920882A 5N0920883H 1K8920885L 7N0920880N 7N5920880J','SW1008 SW1018 SW1104 SW1109 SW2030 SW4030'],                                    
                    ]
        
        print("SA2 Array Key Count: %d"%(len(SA2_ARRAY)))

        SA2_Key_Counter=0
        while SA2_Key_Counter<len(SA2_ARRAY):
            SA2_HEX = SA2_ARRAY[SA2_Key_Counter][0]
            print("\nUsing SA2 Key[%d %s %s]: %s\n"%(SA2_Key_Counter,SA2_ARRAY[SA2_Key_Counter][1],SA2_ARRAY[SA2_Key_Counter][2],SA2_HEX))
            SA2_Key_Counter=SA2_Key_Counter+1
            SA2 = codecs.decode(SA2_HEX, 'hex')           
    
            WorkingFrame = [0x02,0x27,0x11]
            WorkingFrame = FillUpCanFrame(WorkingFrame)
            msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
            bus.send(msg)        
            for receive_counter in range (0,10): # 10 frames empfangen
                recv_message = bus.recv(0.01) # 0.2 s Timeout
                if recv_message != None:
                    if recv_message.data[0] == 0x02 and recv_message.data[1] == 0x7E:
                        #print("ID 0x%3.3x " % (CanID),end='')
                        #print (recv_message)
                        print (str( codecs.encode( bytearray(recv_message.data) ,'hex')) )
                        break
                    #print (str( codecs.encode( bytearray(recv_message.data) ,'hex')) )
                    SeedVal64 = int.from_bytes(bytearray(recv_message.data)[3:7], byteorder='big', signed=False)
                    
            SeedVal = np.int32(SeedVal64)
            print ("SeedVal: 0x%x" % (SeedVal))

            SeedValAnswer = Tacho_SA2_Seed_Calc(SeedVal,SA2)      
            print ("SeedValAnswer: 0x%x" % (SeedValAnswer))
    
            SeedValAnswerByteArr =  int(SeedValAnswer).to_bytes(4, byteorder='big') 
  
            WorkingFrame = [0x06,0x27,0x12] + list(SeedValAnswerByteArr)
            WorkingFrame = FillUpCanFrame(WorkingFrame)
            msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
            bus.send(msg)          
            for receive_counter in range (0,10): # 10 frames empfangen
                recv_message = bus.recv(0.01) # 0.2 s Timeout
                if recv_message != None:
                    if recv_message.data[0] == 0x03 and recv_message.data[1] == 0x7F:
                        print ("Bl Seed Security Access Error")
                        #print (str( codecs.encode( bytearray(recv_message.data) ,'hex')) )
                        break
                    if recv_message.data[0] == 0x02 and recv_message.data[1] == 0x67 and recv_message.data[2] == 0x12:
                        print ("Bl Seed Security Access OK")
                        return
                        #break
        print("\n\nNo SA2 Key matched :( Exit \n\n")
        sys.exit(1)

def Tacho_SA2_Seed_Calc(SeedVal,SA2,Debug=False):
    # 2021.05.08 Implemented from Bootloader Dissassembly, thanks to daku for his input
    r10 = 0
    r25 = 0
    r26 = 0
    r27 = 0
    r28 = SeedVal
    PC = 0
    
    if Debug: print ("SeedVal: 0x%8.8x"%(r28))    
     
    while PC < len(SA2):
        if SA2[PC] == 0x81:
            if Debug: print ("SA2: PC=0x%2.2x Command: RSL (0x%2.2x)"%(PC,SA2[PC]))
            r27 = r28
            r27 = np.uint32(r27>>0x1F)
            r28 = np.uint32(r28<<0x01)
            if r27!=0:
                r28=r28|1
            
            PC=PC+1
            if Debug: print ("                                         r28: 0x%8.8x r27: 0x%8.8x r26: 0x%8.8x r25: 0x%8.8x r10: 0x%8.8x PC: 0x%8.8x"%(r28,r27,r26,r25,r10,PC))            
            
        elif SA2[PC] == 0x82:
            print ("TEST missing !!!")
            print ("SA2: PC=0x%2.2x Command: RSR (0x%2.2x)"%(PC,SA2[PC]))
            r27=r28+1
            r28 = np.uint32(r28>>0x01)            
            if r27!=0:
                r28=r28|0x80000000            
            PC=PC+1
        
        elif SA2[PC] == 0x84:
            if Debug: print ("SA2: PC=0x%2.2x Command: SUB (0x%2.2x)"%(PC,SA2[PC]))
            r10 = np.uint32( ((np.uint32(SA2[PC+1]))<<24) + (np.uint32((SA2[PC+2]))<<16) + (np.uint32((SA2[PC+3]))<<8) + (np.uint32((SA2[PC+4]))<<0) )
            
            if r10 < r28:
                r27 = 0
            else:
                r27 = 1
            
            r28 = np.uint32(r28 - r10)              
            
            PC=PC+5
            if Debug: print ("                                         r28: 0x%8.8x r27: 0x%8.8x r26: 0x%8.8x r25: 0x%8.8x r10: 0x%8.8x PC: 0x%8.8x"%(r28,r27,r26,r25,r10,PC))     
            

        elif SA2[PC] == 0x87:
            if Debug: print ("SA2: PC=0x%2.2x Command: XOR (0x%2.2x)"%(PC,SA2[PC]))
            r10 = np.uint32( ((np.uint32(SA2[PC+1]))<<24) + (np.uint32((SA2[PC+2]))<<16) + (np.uint32((SA2[PC+3]))<<8) + (np.uint32((SA2[PC+4]))<<0) )
            r27 = 0
            r28 = np.uint32(r10) ^ np.uint32(r28)
                    
            PC=PC+5        
            if Debug: print ("                                         r28: 0x%8.8x r27: 0x%8.8x r26: 0x%8.8x r25: 0x%8.8x r10: 0x%8.8x PC: 0x%8.8x"%(r28,r27,r26,r25,r10,PC))
 
        elif SA2[PC] == 0x49:
            if Debug: print ("SA2: PC=0x%2.2x Command: NEXT (0x%2.2x)"%(PC,SA2[PC]))
            PC=PC+1
            r26=r26-1
            if r26 != 0:
                PC=r25
 
        elif SA2[PC] == 0x4A:
            if Debug: print ("SA2: PC=0x%2.2x Command: BCC (0x%2.2x)"%(PC,SA2[PC]))
            r12 = SA2[PC+1]
            PC=PC+2
            if r27==0:
             PC=PC+r12
                     
        elif SA2[PC] == 0x68:
            if Debug: print ("SA2: PC=0x%2.2x Command: LOOP (0x%2.2x)"%(PC,SA2[PC]))
            r26 = SA2[PC+1]
            PC=PC+2
            r25=PC
       
        elif SA2[PC] == 0x93:
            if Debug: print ("SA2: PC=0x%2.2x Command: ADD (0x%2.2x)"%(PC,SA2[PC]))
            #print ("0x%8.8x"%( (np.uint32(SA2[PC+1]))<<24) )
            r10 = np.uint32( ((np.uint32(SA2[PC+1]))<<24) + (np.uint32((SA2[PC+2]))<<16) + (np.uint32((SA2[PC+3]))<<8) + (np.uint32((SA2[PC+4]))<<0) )            
            #r28= np.uint32( np.uint32(r28) + np.uint32(r10) ) # 32 bit aber numpi overflow error, ja ich weiss
            #r28= np.uint32( r28 + r10 ) # 32 bit aber numpi overflow error, ja ich weiss
            r28 = np.uint32(np.uint64(r28) + r10)  # 32 Bit ! dan halt so
            if r10 < r28:
                r27 = 0
            else:
                r27 = 1
            
            PC=PC+5
            if Debug: print ("                                         r28: 0x%8.8x r27: 0x%8.8x r26: 0x%8.8x r25: 0x%8.8x r10: 0x%8.8x PC: 0x%8.8x"%(r28,r27,r26,r25,r10,PC))
            
        else:
            if Debug: print ("SA2: PC=0x%2.2x Command: DONE (0x%2.2x)"%(PC,SA2[PC]))
            if Debug: print ("                                         r28: 0x%8.8x r27: 0x%8.8x r26: 0x%8.8x r25: 0x%8.8x r10: 0x%8.8x PC: 0x%8.8x"%(r28,r27,r26,r25,r10,PC))
            SeedVal=r28
            break 
    
    return SeedVal


def BLSeed2(SeedVal64):
                
                LookupArr1 =  [0x220B8BE7, 0xCA392FF8, 0xC1B02F0E, 0xD43C6CB3, 0x2D2500C7, 0x24537F70, 0x92DE086A, 0x9775DEAE, 
                               0x0F3541D5, 0x799A6042, 0x27C51066, 0xCF49F556, 0x068AAFE6, 0x05723330, 0xF2DDDC7C, 0x9DFEC0AA]
                eax_array =   [0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000]
                eax_array_ptr = 0
                
                esp_array =   [0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                               0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000]
                
                
                EDX=0x00000000
                
                
                #SeedVal64=0x1DBC61FB #Answer64=0xA0A0CAEC
                #SeedVal64=0x1B4C5F8A #Answer64=0xD80A247F
                ebx_10=SeedVal64+0x0B2B2B2B2
                
                print ("ebx_10: 0x%x type: %s" % (ebx_10,type(ebx_10))) 
                
                edx=0x1C
                
                for esi in range(0,6):
                    print("loop run: %d\n" % (esi))
                    
                    Work = ebx_10 >> edx
                    print ("SeedVal: 0x%x type: %s" % (Work,type(Work)))
                    Work = Work & 0x0F
                    print ("SeedVal: 0x%x type: %s" % (Work,type(Work)))
                    ebx_0 = LookupArr1[Work] # kein *4 weil aarray 4 byte groß ist
                    print ("ebx_0: 0x%x" % (ebx_0))
                    
                    edi = edx
                    edi = edi & 0xFF
                    ecx = edi
                    ecx = ecx - 4
                    
                    Work = ebx_10 >> ecx
                    ebx_4 = Work & 0x0F
                    print ("EBX[+4]: 0x%x" % (ebx_4))
                    
                    ecx = ecx - 4
                    Work = ebx_10 >> ecx
                    ebx_8 = Work & 0x0F                    
                    print ("EBX[+8]: 0x%x" % (ebx_8))
                    
                    Work =  ebx_0 >> ebx_4
                    print ("Work: 0x%x 0x%x" % (Work,ebx_4))
                    Work = (Work * ebx_8) & 0xFFFFFFFF # 32 Bit !
                    print ("Work: 0x%x 0x%x" % (Work,ebx_8))
                    Work = (Work + ebx_0) & 0xFFFFFFFF # 32 Bit !
                    print ("ebx_c: 0x%x 0x%x" % (Work,ebx_8))
                    ebx_c = Work
                    
                    ebx_10 = (ebx_10 + ebx_c) & 0xFFFFFFFF # 32 Bit !
                    print ("ebx_10: 0x%x" % (ebx_10))
                    
                    eax_array[eax_array_ptr] = ebx_10 
                    
                    edx = edx - (2+2) # "edx" identisch  zu "dl"
                    print ("edx bzw. dl = 0x%x" %(edx))
                
                    eax_array_ptr = eax_array_ptr + 1
                    
                print ("End Loop\n")    
                for element in eax_array:
                    print ("0x%8.8x"%(element))
                    
                Work = ebx_10 & 0xFF
                Work = Work  >> 4
                print ("Work: 0x%x" % (Work))
                ebx_0 = LookupArr1[Work] # kein *4 weil aarray 4 byte groß ist
                print ("ebx_0: 0x%x" % (ebx_0))                

                ebx_8 = ebx_10  >> 0x1C
                print ("ebx_8: 0x%x" % (ebx_8))

                ebx_4 = ebx_10 & 0x0F
                print ("ebx_4: 0x%x" % (ebx_4))
                
                Work = ebx_0 >> ebx_4
                Work = (Work * ebx_8) & 0xFFFFFFFF # 32 Bit !
                ebx_c = (Work + ebx_0) & 0xFFFFFFFF # 32 Bit !
                print ("ebx_c: 0x%x" % (ebx_c))
                
                ebx_10 = (ebx_10 + ebx_c) & 0xFFFFFFFF # 32 Bit !
                print ("ebx_10: 0x%x" % (ebx_10))
                
                esp_array[int(0x14/4)] = ebx_10
                
                Work = ebx_10 & 0x0F
                ebx_0 = LookupArr1[Work] # kein *4 weil aarray 4 byte groß ist
                print ("ebx_0: 0x%x" % (ebx_0))
                
                ebx_8 = ebx_10  >> 0x1C
                print ("ebx_8: 0x%x" % (ebx_8))
                
                ebx_4 = (ebx_10 >> 0x18) & 0x0F
                print ("ebx_4: 0x%x" % (ebx_4))
                
                Work = ebx_0 >> ebx_8
                print ("Work: 0x%x" % (Work))
                Work = (Work * ebx_4) & 0xFFFFFFFF # 32 Bit !
                ebx_c = (Work+ebx_0) & 0xFFFFFFFF # 32 Bit !
                print ("ebx_c: 0x%x" % (ebx_c))
                              
                Work = (eax_array[0] + eax_array[1]) ^ eax_array[2]
                Work = (Work + eax_array[3]) ^ eax_array[4] 
                Work = (Work + eax_array[5]) & 0xFFFFFFFF # 32 Bit !
                
                Work = Work ^ ebx_10
                Work = (Work + ebx_c) & 0xFFFFFFFF # 32 Bit !
                print ("Work: 0x%x" % (Work))
                Work = (Work + ebx_10) & 0xFFFFFFFF # 32 Bit !
                print ("Work: 0x%x" % (Work))
                
                Work_edx = 0x25478B3F >> 0x10
                print ("Work_edx: 0x%x" % (Work_edx))
                Work_edx = Work_edx + 0x00 # var_44
                
                Work_ecx = 0x25478B3F & 0x0FFFF
                print ("Work_ecx: 0x%x" % (Work_ecx))
                
                Work_edx = (Work_edx * Work_ecx) & 0xFFFFFFFF # 32 Bit !
                print ("Work_edx: 0x%x" % (Work_edx))
                
                Work = Work ^ Work_edx
                print ("SeedAnswer: 0x%8.8x" % (Work))
                return Work

def UDS_SecurityAccess2(bus,CanID):
        WorkingFrame = [0x27,0x01,0x00,0x00,0x00,0x00,0x00,0x00]
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)        
        recv_message = bus.recv(0.01) # 0.2 s Timeout
        if recv_message != None:
            print (str( codecs.encode( bytearray(recv_message.data) ,'hex')) )
        
        SeedVal64 = (recv_message.data[2] << 24) + (recv_message.data[3] << 16) + (recv_message.data[4] << 8) + recv_message.data[5]
        print("BlSeed2Val: 0x%8.8x" %(SeedVal64))
        SeedAnswer = BLSeed2(SeedVal64)
        print("BlSeed2Answer: 0x%8.8x" %(SeedAnswer))

        SeedAnswer = 1234 # test falsche antwort 01.04.2021
        
        WorkingFrame = [0x27,0x02,(SeedAnswer&0xFF000000)>>24,(SeedAnswer&0xFF0000)>>16,(SeedAnswer&0xFF00)>>8,(SeedAnswer&0xFF),0x00,0x00]
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)        
        recv_message = bus.recv(0.01) # 0.2 s Timeout
        if recv_message != None:
            print (str( codecs.encode( bytearray(recv_message.data) ,'hex')) )        

def UDS_TesterPresent(bus,CanID):
        WorkingFrame = [0x02,0x3E,0x00]
        WorkingFrame = FillUpCanFrame(WorkingFrame)
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)
        for receive_counter in range (0,10): # 10 frames empfangen
            recv_message = bus.recv(0.01) # 0.2 s Timeout
            if recv_message != None:
                if recv_message.data[0] == 0x02 and recv_message.data[1] == 0x7E:
                    #print("ID 0x%3.3x " % (CanID),end='')
                    #print (recv_message)
                    break

def UDS_Receive(bus,CanID,buf=" "):
        SingleFrame = False
        recv_message = bus.recv(2.0) # 2 s Timeout
        if recv_message == None:
                return ["Timeout"]
        #print (str(binascii.hexlify(recv_message.data)))
        
        #check for UDS 0x78 requestCorrectlyReceived-ResponsePending 
        if     recv_message.data[0] & 0b11110000 == 0x00 \
           and recv_message.data[1] == 0x7F  \
           and recv_message.data[3] == 0x78:
               #print ("requestCorrectlyReceived-ResponsePending retry recv ...")
               print (" repeat ",end='')
               recv_message = bus.recv(2.0) # 2 s Timeout
               if recv_message == None:
                      print("UDS_Receive requestCorrectlyReceived-ResponsePending retry recv ... Timeout")
                      return ["UDS_Receive requestCorrectlyReceived-ResponsePending retry recv ... Timeout"]               

        
        if recv_message.data[0] == 0x10:    #(FF) First Frame
         SizeDataToReveive = recv_message.data[1]
         UDS_SID = recv_message.data[2]

        if (recv_message.data[0] & 0b11110000) == 0x0: #(SF) Single Frame
         SingleFrame = True
         SizeDataToReveive = recv_message.data[0]
         #SizeDataToReveive = SizeDataToReveive - 7 # max 7 sind im ersten Frame drinn
         UDS_SID = recv_message.data[1]

        #if recv_message.data[0] & 0b11110000 == 0x20: #(CF) Consecutive Frame

        #print ("DataSize= 0x%4.4x " % (SizeDataToReveive),end='')
        #print (" UDS_SID= 0x%2.2x " % (UDS_SID),end='')
        DataReceived = recv_message.data

        if UDS_SID == 0x7F: #Error, nur 1 Frame
            #if recv_message.data[3] != 0x31:
            print(buf + "ServiceIdRQ 0x%2.2x ErrorCode NRC 0x%2.2x" % (recv_message.data[2],recv_message.data[3]),end='\n')
            return []
        
        
        print (buf,end='')
        
        #ACK
        msg = can.Message(arbitration_id=CanID,data=[0x30, 0x10, 0x00, 0x00, 0x00, 0x00,0x00,0x00],is_extended_id=False)
        bus.send(msg)

        if SingleFrame == True:
         #sigle antwort
         #print("Single Antwort")
         pass

        else:
         SizeDataToReveive = SizeDataToReveive - 6 # 6 sind im ersten Frame drinn
         #multiple antwort frames
         while (SizeDataToReveive > 0):
          recv_message = bus.recv(2.0) # 2 s Timeout
          #print (recv_message)
          #print (str(binascii.hexlify(recv_message.data)))
          DataReceived = DataReceived + recv_message.data
          SizeDataToReveive = SizeDataToReveive - 7

        return UDS_ReceiveDecodeAndRemovePadding(DataReceived)

def UDS_ReadDataByIdentifier(bus,CanID,Identifier,Counter=-1):
          buf = ("ReadDataByIdentifier ID: " + str(hex(Identifier)) +" "+ str(hex(Counter))+ " ")
          IdentifierHighByte,IdentifierLowByte = SplitToBytes(Identifier)
          WorkingFrame = [0x03,0x22,IdentifierHighByte,IdentifierLowByte]
          if Counter != -1:
           WorkingFrame[0] = 0x04
           WorkingFrame =  WorkingFrame + [Counter]  
           
          WorkingFrame = FillUpCanFrame(WorkingFrame)

          msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
          bus.send(msg)
          return UDS_Receive(bus,CanID,buf)
      
def UDS_RequestDownload(bus,CanID,DataPayload):
        FrameNr=0
        DataToSendPtr=0
        DataSize = len(DataPayload)
        print("UDS_RequestDownload DataPayload Size: " + hex(DataSize))        
        #WorkingFrame = [0x10,0x0B,0x34,0x01,0x44,0x03,0xFF,0x19]
        WorkingFrame = [0x10,DataSize+1,0x34] + DataPayload[DataToSendPtr:DataToSendPtr+5]
        DataToSendPtr=DataToSendPtr+5 # 5 Bytes gesendet
        
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)
        recv_message = bus.recv(2.0) # 2 s Timeout        
        FrameNr=FrameNr+1
        #WorkingFrame = [0x20+FrameNr,0x00 ,0x00 ,0x00 ,0x06 ,0x00] 
        WorkingFrame = [0x20+FrameNr] +  DataPayload[DataToSendPtr:DataToSendPtr+5]
        
        WorkingFrame = FillUpCanFrame(WorkingFrame)
   
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)  
        recv_message = bus.recv(2.0) # 2 s Timeout            

def UDS_TransferData(bus,CanID,DataPayload):
        WorkingFrame = []
        DataSize = len(DataPayload)
        print("UDS_TransferData DataPayload Size: " + hex(DataSize))
        
        if DataSize>0x70:
            DataPosEndThisBlock = 0x20
            DataSizeThisBlock = 0x20
        else:
            DataPosEndThisBlock = DataSize
            DataSizeThisBlock = DataSize
            
        BlockNumber=1       
        DataToSendPtr=0

        while (DataToSendPtr < DataSize):

            FrameNr=0
            WorkingFrame = [0x10,DataSizeThisBlock+2,0x36,BlockNumber] + DataPayload[DataToSendPtr:DataToSendPtr+4]
            DataToSendPtr=DataToSendPtr+4 # 4 Bytes gesendet
            msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
            bus.send(msg)
            recv_message = bus.recv(2.0) # 2 s Timeout
            
            while(DataToSendPtr < DataPosEndThisBlock):
               FrameNr=FrameNr+1
               #print("Sending Multiple Frames: ConsecutiveFrame (CF) Frame: " + str(FrameNr))
               WorkingFrame = [0x20+FrameNr] + DataPayload[DataToSendPtr:DataToSendPtr+7]
               WorkingFrame = FillUpCanFrame(WorkingFrame)
               DataToSendPtr=DataToSendPtr+7 # 7 Bytes gesendet
               msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
               bus.send(msg)  
               
            UDS_Receive(bus,CanID)
               
            DataPosEndThisBlock = DataPosEndThisBlock + 0x20
            BlockNumber = BlockNumber+1

def UDS_TransferExit(bus,CanID):
        WorkingFrame = [0x01,0x37]
        WorkingFrame = FillUpCanFrame(WorkingFrame)
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)
        recv_message = bus.recv(2.0) # 2 s Timeout        

def UDS_RoutineControl2(bus,CanID,Ctrltype,CtrlPayload):
    # Ctrltype
    #  0x01 Start
    #  0x02 Stop
    #  0x03 RequestResult
    DataSize = len(CtrlPayload)
    print("CtrlPayload Size: " + hex(DataSize))
    DataToSendPtr=0
    FrameNr=0
    
    WorkingFrame = [0x10,DataSize+2,0x31,Ctrltype] + CtrlPayload[DataToSendPtr:DataToSendPtr+4] #,0x02, 0x02, 0x04, 0x03] # 0x8b Size = 6 Byte im ersten frame + 0x13 7 byte Frames
    DataToSendPtr=DataToSendPtr+4 # 4 Bytes gesendet
    msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
    bus.send(msg)
    recv_message = bus.recv(2.0) # 2 s Timeout    
    while(DataToSendPtr < DataSize):
       if FrameNr<0xF:
           FrameNr=FrameNr+1
       else:
           FrameNr=0
       
       #print("Sending Multiple Frames: ConsecutiveFrame (CF) Frame: " + str(FrameNr))
       WorkingFrame = [0x20+FrameNr] + CtrlPayload[DataToSendPtr:DataToSendPtr+7]
       DataToSendPtr=DataToSendPtr+7 # 7 Bytes gesendet
       msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
       bus.send(msg)  
       if FrameNr==0xF:
           recv_message = bus.recv(2.0) # 2 s Timeout
           #sleep(1)
       
    UDS_Receive(bus,CanID)    
    

def UDS_WriteDataByIdentifier(bus,CanID,Identifier,DataList):
        WorkingFrame = []
        #print(CanID)
        #print(Identifier)
        #print(DataList)
        #for BYTE in DataList:
        # print (format(BYTE,'02x'),end = '')
        #print("")

        DataSize = len(DataList)
        #print("Size Data: " + str(DataSize));

        IdentifierHighByte,IdentifierLowByte = SplitToBytes(Identifier)

        if DataSize > 4: # mehr als 4 bytes ==> mehr als 1 Frame
          #print("Sending Multiple Frames: FirstFrame (FF)")
          FrameNr=0
          DataToSendPtr=0
          #TODO Mehr als 0xFF Bytes
          WorkingFrame = [0x10,DataSize+3,0x2E,IdentifierHighByte,IdentifierLowByte] + DataList[DataToSendPtr:DataToSendPtr+3]
          DataToSendPtr=DataToSendPtr+3 # 3 Bytes gesendet
          msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
          bus.send(msg)
          recv_message = bus.recv(2.0) # 2 s Timeout
          #print (recv_message)

          while(DataToSendPtr < DataSize):
           FrameNr=FrameNr+1
           #print("Sending Multiple Frames: ConsecutiveFrame (CF) Frame: " + str(FrameNr))
           WorkingFrame = [0x20+FrameNr] + DataList[DataToSendPtr:DataToSendPtr+7]
           DataToSendPtr=DataToSendPtr+7 # 7 Bytes gesendet
           if len(WorkingFrame) < 8: 
            WorkingFrame = FillUpCanFrame(WorkingFrame)

           msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
           bus.send(msg)


        else: # Single Frame (CS)
          #print("Sending Single Frame (CS)")
          WorkingFrame = [DataSize+3,0x2E,IdentifierHighByte,IdentifierLowByte] + DataList
          WorkingFrame = FillUpCanFrame(WorkingFrame)

          msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
          bus.send(msg)
          recv_message = bus.recv(2.0) # 2 s Timeout
          #print (recv_message)
          return recv_message

        #Message Send, receive Answer
        return UDS_Receive(bus,CanID)

def WriteCPData(bus,CPData,CPDatum):
        #TmpData = UDS_ReadDataByIdentifier(bus,0x714,0xF19E)
        #del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg
        #print(TmpData)

        #TmpData = UDS_ReadDataByIdentifier(bus,0x714,0xF1A2)
        #del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg
        #print(TmpData)

        UDS_DiagnosticSessionControl(bus,0x714)
        
        #UDS_WriteDataByIdentifier(bus,0x714,0xF198,[0x00,0x00,0x00,0x00,0x00,0x2E])
                
        #UDS_WriteDataByIdentifier(bus,0x714,0xF199,CPDatum)

        recv_message = UDS_WriteDataByIdentifier(bus,0x714,0x00BE,CPData)
        if len(recv_message) != 0x00:
         if recv_message[0] == 0x00 and recv_message[1] == 0xbe:
            print(" Write CP Data OK")
        else:
         print(" Write CP Data Error")
            
        #TmpData = recv_message
        #print(TmpData,end='')
        #print( str( codecs.encode( bytearray(TmpData) ,'hex') ) )    

def UDS_ReadMemoryByAddress(bus,CanID,Addr3,Addr2,Addr,Size):
        AddrHi,AddrLo = SplitToBytes(Addr)
        WorkingFrame = [0x07,0x23,0x14,Addr3,Addr2,AddrHi,AddrLo,Size]
        WorkingFrame = FillUpCanFrame(WorkingFrame)
        msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        bus.send(msg)
        return UDS_Receive(bus,CanID)
    
def UDS_WriteMemoryByAddress(bus,CanID,Addr3,Addr2,Addr,DataList):
        #AddrHi,AddrLo = SplitToBytes(Addr)
        #WorkingFrame = [0x07,0x3D,0x14,Addr3,Addr2,AddrHi,AddrLo,DataList[0]]
        #WorkingFrame = FillUpCanFrame(WorkingFrame)
        #msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
        #bus.send(msg)    
        #return UDS_Receive(bus,CanID)  
        WorkingFrame = []

        DataSize = len(DataList)

        AddrHi,AddrLo = SplitToBytes(Addr)

        if DataSize > 0: # mehr als 0 bytes ==> mehr als 1 Frame :)
          #print("Sending Multiple Frames: FirstFrame (FF)")
          FrameNr=0
          DataToSendPtr=0
          #TODO Mehr als 0xFF Bytes
          WorkingFrame = [0x10,DataSize+7,0x3D,0x14,Addr3,Addr2,AddrHi,AddrLo]
          #DataToSendPtr=DataToSendPtr+0 # 0 Bytes gesendet
          msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
          bus.send(msg)
          recv_message = bus.recv(2.0) # 2 s Timeout
          #print (recv_message)

          while(DataToSendPtr < DataSize):
           FrameNr=FrameNr+1
           #print("Sending Multiple Frames: ConsecutiveFrame (CF) Frame: " + str(FrameNr))
           if FrameNr == 1:
            WorkingFrame = [0x20+FrameNr,DataSize] + DataList[DataToSendPtr:DataToSendPtr+6]
            DataToSendPtr=DataToSendPtr+6 # 6 Bytes gesendet           
           else:
            WorkingFrame = [0x20+FrameNr] + DataList[DataToSendPtr:DataToSendPtr+7]
            DataToSendPtr=DataToSendPtr+7 # 7 Bytes gesendet
           
           if len(WorkingFrame) < 8: 
            WorkingFrame = FillUpCanFrame(WorkingFrame)

           msg = can.Message(arbitration_id=CanID,data=WorkingFrame,is_extended_id=False)
           bus.send(msg)

        #Message Send, receive Answer
        return UDS_Receive(bus,CanID)    
    
    

def TachoIDString(bus):
        TmpData = UDS_ReadDataByIdentifier(bus,0x714,0xF190)
        del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg
        #print(TmpData,end= '  ')
        retStrg = str(bytearray(TmpData),'utf-8')
        TmpData = UDS_ReadDataByIdentifier(bus,0x714,0xF17C)
        del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg            
        retStrg = retStrg + "_" + str(bytearray(TmpData),'utf-8')

        TmpData = UDS_ReadDataByIdentifier(bus,0x714,0xF189)
        del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg            
        retStrg = retStrg + "_SW" + str(bytearray(TmpData),'utf-8')

        return retStrg    

def TachoDumpRam(bus,FilenamePrefix):
        now = datetime.now()
        dt_string = now.strftime("%d.%m.%Y.%H.%M.%S")
        
        f = open(FilenamePrefix + "_" + dt_string +'_TachoRAM.bin', 'w+b')
        
        for Tel in range(255,256):
         for Sel in range(255,256):
          for Addr in range(0x0000,0xFFFF,0x20):
            if Addr == 0xf560: # Read ==> Tacho Reset
             f.write(bytearray([0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77]))    
            else:
             TmpData = UDS_ReadMemoryByAddress(bus,0x714,Tel,Sel,Addr,0x20)
             #print(TmpData,end='')
             print( " "+str(hex(Tel))+" "+str(hex(Sel))+" "+str(hex(Addr))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ) )
             f.write(TmpData)
        f.close()    

def TachoDumpEeprom(bus,FilenamePrefix):
        now = datetime.now()
        dt_string = now.strftime("%d.%m.%Y.%H.%M.%S")
        
        f = open(FilenamePrefix + "_" + dt_string +'_TachoEeprom.bin', 'w+b')    
        for Addr in range(0x0000,0x2000,0x20):            
            TmpData = UDS_ReadMemoryByAddress(bus,0x714,0x04,0x00,Addr,0x20)
            print( " "+str(str(hex(Addr))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ))) 
            f.write(TmpData)
        f.close()

def TachoDumpFlash(bus,FilenamePrefix):
        now = datetime.now()
        dt_string = now.strftime("%d.%m.%Y.%H.%M.%S")
        
        f = open(FilenamePrefix + "_" + dt_string +'_TachoFlash_0-1FFFF.bin', 'w+b')
        for UpperByte in range (0x00,0x20):
         for Addr in range(0x0000,0x10000,0x40):            
            TmpData = UDS_ReadMemoryByAddress(bus,0x714,0x00,UpperByte,Addr,0x40)
            print( " "+str(str(hex(Addr))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ))) 
            f.write(TmpData)
        f.close()              

def EnableEngeneeringMode(bus):
        msg = can.Message(arbitration_id=0x714,data=[0x02, 0x10, 0x60, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],is_extended_id=False)
        bus.send(msg)
        #print("Message sent on {}".format(bus.channel_info))
        recv_message = bus.recv(2.0) # 2 s Timeout
        #print (recv_message)
        UDS_WriteDataByIdentifier(bus,0x714,0xFD11,[0x01])
        UDS_WriteDataByIdentifier(bus,0x714,0xFD11,[0x06])
        msg = can.Message(arbitration_id=0x714,data=[0x30, 0x10, 0x00, 0x00, 0x00, 0x00,0x00,0x00],is_extended_id=False)
        bus.send(msg)
        recv_message = bus.recv(2.0) # 2 s Timeout
        #print (recv_message)
        SeedVomTacho = UDS_WriteDataByIdentifier(bus,0x714,0xFD11,SendSeedRequest)
        #recv_message = bus.recv(2.0) # 2 s Timeout
        #print (recv_message)
        #SeedVomTacho = recv_message.data
        #msg = can.Message(arbitration_id=0x714,data=[0x30, 0x10, 0x00, 0x00, 0x00, 0x00,0x00,0x00],is_extended_id=False)
        #bus.send(msg)
        #recv_message = bus.recv(2.0) # 2 s Timeout
        #print (recv_message)
        #SeedVomTacho = SeedVomTacho + recv_message.data
        #recv_message = bus.recv(2.0) # 2 s Timeout
        #print (recv_message)
        #SeedVomTacho = SeedVomTacho + recv_message.data
        #recv_message = bus.recv(2.0) # 2 s Timeout
        #print (recv_message)
        #SeedVomTacho = SeedVomTacho + recv_message.data

        UDS_TesterPresent(bus,0x714)

        #SeedVomTacho = UDS_ReceiveDecodeAndRemovePadding(SeedVomTacho)

        #print("SeedVomTacho: " + str(binascii.hexlify(SeedVomTacho)))
        #print("SeedVomTacho[0..15]: " + str(binascii.hexlify(SeedVomTacho[0:16])))

        #print (len(SeedVomTacho))

        #print(binascii.hexlify(bytearray(SendSeedRequest)))

        #codecs.decode(keyhex, 'hex')

        iv= codecs.decode(binascii.hexlify(bytearray(SendSeedRequest[1:17])), 'hex')
        #print (iv)
        #print (len(iv))
        aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
        plaintext = codecs.decode(binascii.hexlify(bytearray(SeedVomTacho[0:16])), 'hex')
        ciphertext = aes.encrypt(plaintext)

        iv= ciphertext
        aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
        #print (type(SeedVomTacho))
        #print (type(SendSeedRequest))
        #print (type([0x01]))

        plaintext = codecs.decode(binascii.hexlify(bytearray(list(SeedVomTacho[16:23])+SendSeedRequest[17:25]+[0x01])), 'hex') 
        #print (plaintext)
        #print (len(plaintext))
        #print (len(list(SeedVomTacho[16:23])))
        #print (len(SendSeedRequest[18:26]))
        #print (len(SendSeedRequest))
        ciphertext2 = aes.encrypt(plaintext)

        UDS_WriteDataByIdentifier(bus,0x714,0xFD11,([0x04]+list(ciphertext)+list(ciphertext2)))

        UDS_TesterPresent(bus,0x714)

        recv_message = UDS_WriteDataByIdentifier(bus,0x714,0xFD11,[0x01])
        #print (recv_message.data)
        #print (recv_message.data[2])
        if recv_message.data[2] == 0x07:
          print ("Engeneering Mode Access OK")
          return True
        else:
          print ("Error entering Engeneering mode")
          return False

def send_one():

    # this uses the default configuration (for example from the config file)
    # see https://python-can.readthedocs.io/en/stable/configuration.html
    #bus = can.interface.Bus()

    # Using specific buses works similar:
    bus = can.interface.Bus(bustype='socketcan', channel='can0', bitrate=500000)
    #bus1 = can.interface.Bus(bustype='socketcan', channel='can1', bitrate=500000)
    
    try:
        if len(sys.argv) > 1:
            print (sys.argv[1])
            if (sys.argv[1]) == "-ACCStatus":
                TmpData = UDS_ReadDataByIdentifier(bus,0x757,0x03DE)
                print("Acc CP Error Counter: " +str(codecs.encode( bytearray(TmpData[2:4]) ,'hex') ))
                TmpData = UDS_ReadDataByIdentifier(bus,0x757,0x3C0A)
                print("Acc CP VCRN: " +str(codecs.encode( bytearray(TmpData[2:]) ,'hex') ))
                return
 
#            if (sys.argv[1]) == "-CPSniff":
#                while True:
#                    recv_message = bus1.recv(30.0) # 2 s Timeout
#                    if(recv_message.arbitration_id==0x3DB):
#                        print (recv_message)
#                        
#            if (sys.argv[1]) == "-CPSimu":
#                bus1.send(can.Message(arbitration_id=0x3DB,data=[0x10, 0x0B, 0x80, 0x01, 0x00, 0x01, 0x02, 0x03],is_extended_id=False))
#                while True:
#                    recv_message = bus1.recv(2.0)
#                    if recv_message.arbitration_id ==0x3EB:
#                        break
#                print (recv_message)
#                bus1.send(can.Message(arbitration_id=0x3DB,data=[0x21, 0x04, 0x05, 0x06, 0x07, 0x00, 0xAA, 0xAA],is_extended_id=False))
#                while True:
#                    recv_message = bus1.recv(2.0)
#                    if recv_message.arbitration_id ==0x3EB:
#                        break
#                print (recv_message)
#                bus1.send(can.Message(arbitration_id=0x3DB,data=[0x30, 0x0F, 0x05, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],is_extended_id=False))
#                while True:
#                    recv_message = bus1.recv(2.0)
#                    if recv_message.arbitration_id ==0x3EB:
#                        break
#                print (recv_message)
#                return
            
            if (sys.argv[1]) == "-FindCanIds":
                for CanID in range (0x700,0x7FF):
                    #print("ID 0x%3.3x " % (CanID),end='')
                    UDS_TesterPresent(bus,CanID) 
                return

#######################################################################################################################

            if (sys.argv[1]) == "-BootloaderReadEeprom":
                for AddrEeprom in range (0,0x1000,4):
                 HighByte,LowByte = SplitToBytes(AddrEeprom)
                 WorkingFrame = [0x23,0x80,HighByte,LowByte,0x00,0x00,0x00,0x00]
                 msg = can.Message(arbitration_id=0x714,data=WorkingFrame,is_extended_id=False)
                 bus.send(msg)
               	 recv_message = bus.recv(2.0) # 2 s Timeout  
               	 #print (recv_message.data)
                 print( " "+str(str(hex(AddrEeprom)))+" "+str( codecs.encode( bytearray(recv_message.data[4:]) ,'hex') ) )   
                sys.exit(0)

            if (sys.argv[1]) == "-JumpToBootloader":   
                print("Mai 2021")
                UDS_DiagnosticSessionControl(bus,0x714,0x60)
                #RESET tacho
                recv_message = UDS_WriteDataByIdentifier(bus,0x714,0xFD00,[0x01])
                sleep(7)
                
                UDS_DiagnosticSessionControl(bus,0x714,0x60)
                UDS_RoutineControl(bus,0x714)
                
                UDS_DiagnosticSessionControl(bus,0x714,0x03)
                UDS_DiagnosticSessionControl(bus,0x714,0x02)
                #UDS_TesterPresent(bus,0x714)
                
                UDS_SecurityAccess_SA2(bus,0x714)

                UDS_WriteDataByIdentifier(bus,0x714,0xF15A,[0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99])

                UDS_RequestDownload(bus,0x714,[0x01,0x44,0x03,0xFF,0x19,0x00,0x00,0x00,0x06,0x00])
		# Addr: 0x3FF1900 Size: 0x600 = 1536 Bytes

                #DataPayloadhex = '5F5EB0B19821445A4F475F576F677F773155CDEC0ED1DF2498B1364F05D29A7A905F62620700344B7D17D99D99E152B8029EF2C0B59F7D96F18F42A8E14AEE60'             
                DataPayloadhex = '5F5EB0B19821445A4F475F576F677F773155CDEC0ED1DF2498B1364F05D29A7A905F62620700344B7D17D99D99E152B8029EF2C0B59F7D96F18F42A8E14AEE60B2F3CE4A444F166968C0D9FE9EFCDAB1F4D2C49CF4FCE4ECCB96E4867E41DBAC95E2CBBC757DE5629AEC043DBD0F9CD0AADDC5CDD4D520ED50B7A5BBD1BDE38590704772B150A753D330C5233734650F529CFD411AF5C2A0ED9A7D754D455D55ACA4BCB4F07C806B9318E30C533A1E2DD3EB3C34D3CDB9EBD3AC117EF3BC375ED0A7D848B19E9F68F2ED9D373138272E09271AC54D07E1E8F1624A8D30476CAAB45C23B3BB7CE1969B1D81025179406B5BFC5CC6F0F9E0EF4C667B840C96A0A993984E717CBB2651F4DF53DBF3F86611DC0386F1C43F9323575885B1DC737B21969F8E8937BF3DBA5720DBCD4800C3108AE0060F28398CD0DD525A40767F6669C29C3E89945AF1AC6B23CC33740394EC081AAFF3BE89A1291472BB4F91536BAD959540BBB19DC19F5FF085F30AFE02D214DD95379C180D2B556DBAB232339A6E1BD5834BF38025AA9A95C2CAB3B88AD0F3EF4244CD39AB655B9B02648D790A2076B48E4AB789E3952CD8A4FCFD3A39EE161DB3E8993E22212C5B434B527D4DAA6E9B61BFB1B8229A012521F7F1F861D29915014A517F2028B1174148F132C195B99F81B94E462986D0D9C181F4CFA1E9592E01097817DE2A1013C849F9466069979CAE84B3C1C62F776B8EBCF68059AD7618464F5630666C51292ECF5779262EB690C7CF88FFE7EFB69987BF48400680545F0261767FE258161F46259109744A95EBC0CC71C3E5ECD5B623B2E7D9E593515CC44B007F646C141C040C343C242C55DA24FDD503BFEDD5621778F5BA315875BBC7B055A3E5903533A5F2E932252DD33299E5F2FA5D1548675FA44D452A800975424ACD85AE9749F5020A8DC5E6D7F3ED99CBB3CC711ED39C177E93FD02548F54434B283C636BACE4ABF60E3D231B2F27DD18B82AFF124C8F8088EB47A0A8EFA7D0B5EB7761684A1700082D3061FA9AD320186B0CFEDB4D0E8189EA8EA1A9EEA631B4EA4660694C260A09ED3E21295719F83FB738462F6A59477F8880FA90949F3A80B4BF6F5508D67830B1007AE01F1EBB213F3EBB195D5EFB717D7E3B61929EDBA1B3BEFB99D0DE9BF1F1FEA6E86A1D050DB53AC43D75A31F4D3582F798D59A117895532550F5F3653235F267104933040C8BC3D8D0685A447C8B83F85B979CD9BBB4BC1B533E2078F3F7FCB9D3131BBCF4EDC73FF31781D80C727B3E2C939B3C747D47BFA392018BC11222091ED21D80F7723CDD3AD15D414A92556B9CB39C82BA4D452286A2EAC4F4C6E862D66131892370162329216900667D79205E9299C0BEBCB94196DA2F41F581B9E9A7684E80444000A81211674448003821579E98C1CFB5B8E1EFDFD883CEEFF8E0E8CC58845F3739986C5751F80CBF782E367E90CED6B71118EC0A708C966FFD77E516B8B94D3670996D5630F90D8AD92D3757D1CBD753D1EBF75ED74E64F68059ADD2624A54BC94B88CCD17D527757BDA2E7D9ACAD434D42DD750A4A38BB58D5A52D213494CD293696CD35DD84DB2DB2B2C0C96142652F3EBEC5D754C6E695D78A59B524A4653457F6B2D5D170B1A3D33322C24CBFE34151CEB957B7E6C33BBAC8117BB80A8BB9B5E65131A04EA33373F228ED0C217131D62EAD77BDA60B4B25FA5D1595AA134709D86911902ECD0D601CBD4D41A20F6142700CDA38864D956A0A9141A7E965C789B29CACDDD06CF38A42212D209C1D1CFE1E89578DD69ADB03CA296AA81B74B8827AF36E8E78DF41A20DE102ADA3E32D761C695B59A0672726E5A81ABAFC9B7BEA096D0065AF46E24EEE64D37E101B63EC32176144CA37A9B68B35D9480A08B9284ADD2D003C4281CD93416203B32103DFE0454187B0A5C7D405453DDACBDBDB1BDA112D59FCA2BECE4EC971BE71CB43F192A546CBBB3E983676C2E94808B2E94A6AB0B2113C14E1CE6EBCC12CB21F212E6CAECA42BB572A3436532883D750C461F9DDBDA5FC5FBFA2AD8D413BDF5F0C01923B3BBF84F7340E251F191C28F4EA924EED0D980E359BFB28C505E0709B4762029F817122C30366669EF988088B0B8A0A8D0D8C0C8F0F8E0E810180008303820285058404800000101'
                DataPayload = list(codecs.decode(DataPayloadhex, 'hex'))
                UDS_TransferData(bus,0x714,DataPayload)

                UDS_TransferExit(bus,0x714)

                print("Addr: 0x3FF1900 Size: 0x600 = 1536 Bytes  done")

                
                CtrlPayloadhex ='02020403FF1900008072F89CC405F1EF336BCD757353FB38220EAF220C8BE72B5F7183813C68B2BDC382EF408294111D71041710C52682FAA89DD175CD9C3950AF52E4C88C6ABDF3CFCF58FD406E78ED94619B90919247CA0B66146B4F7D463887ACD2D9770B665B892DCA1B7F1B486E58CF983D63A721067B366FB9E829501BC65FBA872BBE26AA59'
                #CtrlPayloadhex ='02020403FF19000080F89CC405F1EF336BCD757353FB38220EAF220C8BE72B5F7183813C68B2BDC382EF408294111D71041710C52682FAA89DD175CD9C3950AF52E4C88C6ABDF3CFCF58FD406E78ED94619B90919247CA0B66146B4F7D463887ACD2D9770B665B892DCA1B7F1B486E58CF983D63A721067B366FB9E829501BC65FBA872BBE26AA59'
                CtrlPayload =list(codecs.decode(CtrlPayloadhex, 'hex'))
                UDS_RoutineControl2(bus,0x714,0x01,CtrlPayload)

                UDS_RequestDownload(bus,0x714,[0x01,0x44,0x03,0xFF,0x18,0x00,0x00,0x00,0x00,0x60])
		# Addr: 0x3FF1800 Size: 0x60 96 Byte

                DataPayloadhex2 = '173DCBA50640262E66A0464EFE7E666E9DC04B25E08AF09AD9DEC9CECD4CE6EE1E94CAA4C8C0D8D0A8A0B8B08880989094F24A24E18BF19BD8DFCFCFCC4DE7EF1E96C9A7CBC3DBD3ABA3BBB38B839B93940849274B435B532B233B330B031B13'                               
                DataPayload2 = list(codecs.decode(DataPayloadhex2, 'hex'))
                UDS_TransferData(bus,0x714,DataPayload2)

                UDS_TransferExit(bus,0x714)                

                CtrlPayloadhex2 ='02020403FF18000080BF1483037145D8B7B9B4475416896A680CE3EEE1273269254762996398A0C537D7F5E3EDC679E97C8AB68DA280B0B97926DFED2FDB2B5209D605D2754BD9982D390106DB245A28CEEE3B884432E5EB644BC78D8A94125E3220CB49E570463AC6030BAE2E234B435F1F09891476D790871437B5F0DF8CD4A396882A627E42BB5C'
                CtrlPayload2 =list(codecs.decode(CtrlPayloadhex2, 'hex'))
                UDS_RoutineControl2(bus,0x714,0x01,CtrlPayload2)
                
                UDS_SecurityAccess2(bus,0x714)
                
                #UDS_ReadMemoryByAddress(bus,0x714,0x00,0x01,0x0100,0x20)
                
                WorkingFrame = [0x23,0x80,0x00,0x12,0x34,0x56,0x78,0xAB]               
                msg = can.Message(arbitration_id=0x714,data=WorkingFrame,is_extended_id=False)
                bus.send(msg)
                recv_message = bus.recv(2.0) # 2 s Timeout                   

                # a31d70f3 6a297fa0 7d9a406d 26247b97
                #TEST
                #WorkingFrame = [0x3D,0x80,0x13,0xA0] + list(codecs.decode('26247b97', 'hex'))               
                #msg = can.Message(arbitration_id=0x714,data=WorkingFrame,is_extended_id=False)
                #bus.send(msg)
                #recv_message = bus.recv(2.0) # 2 s Timeout 
                
                #WorkingFrame = [0x3D,0x80,0x13,0xA4] + list(codecs.decode('7d9a406d', 'hex'))            
                #msg = can.Message(arbitration_id=0x714,data=WorkingFrame,is_extended_id=False)
                #bus.send(msg)
                #recv_message = bus.recv(2.0) # 2 s Timeout 
                
                #WorkingFrame = [0x3D,0x80,0x13,0xA8] + list(codecs.decode('6a297fa0', 'hex'))          
                #msg = can.Message(arbitration_id=0x714,data=WorkingFrame,is_extended_id=False)
                #bus.send(msg)
                #recv_message = bus.recv(2.0) # 2 s Timeout 
                
                #WorkingFrame = [0x3D,0x80,0x13,0xAC] + list(codecs.decode('a31d70f3', 'hex'))           
                #msg = can.Message(arbitration_id=0x714,data=WorkingFrame,is_extended_id=False)
                #bus.send(msg)
                #recv_message = bus.recv(2.0) # 2 s Timeout 


                # Die ersten 4 Byte eeprom lesen
                WorkingFrame = [0x23,0x80,0x00,0x00,0x00,0x00,0x00,0x00]               
                msg = can.Message(arbitration_id=0x714,data=WorkingFrame,is_extended_id=False)
                bus.send(msg)
                recv_message = bus.recv(2.0) # 2 s Timeout  
                print (recv_message.data)
                
                #Magic ...
		        #Here the last algo is missing ......
                sys.exit(0)
                
                UDS_Boot_ExitBl(bus,0x714)
                sleep(1)
                TachoReset(bus,0x714)
                sleep(2)
                recv_message = UDS_WriteDataByIdentifier(bus,0x714,0xFD11,[0x01])
                if recv_message.data[2] == 0x07:
                  print ("Engeneering Mode Access OK")
                else:
                  print ("Error entering Engeneering mode")
                  sys.exit(0)
                
                AesKey= UDS_ReadMemoryByAddress(bus,0x714,0x00,0x01,0x0100,0x20)   
                print( "AesKey: " + str( codecs.encode( AesKey ,'hex') ) )            
                sys.exit(0)    
                
            if (sys.argv[1]) == "-SecAcc2":                

                print(hex(BLSeed2(0x1B4C5F8A))) 
                sys.exit(0)    
                
            if (sys.argv[1]) == "-ExitBl":
                UDS_Boot_ExitBl(bus,0x714)
                sys.exit(0)  

            if (sys.argv[1]) == "-ExitEngeneeringMode":
                UDS_WriteDataByIdentifier(bus,0x714,0xFD11,[0x02,0x02])
                UDS_WriteDataByIdentifier(bus,0x714,0xFD11,[0x05])
                sys.exit(0)                  
                
            
            if (sys.argv[1]) == "-ReadAesKey":  
                UDS_Boot_ExitBl(bus,0x714)
                sleep(1)
                TachoReset(bus,0x714)
                sleep(2)
                recv_message = UDS_WriteDataByIdentifier(bus,0x714,0xFD11,[0x01])
                if recv_message.data[2] == 0x07:
                  print ("Engeneering Mode Access OK")
                else:
                  print ("Error entering Engeneering mode")
                  sys.exit(0)
                
                AesKey= UDS_ReadMemoryByAddress(bus,0x714,0x00,0x01,0x0100,0x20)   
                print( "AesKey: " + str( codecs.encode( AesKey ,'hex') ) )            
    
                sys.exit(0)   
                
            if (sys.argv[1]) == "-ReadEeprom0x13A0":    
                 Addr = 0x13A0
                 TmpData = UDS_ReadMemoryByAddress(bus,0x714,0x04,0x00,Addr,0x10)
                 #print(TmpData,end='')
                 print( " "+str(str(hex(Addr)))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ) )                   
                 sys.exit(0)   

            if len(sys.argv) > 1:
                if (sys.argv[1]) == "-WriteEeprom0x13A0":
                    AddrEeprom = int(sys.argv[2],16)
                    #print (AddrEeprom)
                    #return
                    CPEepromData = list(codecs.decode(sys.argv[3], 'hex'))
                    print (UDS_WriteMemoryByAddress(bus,0x714,0x04,0x00,AddrEeprom,CPEepromData)) 
                
            if (sys.argv[1]) == "-TEST2":     
                print("SeedAnswer: 0x%x" %(BL_Seed(0x1D45723C) ) )
                sys.exit(0)
                
                SeedVal64=0x1D45723C
                
                SeedVal = np.uint32(SeedVal64)
                print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))              
                SeedVal = np.uint32(SeedVal) << 1
                print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))
                if SeedVal > 0xFFFFFFFF:
                    print("SeedVal > 0xFFFFFFFF Seedval:%x"%(SeedVal64))
                    for i in range(0,0x12):
                        SeedVal = np.uint32(SeedVal) << 1
                        if SeedVal > 0xFFFFFFFF:
                            SeedVal = SeedVal ^ 0x2FB67A9C
                            SeedVal = np.uint32(SeedVal) << 1
                            SeedVal = np.uint32(SeedVal)
                            SeedVal = SeedVal - 0x35658453
                            if SeedVal > 0xFFFFFFFF:
                                SeedVal = SeedVal ^ 0x20142BCD
                                SeedVal = SeedVal + 0x0BFB83250
                        else:
                            SeedVal = SeedVal ^ 0x20142BCD
                            SeedVal = SeedVal + 0x0BFB83250                            
                
                else:
                
                    for i in range(0,0xB):
                        SeedVal = np.uint32(SeedVal)
                        SeedVal = SeedVal + 0x0DAE7823C
                        print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))
                        if SeedVal > 0xFFFFFFFF:
                            SeedVal = SeedVal ^ 0x3DCEE873
                            print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))
                            SeedVal = np.uint32(SeedVal)
                            SeedVal = SeedVal + 0x48904532
                            print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))
                            if SeedVal > 0xFFFFFFFF:
                                  SeedVal = SeedVal << 1
                                  SeedVal = SeedVal ^ 0x0D68A42B
                                  SeedVal = SeedVal << 1
                
                print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))
                SeedVal = np.uint32(SeedVal) << 1
                SeedVal = SeedVal + 1
                #SeedVal = np.uint32(SeedVal)
                print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))
                SeedVal = np.uint32(SeedVal) ^ 0x0A16532CD
                print ("SeedVal: 0x%x type: %s" % (SeedVal,type(SeedVal)))

                sys.exit(0)                  
            

        if EnableEngeneeringMode(bus) == False:
            return

        UDS_TesterPresent(bus,0x714)
        
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoWriteCPEeprom":
                AddrEeprom = int(sys.argv[2],16)
                #print (AddrEeprom)
                #return
                CPEepromData = list(codecs.decode(sys.argv[3], 'hex'))
                print (UDS_WriteMemoryByAddress(bus,0x714,0x04,0x00,AddrEeprom,CPEepromData)) 
                
        
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-WriteCPdata":
         
             CPDatum = [0x19,0x11,0x28]
                                     
             CPData = list(codecs.decode(sys.argv[2], 'hex'))
             #for byte in range(0x10,0x100): # 
                 # Byte[33] last byte can be changed    
                 # 0x14 ==> Cp DIsabled für ACC
                 # 0x57 ==> OK Normal
                 # 0x73 115 ==> Akzeptiert, CP Communikation, alles ok
                 # 0xff 255 ==> Akzeptiert, CP Communikation, alles ok
                 
                 # Byte[32] 
                 # 0x0B ==> Normal
                 # 0x00 ==> Works,too
                 # 0xFF ==> Works,too
                 
                #CPData[32] = byte
                #print (CPData[30:34],end= ' ')
             WriteCPData(bus,CPData,CPDatum)
                #sleep(2)
                #TmpData = UDS_ReadDataByIdentifier(bus,0x757,0x03DE)
                #print("Acc CP Error Counter: " +str(codecs.encode( bytearray(TmpData[2:4]) ,'hex') ))
                #TmpData = UDS_ReadDataByIdentifier(bus,0x757,0x3C0A)                

        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-ReadInfo":      
                for Identifier in [0xF1A2,0xF190,0x2292,0x2203,0x2216,0xF17C,0xF19E,0xF1A2,0x0600,0x0956,0xF197]:
                
                    TmpData = UDS_ReadDataByIdentifier(bus,0x714,Identifier)
                    del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg
                    print(TmpData,end= '  ')
                    print( str( codecs.encode( bytearray(TmpData) ,'hex') ) )
        
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-ReadCPEepromData":    
                #Addr=0x13A0
                #TmpData = UDS_ReadMemoryByAddress(bus,0x714,0x04,0x00,Addr,0x20)
                #print(TmpData,end='')
                #print( " "+str(str(hex(Addr)))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ) )                       
                for Addr in range(0x1500,0x1580,0x20):            
                 #Addr=0x1500
                 TmpData = UDS_ReadMemoryByAddress(bus,0x714,0x04,0x00,Addr,0x20)
                 #print(TmpData,end='')
                 print( " "+str(str(hex(Addr)))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ) )                    
 
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-ReadEepromData":     
                AddrEeprom = int(sys.argv[2],16)                  
                TmpData = UDS_ReadMemoryByAddress(bus,0x714,0x04,0x00,AddrEeprom,0x20)
                #print(TmpData,end='')
                print( " "+str(str(hex(AddrEeprom)))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ) )  
       
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoDumpRam":
                FilenamePrefix = TachoIDString(bus)                      
                if sys.argv[2] != "":
                   Directory = sys.argv[2]
                else:
                   Directory = "./"
                TachoDumpRam(bus,Directory+FilenamePrefix)
                
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoDumpRamVars":
                for Addr in (0x00,0xb504,0x7b40,0x7b60,0x7b80,0x7bA0,0x7bC0,0x7bE0,0x7c00,0xb8a1,0xb8b8,0x6f10,0xb8a3,0xBEBD):
                    TmpData = UDS_ReadMemoryByAddress(bus,0x714,255,255,Addr,0x20)
                    print( " "+str(str(hex(Addr))+" "+str( codecs.encode( bytearray(TmpData) ,'hex') ) ) )
                
                
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoDumpEeprom":
                FilenamePrefix = TachoIDString(bus)                      
                if sys.argv[2] != "":
                   Directory = sys.argv[2]
                else:
                   Directory = "./"
                TachoDumpEeprom(bus,Directory+FilenamePrefix)
                
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoDumpFlash":                      
                FilenamePrefix = TachoIDString(bus)
                if sys.argv[2] != "":
                   Directory = sys.argv[2]
                else:
                   Directory = "./"
                TachoDumpFlash(bus,Directory+FilenamePrefix)
                

        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoReset":
                TachoReset(bus,0x714)
                sys.exit(0) 
                
                recv_message = UDS_WriteDataByIdentifier(bus,0x714,0xFD00,[0x01])
                print (recv_message)
                
                RecID3DB=0
                DataReceived3DB=bytearray()
                RecID3EB=0
                DataReceived3EB=bytearray()                
#                while True:
#                    recv_message = bus1.recv(30.0) # 2 s Timeout
#                    if(recv_message.arbitration_id==0x3DB):
#                      if(recv_message.data[0] != 0x30): # ACk Frsames interessieren nicht
#                        RecID3DB=RecID3DB+1
#                        DataReceived3DB = DataReceived3DB + recv_message.data
#                        if RecID3DB==2:
#                            RecID3DB=0
#                            del DataReceived3DB[8]
#                            del DataReceived3DB[0]
#                            print("Tacho==>ACC: "+str( codecs.encode( bytearray(DataReceived3DB[:3]) ,'hex'))+ " "+str( codecs.encode( bytearray(DataReceived3DB[3:11]) ,'hex'))+" "+hex(DataReceived3DB[11]))
#                            DataReceived3DB=bytearray()
#                            
#                    if(recv_message.arbitration_id==0x3EB): 
#                      if(recv_message.data[0] != 0x30): # ACk Frsames interessieren nicht
#                        RecID3EB=RecID3EB+1
#                        DataReceived3EB = DataReceived3EB + recv_message.data
#                        if RecID3EB==2:
#                            RecID3EB=0
#                            del DataReceived3EB[8]
#                            del DataReceived3EB[0]
#                            print("ACC==>Tacho: "+str( codecs.encode( bytearray(DataReceived3EB[:3]) ,'hex'))+ " "+str( codecs.encode( bytearray(DataReceived3EB[3:11]) ,'hex'))+" "+hex(DataReceived3EB[11]))
#                            DataReceived3EB=bytearray()

        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoDumpIdentifiers":
                for Identifier in range(0x00,0x10000):
                 TmpData = UDS_ReadDataByIdentifier(bus,0x714,Identifier)
                 del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg
                 if TmpData != []:
                  print(TmpData,end='')
                  print( str( codecs.encode( bytearray(TmpData) ,'hex') ) )
                  
        if len(sys.argv) > 1:
            if (sys.argv[1]) == "-TachoDumpIdentifiersCp":
                for Identifier in [0x2216,0x2239,0xf15a,0xf198,0xf199,0xf442]:
                 TmpData = UDS_ReadDataByIdentifier(bus,0x714,Identifier)
                 del TmpData[0:2] # die zwei Byte response ID müssen hier noch weg
                 if TmpData != []:
                  print(TmpData,end='')
                  print( str( codecs.encode( bytearray(TmpData) ,'hex') ) )                        

    except can.CanError:
        print("Message NOT sent")

if __name__ == '__main__':
    send_one()

