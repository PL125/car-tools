#!/bin/bash

echo "https://github.com/GENIVI/CANdevStudio#compatible-can-interfaces"
ip link set can0 type can restart-ms 1000
ip link set can1 type can restart-ms 1000

ip link set can0 up type can bitrate 500000
ip link set can1 up type can bitrate 500000

/usr/sbin/modprobe can-gw

/usr/bin/cangw -F

cd /usr/bin/

#DIAG
cangw -A -s can1 -d can0 -f 200:7FF
#cangw -A -s can0 -d can1 -e -f 200:7FF
cangw -A -s can1 -d can0 -f 700:7FF
#cangw -A -s can0 -d can1 -e -f 700:7FF
cangw -A -s can1 -d can0 -f 752:7FF
#cangw -A -s can0 -d can1 -e -f 752:7FF

# engine to epb
cangw -A -s can1 -d can0 -f 050:7FF #mAirbag_1
cangw -A -s can1 -d can0 -f 1A0:7FF #mBremse_1
cangw -A -s can1 -d can0 -f 4A0:7FF #mBremse_3
cangw -A -s can1 -d can0 -f 4A8:7FF #mBremse_5
cangw -A -s can1 -d can0 -f 1AC:7FF #mBremse_8
cangw -A -s can1 -d can0 -f 5B7:7FF #mBremse_11
cangw -A -s can1 -d can0 -f 440:7FF #mGetriebe_1
cangw -A -s can1 -d can0 -f 280:7FF #mMotor_1
cangw -A -s can1 -d can0 -f 288:7FF #mMotor_2
cangw -A -s can1 -d can0 -f 380:7FF #mMotor_3
cangw -A -s can1 -d can0 -f 480:7FF #mMotor_5
cangw -A -s can1 -d can0 -f 58C:7FF #mMotor_10
cangw -A -s can1 -d can0 -f 420:7FF #mKombi_2
cangw -A -s can1 -d can0 -f 390:7FF #mGate_Komf_1
cangw -A -s can1 -d can0 -f 7D0:7FF #mDiagnose_1
cangw -A -s can1 -d can0 -f 5D2:7FF #mIdent
cangw -A -s can1 -d can0 -f 570:7FF #mBSG_Last

#EPB to engine

cangw -A -s can0 -d can1 -f 739:7FF #NMH_EPB
#cangw -A -s can0 -d can1 -e -f 5C0:7FF #mEPB_1
cangw -A -s can0 -d can1 -f 7BC:7FF #ISO_EPB_Res

/root/wiringPi/receive/Autohold &
