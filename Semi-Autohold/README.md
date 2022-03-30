Semi Autohold with VW T6 using Factory MK100 ABS and 56D EPB

This is the Code running on Raspberry Pi with an Dual Can Header.
The Pi needs to be between the EPB and the Engine Can.
CAN0 connected to EPB
CAN1 connected to Engine-Can


AutoHold.sh sets up all Kernel Based CAN routings which do not need patching.
Autohold is used to receive and patch 0x5C0 mEPB_1 can Mesage from epb.
And it simply patches EP1_AutoHold_aktiv and EP1_EP1_HydrHalten to be on always.

This leads the Car to think that we are in Aktive Autohold.

Theirfor DriveTrain is Powerless and Cat is not Trying to roll, when you release the Brek-Pedal.

But ABS is not breaking, so be carefull car will roll by its own.

Thats why it is called Semi Autohold
