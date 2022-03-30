#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>

int main()
{
    int ReceiveCounter;
    int ii, Checksum;
    int ret;
    int s_can0_epb, s_can1_epb, nbytes;
    struct sockaddr_can addr;
    struct ifreq ifr_can0_epb, ifr_can1_epb;
    struct can_frame frame,frame_epb;
    
    int s_can1_BR1;
    struct ifreq ifr_can1_BR1;
    struct can_frame frame_BR1;

    memset(&frame, 0, sizeof(struct can_frame));
    
    printf("Autohold Faker 2.0 can0 is dedicated EPB Can\r\n");
    printf("can1 is Engine Can \r\n");
    printf("EP1_AutoHold_aktiv and EP1_EP1_HydrHalten is Statically Set always right now for testing \r\n");
    printf("Using Speed as indicator as quick hack did not work"); 
 
    //1.Create socket
    s_can0_epb = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s_can0_epb < 0) {
        perror("socket can0_epb PF_CAN failed");
        return 1;
    }
    s_can1_epb = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s_can1_epb < 0) {
        perror("socket can1_epb PF_CAN failed");
        return 1;
    }

    s_can1_BR1 = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s_can1_epb < 0) {
        perror("socket can1_BR1 PF_CAN failed");
        return 1;
    }
    
    //2.Specify can0 device
    strcpy(ifr_can0_epb.ifr_name, "can1");
    ret = ioctl(s_can0_epb, SIOCGIFINDEX, &ifr_can0_epb);
    if (ret < 0) {
        perror("ioctl can0 epb failed");
        return 1;
    }
    strcpy(ifr_can1_epb.ifr_name, "can0");
    ret = ioctl(s_can1_epb, SIOCGIFINDEX, &ifr_can1_epb);
    if (ret < 0) {
        perror("ioctl can1 epb failed");
        return 1;
    }

    strcpy(ifr_can1_BR1.ifr_name, "can1");
    ret = ioctl(s_can1_BR1, SIOCGIFINDEX, &ifr_can1_BR1);
    if (ret < 0) {
        perror("ioctl can1 BR1 failed");
        return 1;
    }



    //3.Bind the socket to can0
    addr.can_family = PF_CAN;
    addr.can_ifindex = ifr_can0_epb.ifr_ifindex;
    ret = bind(s_can0_epb, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind can0 epb failed");
        return 1;
    }
    //3.Bind the socket to can1
    addr.can_family = PF_CAN;
    addr.can_ifindex = ifr_can1_epb.ifr_ifindex;
    ret = bind(s_can1_epb, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind can1 epb failed");
        return 1;
    }
    //3.Bind the socket to can1
    addr.can_family = PF_CAN;
    addr.can_ifindex = ifr_can1_BR1.ifr_ifindex;
    ret = bind(s_can1_BR1, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind can1 BR1 failed");
        return 1;
    }


    //can1 EPB 4.Define receive rules
    struct can_filter rfilter_epb[1];
    rfilter_epb[0].can_id = 0x5C0;
    rfilter_epb[0].can_mask = CAN_SFF_MASK;
    setsockopt(s_can1_epb, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter_epb, sizeof(rfilter_epb));

    //cam0 EPB Disable filtering rules, do not receive packets, only send
    setsockopt(s_can0_epb, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

    //can1 BR1 4.Define receive rules
    struct can_filter rfilter_BR1[1];
    rfilter_BR1[0].can_id = 0x1A0;
    rfilter_BR1[0].can_mask = CAN_SFF_MASK;
    setsockopt(s_can1_BR1, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter_BR1, sizeof(rfilter_BR1));


    ReceiveCounter = 0;

int BR1_Rad_km,BR1_Rad_km_last;
int notRepeat_0,notRepeat_1;
notRepeat_0=0;
notRepeat_1=0;


while(1)
{
    
    //5.Receive BR1 data and exit
    while(1) 
    {
        nbytes = read(s_can1_BR1, &frame_BR1, sizeof(frame_BR1));
        if(nbytes > 0) 
        {
             BR1_Rad_km= ((frame_BR1.data[2] & 0xFE) >> 1) +  ((frame_BR1.data[3] &0xFF)<<7)  ;
             if (((BR1_Rad_km_last-250)>BR1_Rad_km) | ((BR1_Rad_km_last+250)<BR1_Rad_km) | ( (BR1_Rad_km==0) & (BR1_Rad_km_last>0) ) )
	     {
              printf("BR1_Rad_km %d %2.2x %2.2x\n\r",BR1_Rad_km,(frame_BR1.data[2]>>1),frame_BR1.data[3]);
              BR1_Rad_km_last=BR1_Rad_km;
	     }
             break;
        }

    }


    //5.Receive data and exit
    while(1) 
    {
        nbytes = read(s_can1_epb, &frame_epb, sizeof(frame_epb));
        if(nbytes > 0) 
        {
             ReceiveCounter++;
             //printf("mEPB_1 \n\r");
             break;
        }

    }

    frame_epb.data[4] = frame_epb.data[4] | 1<<3;//set EP1_AutoHold_aktiv
    frame_epb.data[5] = frame_epb.data[5] | 1<<7;//set EP1_EP1_HydrHalten

    if (BR1_Rad_km < 100)
    {
     //hier !!!
     if(notRepeat_0==0) 
     {
        printf("Faking EP1_EP1_HydrHalten\n\r");
        notRepeat_0=1;
        notRepeat_1=0;
     }
    }
    else
    {
     if(notRepeat_1==0) 
     {
       printf("Not Faking EP1_EP1_HydrHalten\n\r");
       notRepeat_0=0;
       notRepeat_1=1;
     }
    }

    Checksum = 0;
    for(ii = 0; ii < 7; ii++)
     Checksum = Checksum ^ frame_epb.data[ii];
    frame_epb.data[7] = Checksum;
    

    nbytes = write(s_can0_epb, &frame_epb, sizeof(frame_epb)); 
    if(nbytes != sizeof(frame)) 
    {
     printf("Send Error can1 epb frame[0]!\r\n");
    }

     
     


    if (BR1_Rad_km < 1)
    {
    frame_epb.can_id = 0x2B7;
    frame_epb.can_dlc = 8;
    frame_epb.data[0] = 0; // CRC
    frame_epb.data[1] = 2; // 0..3 counter
    frame_epb.data[2] = 3;
    frame_epb.data[3] = 4;
    frame_epb.data[4] = 5;
    frame_epb.data[5] = 1<<3; //RCTA_Anforderung_HMS = 1 halten (3 bit ab bit 3)
    frame_epb.data[6] = 7;
    frame_epb.data[7] = 8;

     //nbytes = write(s_can0_epb, &frame_epb, sizeof(frame_epb)); 
     //if(nbytes != sizeof(frame)) 
     //{
     // printf("Send Error can1 epb frame[0]!\r\n");
     //}


    }

    
    

    

}

}
