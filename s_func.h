#ifndef __SNIFFER__
#define __SNIFFER__

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define C_NULL ((pcap_if_t*)0)
#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define BUFVAL 256
#define TTL 1000
#define ENDLESS -1

char errbuf[PCAP_ERRBUF_SIZE];

struct eth {
   unsigned char  dst[ETHER_ADDR_LEN];
   unsigned char  src[ETHER_ADDR_LEN];
   unsigned short type;
};

struct ip {
   unsigned char  vhl;
   unsigned char  tos;
   unsigned short len;
   unsigned short id;
   unsigned short offset;
   unsigned char  ttl;
   unsigned char  prot;
   unsigned short csum;
   struct in_addr src;
   struct in_addr dst;
};

void read_data(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);
void show_data(const struct eth*, const struct ip*);
pcap_t* choose_device(pcap_if_t*);

#endif