#include "s_func.h"

void read_data(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    const struct eth *ethernet;
    const struct ip *t_ip;
    unsigned int ip_size;

    ethernet = (struct eth*)(packet);
    t_ip = (struct ip*)(packet + SIZE_ETHERNET);
    
    show_data(ethernet, t_ip);
};

void show_data(const struct eth* ethernet, const struct ip* t_ip) {
    printf("Source IP: %s\n",      inet_ntoa(t_ip->src));
	printf("Destination IP: %s\n", inet_ntoa(t_ip->dst));
};