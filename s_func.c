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
    printf("Source IP: %s\n", inet_ntoa(t_ip->src));
	printf("Destination IP: %s\n", inet_ntoa(t_ip->dst));
};

pcap_t* choose_device(pcap_if_t* devices) {
    pcap_if_t* dev = C_NULL;
    for (dev = devices; dev != C_NULL; dev = dev->next)
        for (pcap_addr_t* dev_addr = dev->addresses; dev_addr != ((pcap_addr_t*)0); dev_addr = dev_addr->next)
            if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr && dev_addr->netmask) {
                printf("**SUCCESS** Device was found. Devname: %s\n", dev->name);
                return pcap_open_live(dev->name, BUFVAL, 1, TTL, errbuf);
            }
    return ((pcap_t*)0);
}