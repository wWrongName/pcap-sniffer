#include <stdio.h>
#include "s_func.h"

int main(int argc, char** argv) {

    char rule[] = "port 80";
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    struct bpf_program fp;
    bpf_u_int32 IP;
    pcap_t *session;

    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        printf("**ERRROR** Could not find net device. Pcap error: %s\n", errbuf);
        return 1;
    }
    else
        printf("**SUCCESS** Device was found. Devname: %s\n", device);

    session = pcap_open_live(device, BUFVAL, 1, TTL, errbuf);
    if (session == NULL) {
        printf("**ERRROR** Could not open device. Devname: %s. Error: %s\n", device, errbuf);
        return 1;
    }
    else
        printf("**SUCCESS** Session was established");
    
    if (pcap_datalink(session) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", device);
        return 1;
    }

    if (pcap_compile(session, &fp, rule, 0, IP) == -1) {
        fprintf(stderr, "Could not parse filter. Rule: %s. Error: %s\n", rule, pcap_geterr(session));
        return 1;
    }

    if (pcap_setfilter(session, &fp) == -1) {
        fprintf(stderr, "Could not install filter. Rule: %s. Error: %s\n", rule, pcap_geterr(session));
        return 1;
    }

    pcap_loop(session, ENDLESS, read_data, NULL);
    
    return 0;
};