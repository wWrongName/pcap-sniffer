#include <stdio.h>
#include "s_func.h"

int main(int argc, char** argv) {

    char rule[] = "port 22";
    pcap_if_t *devices;
    char *name = NULL;
    struct bpf_program fp;
    bpf_u_int32 IP;
    pcap_t *session;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        printf("**ERRROR** Could not find net devices. Pcap error: %s\n", errbuf);
        return 1;
    }
    else {
        session = choose_device(devices);
        if (session == NULL) {
            printf("**ERRROR** Could not open device. Error: %s\n", errbuf);
            return 1;
        }
        else
            printf("**SUCCESS** Session was established.\n");
    }
    pcap_freealldevs(devices);
    
    if (pcap_datalink(session) != DLT_EN10MB) {
        fprintf(stderr, "Device doesn't provide Ethernet headers\n");
        return 1;
    }

    if (pcap_compile(session, &fp, rule, 0, IP) == -1) {
        fprintf(stderr, "**ERRROR** Could not parse filter. Rule: %s. Error: %s\n", rule, pcap_geterr(session));
        return 1;
    }

    if (pcap_setfilter(session, &fp) == -1) {
        fprintf(stderr, "**ERRROR** Could not install filter. Rule: %s. Error: %s\n", rule, pcap_geterr(session));
        return 1;
    }

    pcap_loop(session, /*ENDLESS*/ 4, read_data, NULL);
    return 0;
};