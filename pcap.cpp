#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "pcap.h"

struct ether_arp * DataLinkLayer(const u_char * packet) {
    struct ether_header * ether_hdr = (struct ether_header *)packet;

    if(ntohs(ether_hdr -> ether_type) == ETHERTYPE_ARP) {
        struct ether_arp * res_pcap = NetworkLayer(packet);
        return res_pcap;
    }

    return NULL;
}

struct ether_arp * NetworkLayer(const u_char * packet) {
    struct ether_arp * res_pcap = (struct ether_arp *)(packet + DATALINK_HEADER_SIZE);
    return res_pcap;
}