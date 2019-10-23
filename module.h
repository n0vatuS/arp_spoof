#pragma once
#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdlib.h>

#define IP_ADDR_LEN 4
#define SUCCESS 1
#define FAIL 0

struct arp_packet {
    struct ether_header eth_hdr;
    struct ether_arp arp_hdr;
};

struct ip_packet {
    struct ether_header eth_hdr;
    struct ip ip_hdr;
};

void printIPAddress(const char * msg, uint8_t * ip);
void printMacAddress(const char * msg, uint8_t * mac);

bool cmpIPAddress(uint8_t * a, uint8_t * b);
bool cmpMacAddress(uint8_t * a, uint8_t * b);

int parseIP(uint8_t * ip, char * ip_str);

int getAttackerIPAddress(char * ip_str, char * dev);
int getAttackerMacAddress(uint8_t * mac, char * dev);
int getMacAddress(pcap_t * handle, uint8_t * ret, uint8_t * src_mac, uint8_t * src_ip, uint8_t * des_ip);

void sendArpPacket(pcap_t * handle, uint8_t * src_mac, uint8_t * des_mac, uint8_t * src_ip, uint8_t * des_ip, int opcode);
void afterHack(pcap_t * handle, uint8_t * atk_mac, uint8_t * trg_mac, uint8_t * sdr_mac, uint8_t * trg_ip, uint8_t * sdr_ip);
