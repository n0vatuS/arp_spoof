// #pragma once
#include <pcap.h>
#include <stdlib.h>

char * printIPAddress(uint8_t * ip);
char * printMacAddress(u_char * mac);
bool cmpMacAddress(u_char * a, u_char * b);
uint8_t * parseIP(char * ori_ip);
u_char * makeArpPacket(u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip, int opcode);
char * getAttackerIPAddress(char * dev);
u_char * getAttackerMacAddress(char * dev);
u_char * getSenderMacAddress(pcap_t * handle, u_char * src_mac, uint8_t * src_ip, uint8_t * des_ip);
void hackSender(pcap_t * handle, u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip);
void passTest(pcap_t * handle, u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip);
