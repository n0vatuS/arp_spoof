#pragma once

// header size
#define DATALINK_HEADER_SIZE 14

struct ether_arp * DataLinkLayer(const u_char * packet);
struct ether_arp * NetworkLayer(const u_char * packet);
