#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * |--------------- UDP HEADER --------------|
 * |    SOURCE PORT     |  DESTINATION PORT  | = 32 bits
 * |--------------------|--------------------|
 * |      LENGTH        |      CHECKSUM      | = 32 bits
 * |-----------------------------------------|
 *
 **/

#define SRC_IP 10, 10, 10, 99
#define DST_IP 10, 10, 10, 65
const unsigned char ip_hdr[] = {
  0x45, 0x00, 0x00, 0x00, // Version:4 IHL:4, DSCP:6 ECN:2, [Total Len]:16
  0x00, 0x00, 0x00, 0x00, // Identification:16, Flags:3, [Fragment Offset]:13
  0x40, 0x06, 0x00, 0x00, // TTL:8, Protocol:8, [Header checksum]:16
  SRC_IP,                 // [Source IP Address]:32
  DST_IP                  // [Destination IP Address]:32
};

static void fill_iphdr(char* header) {
  memcpy(header, ip_hdr, sizeof(ip_hdr));
}

static void fill_tcp(char* header) {
  // TODO - do something here
  memset(header, '0', 24); // 8 bytes udp header + 3 bytes data
}

static in_addr_t address() {
  unsigned char ip[] = { DST_IP };
  return *((int *)ip);
}

int main() {
  int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  int one = 1;
  unsigned char packet[256]; // just in case
  size_t packet_len = 44;    // 20 ip header + 8 udp header + 0 data
  int i = 0;
  struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr.s_addr = address(), .sin_port = 0 };
  if (s < 0) {
    perror("socket failed");
    return 1;
  }
  if (setsockopt(s, SOL_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("setsockopt failed");
    return 1;
  }
  fill_iphdr(packet);
  fill_tcp(&packet[20]);
  printf("----- PACKET ------\n");
  for (i = 0; i < packet_len; i++)
    printf("%02x ", packet[i]);
  printf("\n-----/PACKET ------\n");
  while (1) {
    if (sendto(s, packet, packet_len, 0, (const struct sockaddr*)&sin, sizeof(sin)) < 0) {
      perror("sendto failed :(");
    }
    sleep(1);
  }
  return 0;
}
