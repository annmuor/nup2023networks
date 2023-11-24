#ifndef _LIB_H
#define _LIB_H 1

#include <net/if.h>
#include <netinet/ether.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define TYPE_PRIVATE 0
#define TYPE_PUBLIC 1

#pragma pack(push, 1)
typedef struct {
  u_char type : 1;
  u_char msg_size : 7; // up to 127 bytes
  u_char from[8];
  u_short crc;
  u_char msg[];
} chat_message;
#pragma pack(pop)

typedef struct {
  const char* mac;
  pcap_t* pcap;
} user_data;

#define SNAPLEN sizeof(struct ether_header) + sizeof(chat_message) + 127

extern u_short ether_type;

u_char* get_mac_address(const char*);
char* mac_to_str(u_char*);
u_short calc_crc(const u_char from[8], const u_char* msg, u_char msg_size);
void send_message(pcap_t*, const u_char[6], const u_char[6], const chat_message*, u_char);
void init();

#endif
