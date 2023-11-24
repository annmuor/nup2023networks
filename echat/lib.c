
/**
 * Warning!
 * This is plain old-style C code
 * Please don't write your code like that
 * You should never do it in that way in production
 * Really
 *
 * I'm just having fun writing code like that
 *
 **/

#include "lib.h"

u_short ether_type;

void init() {
 ether_type = htons(0x8822);
}

u_char* get_mac_address(const char* dev)
{
  static u_char addr[6];
  struct ifreq ifr;
  int s;
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return NULL;
  }
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return NULL;
  }
  memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);
  return addr;
}

char* mac_to_str(u_char* mac)
{
  static char buf[5 + 2 * 6];
  int i = 0;
  for (; i < 6; i++) {
    if (i != 5)
      sprintf(buf + (i * 3), "%02X:", *(mac + i) & 0xff);
    else
      sprintf(buf + (i * 3), "%02X", *(mac + i) & 0xff);
  }
  return buf;
}

u_short calc_crc(const u_char from[8], const u_char* msg, u_char msg_size)
{
  u_short res = 31;
  int i = 0;
  for (; i < 8; i++) {
    res |= from[i];
    if (i % 2 == 0) {
      res <<= 8;
    }
  }
  for (i = 0; i < msg_size; i++) {
    res |= *(msg + i);
    if (i % 2 == 0) {
      res <<= 8;
    }
  }
  return htons(res & 0xffff);
}

void send_message(pcap_t* h, const u_char from[6], const u_char to[6], const chat_message *msg)
{
  u_char buf[sizeof(struct ether_header) + sizeof(chat_message) + 127];
  struct ether_header* he = (struct ether_header*)buf;
  chat_message* m = (chat_message*)&buf[sizeof(struct ether_header)];
  memset(buf, 0, sizeof(buf));
  memcpy(he->ether_shost, from, 6);
  memcpy(he->ether_dhost, to, 6);
  he->ether_type = ether_type;
  memcpy(m, msg, sizeof(chat_message) + msg->msg_size);
  if (pcap_inject(h, (void*)buf, sizeof(struct ether_header) + sizeof(chat_message) + msg->msg_size) < 0) {
    pcap_perror(h, "pcap_inject failed :(");
  }
}
