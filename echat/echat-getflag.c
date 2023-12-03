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
#include <unistd.h>

int main(int argc, char** argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *p;
  size_t if_len;
  char* mac;
  int i;
  pcap_t* h;
  user_data u;
  init();
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  if (argc < 2) {
    printf("Usage: %s <interface>\n", *argv);
    return 0;
  }
  argv++;
  if_len = strlen(*argv);
  if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == PCAP_ERROR) {
    printf("pcap_init error: %s\n", errbuf);
    return 1;
  }
  if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
    printf("pcap_findalldevs error: %s\n", errbuf);
    return 2;
  }
  for (p = alldevs; p != NULL; p = p->next) {
    if (strncmp(p->name, *argv, if_len) == 0) {
      pcap_addr_t* addr = p->addresses;
      printf("Device %s was found\n", p->name);
      goto dev_found;
    }
  }
  printf("Device %s was not found\n", *argv);
  return 2;

dev_found:
  pcap_freealldevs(alldevs);
  if ((mac = get_mac_address(*argv)) == NULL) {
    printf("Mac address not found, exiting\n");
    return 2;
  }
  printf("mac address for the device is %s\n", mac_to_str(mac));

  if ((h = pcap_create(*argv, errbuf)) == NULL) {
    printf("pcap_create failed: %s\n", errbuf);
    return 3;
  }
  pcap_set_promisc(h, 0);
  pcap_set_immediate_mode(h, 1);
  pcap_set_snaplen(h, SNAPLEN);
  if(pcap_activate(h) < 0) {
    pcap_perror(h, "pcap_activate failed :(");
    return 4;
  }
  while(1) {
    u_char from[6] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    u_char buf[sizeof(chat_message)+7];
    chat_message *m = (chat_message *)buf;
    m->type = TYPE_PRIVATE;
    strncpy(m->from, "annmuor", sizeof(m->from));
    strncpy(m->msg, "getflag", 7);
    m->msg_size = 7;
    m->crc = calc_crc(m->from, m->msg, m->msg_size);
    send_message(h, from, mac, m);
    sleep(5);

  }
}

