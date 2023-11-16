#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern struct client **clients;
extern size_t clients_size;

#define pexit(s) { perror(s); exit(1); }

#define _STATE_NEW 0x01
#define _STATE_ACK 0x02
#define _STATE_RMS 0x03

#define _SERVICE_PORT 2489

#define _FLAG_FIN 0x01
#define _FLAG_SYN 0x02
#define _FLAG_RST 0x04
#define _FLAG_PSH 0x08
#define _FLAG_ACK 0x10
#define _FLAG_URG 0x20

struct client {
  size_t idx;
  u32 dst;
  u32 src;
  u16 sport;
  u32 last_seq;
  u32 last_ack;
  u8 state;
  u16 msg_size;
  u8 msg[256];
  u8 eof:1;
};

struct ip_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u8 ihl:4;
  u8 ver:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u8 ver:4;
  u8 ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
  u8 dscp:6;
  u8 ecn:2;
  u16 len;
  u16 id;
  u16 frag_off;
  u8 ttl;
  u8 proto;
  u16 checksum;
  u32 src;
  u32 dst;
};

struct fakeiphdr {
  u32 src;
  u32 dst;
  u8 zero;
  u8 proto;
  u16 next_proto_len;
};

struct tcp_hdr {
  u16 sport;
  u16 dport;
  u32 seq;
  u32 ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u8 rsv:4;
  u8 doff:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u8 doff:4;
  u8 rsv:4;
#else
# error "Please fix <bits/endian.h>"
#endif
  u8 flags;
  u16 win;
  u16 checksum;
  u16 urgptr;
};

void init_clients();

struct client *get_client(size_t index);

void free_client(struct client *);

void fini_clients();

struct client *create_client();

struct client *find_or_create(u32 address, u_short port);
