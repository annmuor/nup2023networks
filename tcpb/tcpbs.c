#include "config.h"

static int send_socket;
static int recv_socket;

static u_short service_port;


const char *ipv4_str(u32 addr) {
  static char ret[16];
  char *repr = (char *)&addr;
  memset(ret, 0, sizeof(ret));
  snprintf(ret, sizeof(ret), "%u.%u.%u.%u", (*repr)&0xff, (*(repr+1)&0xff), (*(repr+2)&0xff), (*(repr+3)&0xff));
  return ret;
}


void init_sockets() {
  service_port = htons(_SERVICE_PORT);
  if((send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    pexit("send_socket failed") // only with TCP headers, I don't want to mess with IP here
  if((recv_socket = socket(PF_PACKET, SOCK_DGRAM, htons(0x0800))) < 0)
    pexit("recv_socket failed")
}

static unsigned short compute_checksum(u_short *addr, u_int count, int final) {
  static unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  if(final) {
    unsigned long new_sum = 0;
	  while (sum>>16) {
		  sum = (sum & 0xffff) + (sum >> 16);
	  }
	  new_sum = ~sum;
    sum = 0;
    return ((unsigned short)new_sum);
  }
  return 0;
}

int send_packet(struct client *c, u8 flags, u16 window) {
  struct fakeiphdr ip = {
    .src = c->dst,
    .dst = c->src,
    .zero = 0,
    .proto = 6,
    .next_proto_len = htons(20),
  };
  struct tcp_hdr tcp = {
    .sport = service_port,
    .dport = c->sport,
    .seq = htonl(++c->last_ack),
    .ack = htonl(++c->last_seq),
    .doff = 5,
    .rsv = 0,
    .flags = flags,
    .win = window,
    .checksum = 0,
    .urgptr = 0,
  };
  struct sockaddr_in sin = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = c->src,
    .sin_port = tcp.dport,
  };

  compute_checksum((u16 *)&ip, sizeof(ip), 0);
  tcp.checksum = compute_checksum((u16 *)&tcp, sizeof(tcp), 1);
  // now print what we are sending
  printf(">> [cli:%d] [40 bytes] (%s:%d -> ",
      c->idx, ipv4_str(ip.src), htons(tcp.sport));
  printf("%s:%d) [f:0x%02x] [w:0x%04x] seq:[%lu] ack:[%lu]\n",
      ipv4_str(ip.dst), htons(tcp.dport),
      tcp.flags, tcp.win, ntohl(tcp.seq), ntohl(tcp.ack));
  return sendto(send_socket, (void *)&tcp, sizeof(tcp), 0, (struct sockaddr *)&sin, sizeof(sin));
}

int is_flag_command(struct client *c) {
  static char cmd[] = "getflag";
  return (strncmp(c->msg, cmd, sizeof(cmd)) == 0)?1:0;
}

void send_flag(struct client *c) {
  static char flag[] = "FIND IT YOURSELF MATE\0\0";
  u16 *win_ptr = (u16 *)flag;
  while(*win_ptr != 0) {
    c->last_seq--;
    c->last_ack--;
    send_packet(c, _FLAG_ACK, *win_ptr++);
  }
  send_packet(c, _FLAG_ACK, 0);
}

void main() {
  u8 *packet = malloc(1500); // magic constant - MAX MTU
  struct sockaddr_in inc;
  socklen_t inc_size;
  init_sockets();
  init_clients();
  memset(packet, 0, 1500);
  while(1) {
    size_t len;
    struct client *c = NULL;
    struct ip_hdr *ip;
    struct tcp_hdr *tcp;
    u8 *data;
    if((len = recvfrom(recv_socket, packet, 1500, 0, (struct sockaddr *)&inc, &inc_size)) < 0) {
      perror("recvfrom");
      continue;
    }
    ip = (struct ip_hdr *)packet;
    if(len < 40 || ip->ver != 4 || ip->proto != 6) {
      continue;
    }
    tcp = (struct tcp_hdr *)(packet + (ip->ihl*4));
    if(tcp->dport != service_port) {
      continue;
    }
    data = packet + (ip->ihl*4) + (tcp->doff*4);
    c = find_or_create(ip->src, tcp->sport);
    c->dst = ip->dst;
    if(c == NULL) {
      pexit("Client creation failed\n");
      continue;
    }

    if(tcp->seq < c->last_seq) {
      printf("[cli:%d] %d is less than %d, resetting\n",
          c->idx, ntohl(tcp->seq), c->last_seq);
      if(send_packet(c, _FLAG_RST, 0) < 0) {
        perror("send_packet failed");
      }
      free_client(c);
      continue;
    }

    c->last_seq = ntohl(tcp->seq);
    c->last_ack = ntohl(tcp->ack);

    printf("<< [cli:%lu] [%lu bytes] (%s:%lu -> ",
        c->idx, len, ipv4_str(ip->src), htons(tcp->sport));
    printf("%s:%lu) [f:0x%02x] [w:0x%04x] seq:[%lu] ack:[%lu]\n",
        ipv4_str(ip->dst), htons(tcp->dport),
        tcp->flags, tcp->win, ntohl(tcp->seq), ntohl(tcp->ack));


    if(tcp->flags == _FLAG_RST || tcp->flags == (_FLAG_RST|_FLAG_ACK)) {
      printf("<< [cli:%lu] connection reset\n", c->idx);
      send_packet(c, _FLAG_RST|_FLAG_ACK, 0);
      free_client(c);
      continue;
    }
    if(tcp->flags == _FLAG_FIN || tcp->flags == (_FLAG_ACK|_FLAG_FIN)) {
      printf("<< [cli:%lu] connection finish\n", c->idx);
      if(send_packet(c, _FLAG_RST|_FLAG_ACK, 0) < 0) {
        perror("send_packet failed");
      }
      free_client(c);
      continue;
    }
    if(tcp->flags == _FLAG_SYN && tcp->win != 0) { // && tcp->flags & _FLAG_ACK == 0 && tcp->win != 0) { // not our client - window shall be zero
        printf("<< [cli:%lu] wrong window start, %lu != 0\n", c->idx, htons(tcp->win));
        if(send_packet(c, _FLAG_RST|_FLAG_ACK, 0) < 0) {
          perror("send_packet failed");
        }
        free_client(c);
        continue;
    }
    switch(c->state) {
      case _STATE_NEW:
        if(tcp->flags == _FLAG_SYN) {
          c->last_ack = 0;
          if(send_packet(c, _FLAG_SYN|_FLAG_ACK, 0) < 0) {
            perror("send_packet failed\n");
          } else {
            c->state = _STATE_ACK;
          }
        } else {
          printf("<< [cli:%lu] unknown flags - resetting the connection\n", c->idx);
          send_packet(c, _FLAG_RST|_FLAG_ACK, 0);
          free_client(c);
        }
        break;
      case _STATE_ACK:
        if(tcp->flags == _FLAG_ACK) {
          printf("<< [cli:%lu] connection established\n", c->idx);
          c->state = _STATE_RMS;
        } else if(tcp->flags == _FLAG_SYN) {
          c->last_ack = 0;
          if(send_packet(c, _FLAG_SYN|_FLAG_ACK, 0) < 0) {
            perror("send_packet failed\n");
          } else {
            c->state = _STATE_ACK;
          }
        } else {
          printf("<< [cli:%lu] unknown flags - resetting the connection\n", c->idx);
          send_packet(c, _FLAG_RST|_FLAG_ACK, 0);
          free_client(c);
        }
        break;
      case _STATE_RMS:
        {
        char *b = (char *)&tcp->win;
        for(u8 i = 0; i < 2; i++) {
          if(*(b+i) == 0) {
            c->eof = 1;
            printf("<< [cli:%lu] got zero byte, message completed\n", c->idx);
            break;
          } else {
            if(c->msg_size < sizeof(c->msg)) {
              c->msg[c->msg_size++] = *(b+i);
            } else {
              c->eof = 1;
              printf("<< [cli:%lu] got overflow, message completed\n", c->idx);
              break;
            }
          }
        }
        if(c->eof) {
            printf("<< [cli:%lu] got message: [%s]\n", c->idx, c->msg);
          if(is_flag_command(c)) {
            send_flag(c);
          }
          memset(c->msg, 0, sizeof(c->msg));
          c->msg_size = 0;
          c->eof = 0;
        }
        }
        break;
    }
  }
}

