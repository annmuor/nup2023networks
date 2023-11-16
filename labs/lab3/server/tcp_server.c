#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define compare_short(x, y) *(unsigned short *)&x == htons(y)

#define compare_int(x, y) *(unsigned int *)&x == htonl(y)

static char flag1[] = "NUP23{Please go and solve it yourself}\n\0";
static char flag2[] = "NUP23{And this task to as well :)))))}\n\0";
void send_flag_back(int s, int v, unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
	char *flag = (v)?flag2:flag1;
	int len = sizeof(flag2);
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl((a<<24 | b<<16 | c<<8 | d) & 0xffffffff),
		.sin_port = htons(12345)
	};
	printf("We found the hacker! The ip is %d.%d.%d.%d\n", a, b, c, d);

	if(sendto(s, flag, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("sendto failed");
	}
}

static unsigned short compute_checksum(unsigned short *addr, unsigned int count, int final) {
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
	  unsigned long new_sum;
	  //Fold sum to 16 bits: add carrier to result
	  while (sum>>16) {
		  sum = (sum & 0xffff) + (sum >> 16);
	  }
	  //one's complement
	  new_sum = ~sum;
	  sum = 0; // for static
	  return (unsigned short)new_sum;
  }
  return ((unsigned short)sum);
}

static int check_checksum(unsigned short checksum, char *packet) {
  // source port: 1337 destination port: 7331 ack: 81321 seq: 321342
  unsigned short _checksum;
  unsigned char phdr[12];
  memcpy(phdr, &packet[12], 4);
  memcpy(&phdr[4], &packet[16], 4);
  phdr[8] = 0; phdr[9] = 6; phdr[10] = 0; phdr[11] = 20;
  packet[36] = 0;
  packet[37] = 0; // drop checksum
  compute_checksum((short *)phdr, 12, 0);
  _checksum = htons(compute_checksum((short *)&packet[20], 20, 1));
  return _checksum == checksum;
}

int main() {
  int s = socket(PF_PACKET, SOCK_RAW, htons(0x0003)), s2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int one = 1;
  unsigned char packet[256]; // just in case
  struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };
  socklen_t len = sizeof(sin);
  if (s < 0 || s2 < 0) {
    perror("socket failed");
    return 1;
  }
  while(1) {
	  unsigned char p[40];
	  size_t l = recvfrom(s, packet, sizeof(packet), 0, (struct sockaddr *)&sin, &len);
	  if(l < 0) {
		  perror("recvfrom");
		  return 1;
	  }
	  if(l != 54 ) {
		  continue;
	  }
	  memcpy(p, &packet[14], 40);
	  // source port: 1337,destination port: 7331 ack: 81321, seq: 321342,no data checksum may be correct or incorrect*
	  if(p[9] == 0x06 && compare_short(p[20], 1337) && compare_short(p[22], 7331) && \
			  compare_int(p[24], 321342) && compare_int(p[28], 81321) && \
			  p[33] == 4) {
		  unsigned short checksum = ntohs(*(unsigned short *)&p[36]);
		  int result = check_checksum(checksum, p);
		  send_flag_back(s2, result, p[12], p[13], p[14], p[15]);
	  }
  }
  return 0;
}

