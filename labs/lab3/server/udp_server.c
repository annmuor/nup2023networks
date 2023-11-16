#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define compare_short(x, y) *(unsigned short *)&x == htons(y)

void send_flag_back(int s, unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
	char flag[] = "NUP23{Show me the solution}\n\0";
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl((a<<24 | b<<16 | c<<8 | d) & 0xffffffff),
		.sin_port = htons(12345)
	};
	printf("We found the hacker! The ip is %d.%d.%d.%d\n", a, b, c, d);
	if(sendto(s, flag, sizeof(flag), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("sendto failed");
	}
}

int main() {
  int s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP), s2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int one = 1;
  unsigned char packet[256]; // just in case
  struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };
  socklen_t len = sizeof(sin);
  if (s < 0 || s2 < 0) {
    perror("socket failed");
    return 1;
  }
  if (setsockopt(s, SOL_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("setsockopt failed");
    return 1;
  }
  if(bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	  perror("bind failed");
	  return 1;
  }
  while(1) {
	  size_t l = recvfrom(s, packet, sizeof(packet), 0, (struct sockaddr *)&sin, &len);
	  if(l < 0) {
		  perror("recvfrom");
		  return 1;
	  }
	  if(l == 31 && packet[9] == 0x11 && compare_short(packet[20],0) && compare_short(packet[22],0) \
			  && compare_short(packet[24], 0x20) && compare_short(packet[26], 0x1337) \
			  && packet[28] == 0x73 && packet[29] == 0x31 && packet[30] == 0x03) {
		  send_flag_back(s2, packet[12], packet[13], packet[14], packet[15]);
	  }
  }
  return 0;
}

