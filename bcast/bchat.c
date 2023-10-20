#include <stdio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <string.h>
#include <stdlib.h>
#define READLINE_CALLBACKS
#include <readline/readline.h>

#define MAX_SIZE 4096
#define PORT 25555
const unsigned char broadcast[] = {10,10,10,127};
const unsigned char my_addr[] = {10,10,10,66};
const char *prompt = "chat> ";
int ssock = -1; void chat_callback(char *);

int main() {
  char buf[MAX_SIZE];
  int lsock;
  struct sockaddr_in bind_addr;
  fd_set read;
  int opt = 1;

  lsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(lsock < 0) {
    perror("UPD socket failed");
    return 1;
  }
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = 0;
  bind_addr.sin_port = htons(PORT);
  if(bind(lsock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
    perror("UDP socket bind failed");
    return 1;
  }
  bind_addr.sin_port = htons(0);
  ssock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(ssock < 0) {
    perror("UDP client socket failed");
    return 1;
  }
  if(bind(ssock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
    perror("UDP client bind socket failed");
    return 1;
  }
  if(setsockopt(ssock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
    perror("setsockopt failed");
    return 1;
  }
  // Setting callbacks
  rl_callback_handler_install(prompt, chat_callback);
  // setting SELECT
  while(1) {
    FD_ZERO(&read);
    FD_SET(0, &read);
    FD_SET(lsock, &read);
    if(select(lsock+1, &read, NULL, NULL,NULL) < 0) {
      perror("Select failed");
      return -1;
    }
    if(FD_ISSET(0, &read)) {
      rl_callback_read_char();
    }
    if(FD_ISSET(lsock, &read)) {
      struct sockaddr_in from;
      int size = sizeof(from);
      int len;
      unsigned char *ip;
      int port;
      if((len = recvfrom(lsock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &size)) < 0) {
        perror("Recvfrom failed");
        return -1;
      }
      *(buf+len) = 0;
      ip = (char *)(&from.sin_addr.s_addr);
      port = ntohs(from.sin_port);
      printf("\n[%03d.%03d.%03d.%03d]: %s\n", *ip, *(ip+1), *(ip+2), *(ip+3), buf);
      fflush(stdout);
    }
  }
}

void chat_callback(char *line) {
  if(line == NULL) {
    printf("Exiting\n");
    exit(0);
  }
  if(strlen(line) == 0) {
    free(line);
    return;
  }
  struct sockaddr_in send_addr;
  send_addr.sin_family = AF_INET;
  send_addr.sin_addr.s_addr = *((int *)(broadcast));
  send_addr.sin_port = htons(PORT);
  if(sendto(ssock, (const void *)line, strlen(line), 0, (struct sockaddr *)&send_addr, sizeof(send_addr)) < 0) {
    perror("Sendto error");
  }
  free((void *)line);
}


