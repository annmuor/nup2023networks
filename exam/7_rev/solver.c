#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

int check_magic(const uint8_t const *);

int main(int argc, char **argv) {
	int fd;
	size_t size;
	uint8_t *data;
	uint8_t *flag = NULL;
	uint8_t *key = NULL;
	uint32_t *src = NULL;
	uint8_t *packet;
	uint16_t mlen, idx, key_idx;

	if(argc != 2) {
		fprintf(stderr, "Usage: %s <pcap file>\n", *argv);
		return -1;
	}
	argv++;
	if((fd = open(*argv, O_RDONLY)) < 0) {
		perror("open");
		return -1;
	}

	if((size = lseek(fd, 0, SEEK_END)) < 0) {
		perror("lseek");
		return -1;
	}
	lseek(fd, 0, SEEK_SET);
	data = (uint8_t *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if(data == NULL) {
		perror("mmap");
		return -1;
	}
	if(!check_magic(data)) {
		fprintf(stderr, "Not a pcap file: %s\n", *argv);
		return -1;
	}
	packet = data + 24 + 16;
	while(flag == NULL) {
		uint16_t len = ntohs(*(uint16_t *)(packet + 16));
		printf("Reading Ipv4 packet with len == %d\n", len);
		if(*(packet + 14 + 20 + 8) == 0x3f) {
			printf("Found FLAG packet\n");
			flag = (packet + 14 + 20 + 8);
			src = (uint32_t *)(packet +14 + 16);
		}
		packet += 14 + len + 16;
	}
	packet = data + 24 + 16;
	while(key == NULL) {
		uint16_t len = ntohs(*(uint16_t *)(packet + 16));
		uint32_t *_src = (uint32_t *)(packet +14 + 12);
		printf("Reading Ipv4 packet with len == %d\n", len);
		if(*(packet + 14 + 20 + 8) == 0xff && *src == *_src) {
			printf("Found KEY packet\n");
			key = (packet + 14 + 20 + 8);
		}
		packet += 14 + len + 16;
	}
	mlen = ntohs(*(uint16_t *)(flag+1));
	printf("Message len = %d\n", mlen);
	for(idx=0;idx<mlen;idx++) {
		key_idx = 11 + (idx % 16);
		*(flag + 1 + 2 + 8 + 8 + idx) ^= *(key + key_idx);
	}
	printf("Flag is: %s\n", (flag + 1 +2 +8 +8));
	

}

int check_magic(const uint8_t const *data) {
	static uint8_t magic1[] = {0xa1,0xb2,0xc3,0xd4};
	static uint8_t magic2[] = {0xd4,0xc3,0xb2,0xa1};
	return memcmp(data, magic1, 4) == 0 ? 1 : memcmp(data, magic2, 4) == 0 ? 1 : 0;

}


