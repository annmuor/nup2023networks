### Peer connection protocol (PCP)

#### 1. Each peer sends broadcast messages (UDP port 25655) with the following data:

```c
struct broadcast_message {
    uint8_t magic;
    uint64_t id;
    uint16_t port;
    uint8_t key[16];
}
```

Where:

- magic - shows the type of message. 0xFF for broadcast_message
- id - is the ID of the peer who transmits the message
- port - is the port to connect to (IP address is taken from the message itself)
- key - is the key ( 16 bytes / 128 bits ) to encrypt the data

#### 2. When another peer sees the message, it connects to the port (via UDP) and send the following message:

```c
struct hello_message {
    uint8_t magic;
    uint64_t from_id;
    uint64_t to_id;
    uint8_t caller_key[16];
    uint8_t hello_iv[16];
}
```

Where:

- magic - shows the type of message. 0x1F for hello_message
- from_id - is the ID of the sender
- to_id - is the ID of the receiver (sender got it from the broadcast message in #1)
- caller_key - the key of the caller
- hello_iv - a random string encrypted with the receiver key (sender got the key from broadcast message in #1)

#### 3. The callee responds with the following message

```c
struct hello_reply {
    uint8_t magic;
    uint64_t from_id;
    uin64_t to_id;
    uint8_t hello_reply[16];
}
```

Where:

- magic - shows the type of message. 0x2F for hello_reply
- from_id - is the ID of the sender
- to_id - is the ID of the receiver
- hello_reply - the same random string, decrypted and encrypted back using the key from #2

#### 4. The peers can now exchange messages using the following format:

```c
struct message {
    uint8_t magic;
    uint16_t len;
    uint64_t from_id;
    uin64_t to_id;
    uint8_t message[len];
}
```

Where:

- magic - shows the type of message.
- len - the length of the message
- from_id - is the ID of the sender
- to_id - is the ID of the receiver
- message - the message encrypted with the key we know for that peer

### Message types

- 0xFF - broadcast message
- 0x1F - hello message
- 0x2F - hello_reply message
- 0x3F - FLAG message
- 0x4F - TODO
- 0x5F - TODO
- 0x6F - TODO
- 0x7F - TODO
- 0x8F - TODO

### Data format

- uint64_t - 64-bit integer, unsigned, big endian (network order)
- uint16_t - 16-bit integer, unsigned, big endian (network order)
- uint8_t - 8-bit integer, unsigned (aka unsigned char)

### Encryption

Messages are encrypted by using XOR with the receiver's key.
You may use the following code as an example implementation:

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void encrypt_data(uint8_t *message, const uint16_t len, const uint8_t const key[16]) {
	for(uint16_t i = 0; i < len; i++) {
		uint16_t key_idx = i % 16;
		*(message + i) = key[key_idx] ^ *(message + i);
	}
}

int main() {
	uint8_t msg[] = "Hello, team!\0";
	uint8_t key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
	uint16_t len = strlen(msg);
	encrypt_data(msg, len, key);
	printf("Encrypted data is: %s\n", msg);
	encrypt_data(msg, len, key);
	printf("Encrypted (twice) data is: %s\n", msg);
}
```

And the output is the following:

```text
Encrypted data is: Igohj*'|lkf-
Encrypted (twice) data is: Hello, team!
```

So encrypting the message twice will decrypt it.
