#include "config.h"

size_t clients_size;
struct client **clients;

void init_clients() {
  extern size_t clients_size;
  extern struct client **clients;
  clients_size = 64;
  if((clients = calloc(clients_size, sizeof(struct client *))) == NULL)
      pexit("calloc failed");
  memset(clients, 0, sizeof(struct client *)*clients_size);
}

struct client *get_client(size_t index) {
  extern size_t clients_size;
  extern struct client **clients;
  if(index >= clients_size) {
    return NULL;
  } else {
    return *(clients+index);
  }
}

void free_client(struct client *c) {
  if(c != NULL) {
    *(clients + c->idx) = NULL;
    free(c);
  }
}

void fini_clients() {
  extern size_t clients_size;
  extern struct client **clients;
  for(size_t i = 0; i < clients_size; i++) {
    free_client(*(clients+i));
  }
  clients_size = 0;
  free(clients);
  clients = NULL;
}

struct client *create_client() {
  extern size_t clients_size;
  extern struct client **clients;
  size_t index = 0;
  struct client *c = malloc(sizeof(struct client));
  memset(c, 0, sizeof(struct client));
  for(; index < clients_size; index++) {
    if(get_client(index) == NULL) { // we found free space
      *(clients+index) = c;
      c->idx = index;
      return c;
    }
  }
  if(index == clients_size) { // now let's reallocate the table as we need more space
    clients_size *= 2; // make it x2 - easy
    clients = realloc(clients, clients_size*sizeof(struct client *));
    *(clients+index) = c;
    c->idx = index;
    return c;
  }
}

struct client *find_or_create(u32 address, u_short port) {
  struct client *c = NULL;
  for(size_t i = 0; i < clients_size; i++) {
    if((c = get_client(i)) != NULL) {
      if(c->src == address && c->sport == port) {
        return c;
      }
    }
  }
  c = create_client();
  c->src = address;
  c->sport = port;
  c->state = _STATE_NEW;
  return c;
}
