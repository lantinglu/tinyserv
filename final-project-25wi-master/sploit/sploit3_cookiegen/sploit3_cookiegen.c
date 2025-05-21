#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "hmac.c"
#include "sha1.c"

typedef struct {
  uint32_t authenticated;  // must be exactly 1 to be authenticated
  time_t expiration;  // must be in the future to be authenticated
} cookie_data;

const uint8_t *cookie_key = (char[]) {
  0x4E, 0x2B, 0xE2, 0x5A, 0xCC, 0x99, 0xA9, 0xAA,
  0xC6, 0x6F, 0xB6, 0xCE, 0x21, 0x7F, 0x07, 0x1A,
  0x47, 0x0B, 0xCE, 0x95, 0xB5, 0x3D, 0x6E, 0xD5,
  0xB4, 0x6D, 0xA7, 0xE9, 0xF4, 0xD6, 0x55, 0x5E
};        // 32 byte key

int make_cookie(uint8_t * buffer)
{
  time_t rawtime;
  time(&rawtime);
  cookie_data *to_sign = (cookie_data *) malloc(sizeof(cookie_data));
  to_sign->authenticated = 1;
  to_sign->expiration = rawtime + 60 * 60 * 48;  // 48 hours in the future
  uint8_t signature[20];
  hmac_sha1(cookie_key, sizeof(cookie_key), (uint8_t *) to_sign,
      sizeof(cookie_data), (uint8_t *) signature);
  // write cookie data
  int data_size = sizeof(cookie_data);
  for (int i = 0; i < data_size; i++) {
    uint8_t byte = ((uint8_t *) to_sign)[i];
    snprintf(buffer + (2 * i), 3, "%02X", byte);  // Write byte as ASCII, e.g. "9A" for 0x9A
  };
  // write signature
  for (int i = 0; i < 20; i++) {
    uint8_t byte = signature[i];
    snprintf(buffer + (2 * data_size) + (2 * i), 3, "%02X", byte);
  };
  free(to_sign);
  return 2 * data_size + 2 * 20;
}
#define BUFFER_SIZE 1024

int main(int argc, char *argv[])
{
  int fd;
  char buffer[BUFFER_SIZE];

  char *cookie = calloc(400, sizeof(char));
  int cookie_len = make_cookie(cookie);
  cookie[cookie_len] = '\0';

  printf("session=%s",cookie);

  return 0;
}
