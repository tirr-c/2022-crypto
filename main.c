#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "poly1305.h"
#include "util.h"

int main(int argc, char** argv) {
  if (argc < 2 || argc >= 4) {
    fprintf(stderr, "Usage: %s <keyfile> [messagefile]\n", argv[0]);
    return EXIT_FAILURE;
  }

  int keyfd = open(argv[1], O_RDONLY);
  if (keyfd == -1) {
    fprintf(stderr, "%s: Failed to open keyfile %s: %s\n", argv[0], argv[1], strerror(errno));
    return EXIT_FAILURE;
  }

  struct poly1305_key kr;
  {
    uint8_t key[32];
    ssize_t count = read_exact(keyfd, key, 32);
    if (count < 0) {
      fprintf(stderr, "%s: Failed to read keyfile %s: %s\n", argv[0], argv[1], strerror(errno));
      return EXIT_FAILURE;
    }
    if (count != 32) {
      fprintf(stderr, "%s: Invalid keyfile %s: key is shorter than 32 bytes\n", argv[0], argv[1]);
      return EXIT_FAILURE;
    }

    if (poly1305_prepare_key(key, &kr) < 0) {
      fprintf(stderr, "%s: Invalid keyfile %s: some bits are not zero\n", argv[0], argv[1]);
      return EXIT_FAILURE;
    }
  }
  close(keyfd);

  int msgfd;
  if (argc == 2 || (argv[2][0] == '-' && argv[2][1] == 0)) {
    msgfd = STDIN_FILENO;
  } else {
    msgfd = open(argv[2], O_RDONLY);
    if (msgfd == -1) {
      fprintf(stderr, "%s: Failed to open message %s: %s\n", argv[0], argv[2], strerror(errno));
      return EXIT_FAILURE;
    }
  }

  struct poly1305_tag tag;
  getrandom_exact(tag.nonce, sizeof(tag.nonce));
  poly1305_auth_stream(&kr, msgfd, &tag);

  printf("Nonce:");
  for (int i = 0; i < 16; i++) {
    printf(" %02x", tag.nonce[i]);
  }
  printf("\n");
  printf("  MAC:");
  for (int i = 0; i < 16; i++) {
    printf(" %02x", tag.tag[i]);
  }
  printf("\n");

  return 0;
}
