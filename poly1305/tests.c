#include <stdio.h>
#include <string.h>
#include <stdalign.h>

#include "../util.h"
#include "poly1305.h"

static void print_tag(struct poly1305_tag const* tag) {
  printf("Nonce:");
  for (int i = 0; i < 16; i++) {
    printf(" %02x", tag->nonce[i]);
  }
  printf("\n");
  printf("  Tag:");
  for (int i = 0; i < 16; i++) {
    printf(" %02x", tag->tag[i]);
  }
  printf("\n");
}

int main() {
  struct poly1305_key kr;
  struct poly1305_tag tag;
  int ret = 0;

  {
    static char key[] = "\x75\xde\xaa\x25\xc0\x9f\x20\x8e\x1d\xc4\xce\x6b\x5c\xad\x3f\xbf\xa0\xf3\x08\x00\x00\xf4\x64\x00\xd0\xc7\xe9\x07\x6c\x83\x44\x03";
    static char msg[] = "";
    poly1305_prepare_key(
      (uint8_t const*) key,
      &kr
    );
    memcpy(tag.nonce, "\x61\xee\x09\x21\x8d\x29\xb0\xaa\xed\x7e\x15\x4a\x2c\x55\x09\xcc", 16);
    poly1305_auth_once(&kr, (uint8_t const*) msg, 0, &tag);
    if (!is_equal_const(tag.tag, (uint8_t const*) "\xdd\x3f\xab\x22\x51\xf1\x1a\xc7\x59\xf0\x88\x71\x29\xcc\x2e\xe7")) {
      printf("Tag mismatch\n");
      print_tag(&tag);
      ret = EXIT_FAILURE;
    }
  }

  {
    static char key[] = "\xe1\xa5\x66\x8a\x4d\x5b\x66\xa5\xf6\x8c\xc5\x42\x4e\xd5\x98\x2d\x12\x97\x6a\x08\xc4\x42\x6d\x0c\xe8\xa8\x24\x07\xc4\xf4\x82\x07";
    static char msg[] = "\xab\x08\x12\x72\x4a\x7f\x1e\x34\x27\x42\xcb\xed\x37\x4d\x94\xd1\x36\xc6\xb8\x79\x5d\x45\xb3\x81\x98\x30\xf2\xc0\x44\x91\xfa\xf0\x99\x0c\x62\xe4\x8b\x80\x18\xb2\xc3\xe4\xa0\xfa\x31\x34\xcb\x67\xfa\x83\xe1\x58\xc9\x94\xd9\x61\xc4\xcb\x21\x09\x5c\x1b\xf9";
    poly1305_prepare_key(
      (uint8_t const*) key,
      &kr
    );
    memcpy(tag.nonce, "\x9a\xe8\x31\xe7\x43\x97\x8d\x3a\x23\x52\x7c\x71\x28\x14\x9e\x3a", 16);
    poly1305_auth_once(&kr, (uint8_t const*) msg, 63, &tag);
    if (!is_equal_const(tag.tag, (uint8_t const*) "\x51\x54\xad\x0d\x2c\xb2\x6e\x01\x27\x4f\xc5\x11\x48\x49\x1f\x1b")) {
      printf("Tag mismatch\n");
      print_tag(&tag);
      ret = EXIT_FAILURE;
    }
  }

  return ret;
}
