#ifndef __POLY1305_H
#define __POLY1305_H

#include <stdint.h>
#include <immintrin.h>

struct poly1305_key {
  __m256i r0;
  __m256i r1;
  __m256i r2;
  __m256i r3;
  __m128i aes_k;
};

struct poly1305_tag {
  uint8_t tag[16];
  uint8_t nonce[16];
};

extern int poly1305_prepare_key(const uint8_t key[32], struct poly1305_key* out);

extern void poly1305_auth_once(struct poly1305_key const* key,
                               uint8_t const* buf,
                               size_t len,
                               struct poly1305_tag* out);
extern ssize_t poly1305_auth_stream(struct poly1305_key const* key,
                                    int fd,
                                    struct poly1305_tag* out);
#endif
