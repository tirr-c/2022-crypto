#ifndef __HMAC_SHA256_H
#define __HMAC_SHA256_H

#include <stdint.h>
#include "sha256.h"

struct hmac_sha256_state {
  struct sha256_state sha256;
  uint8_t opad[64];
};

extern struct hmac_sha256_state
hmac_sha256_init(uint8_t const* key, size_t keylen);

extern void hmac_sha256_digest(const struct hmac_sha256_state state, uint8_t* out);

#endif
