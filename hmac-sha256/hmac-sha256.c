#include <string.h>
#include <stdint.h>

#include "sha256.h"
#include "hmac-sha256.h"

struct hmac_sha256_state
hmac_sha256_init(uint8_t const* key, size_t keylen)
{
  struct hmac_sha256_state state;
  uint8_t ipad[64];

  keylen = keylen > 64 ? 64 : keylen;
  memset(ipad, 0x36, 64);
  memset(state.opad, 0x5c, 64);
  for (size_t p = 0; p < keylen; p++) {
    ipad[p] ^= key[p];
    state.opad[p] ^= key[p];
  }

  state.sha256 = sha256_init();
  state.sha256 = sha256_update(state.sha256, ipad, 64);

  return state;
}

void hmac_sha256_digest(const struct hmac_sha256_state state, uint8_t* out) {
  uint8_t msg[96];
  memcpy(msg, state.opad, 64);
  sha256_digest(state.sha256, &msg[64]);

  struct sha256_state finalstate = sha256_init();
  finalstate = sha256_update_final(finalstate, msg, 96);
  sha256_digest(finalstate, out);
}
