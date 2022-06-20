#ifndef __SHA256_H
#define __SHA256_H

#include <stdint.h>
#include <immintrin.h>

struct sha256_state {
  __m128i abef;
  __m128i cdgh;
  uint64_t len;
  uint64_t padding[3];
};

static struct sha256_state sha256_init() {
  struct sha256_state state;
  state.abef = _mm_set_epi32(0x6a09e667, 0xbb67ae85, 0x510e527f, 0x9b05688c);
  state.cdgh = _mm_set_epi32(0x3c6ef372, 0xa54ff53a, 0x1f83d9ab, 0x5be0cd19);
  state.len = 0;
  return state;
}

extern struct sha256_state
sha256_update(struct sha256_state state, uint8_t const* buf, size_t len);

extern struct sha256_state
sha256_update_final(struct sha256_state state, uint8_t const* buf, size_t len);

extern void sha256_digest(struct sha256_state state, uint8_t* out);

#endif
