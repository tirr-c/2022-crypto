#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <immintrin.h>
#include <stdalign.h>

#include "sha256.h"

alignas(alignof(__m128i))
static const uint32_t K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static struct sha256_state
sha256_update_single(struct sha256_state state, uint8_t const* block)
{
  __m128i abef = state.abef;
  __m128i cdgh = state.cdgh;
  __m128i w[4];
  {
    __m128i const* buf128 = (__m128i const*) block;
    __m128i shuffle = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
    w[0] = _mm_loadu_si128(buf128 + 0);
    w[1] = _mm_loadu_si128(buf128 + 1);
    w[2] = _mm_loadu_si128(buf128 + 2);
    w[3] = _mm_loadu_si128(buf128 + 3);
    w[0] = _mm_shuffle_epi8(w[0], shuffle);
    w[1] = _mm_shuffle_epi8(w[1], shuffle);
    w[2] = _mm_shuffle_epi8(w[2], shuffle);
    w[3] = _mm_shuffle_epi8(w[3], shuffle);
  }

  for (int i = 0; i < 16; i++) {
    // run 2+2 rounds
    __m128i kw = _mm_load_si128((const __m128i *) &K[i * 4]);
    kw = _mm_add_epi32(kw, w[0]);
    cdgh = _mm_sha256rnds2_epu32(cdgh, abef, kw);
    kw = _mm_shuffle_epi32(kw, 0xee);
    abef = _mm_sha256rnds2_epu32(abef, cdgh, kw);

    __m128i w9c = _mm_castps_si128(_mm_move_ss(_mm_castsi128_ps(w[2]), _mm_castsi128_ps(w[3])));
    __m128i next = _mm_sha256msg1_epu32(w[0], w[1]);
    w9c = _mm_shuffle_epi32(w9c, 0x39);
    next = _mm_add_epi32(next, w9c);
    next = _mm_sha256msg2_epu32(next, w[3]);
    w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = next;
  }

  state.abef = _mm_add_epi32(state.abef, abef);
  state.cdgh = _mm_add_epi32(state.cdgh, cdgh);
  state.len += 64;
  return state;
}

static struct sha256_state
sha256_update_lastblock(struct sha256_state state, uint8_t const* block, size_t len)
{
  if (len > 0x40) {
    len = 0x40;
  }
  state.len += len;
  uint64_t total_len = state.len;

  uint8_t buf[128] = {0};
  memcpy(buf, block, len);
  buf[len] = 0x80;

  uint8_t* eob = buf + 0x40;
  if (len + 1 > 0x40 - 8) {
    eob = buf + 0x80;
  }

  for (int i = 1; i <= 8; i++) {
    eob[-i] = total_len & 0xff;
    total_len >>= 8;
  }

  state = sha256_update_single(state, buf);
  if (eob == buf + 0x80) {
    state = sha256_update_single(state, buf + 0x40);
  }
  return state;
}

struct sha256_state
sha256_update(struct sha256_state state, uint8_t const* buf, size_t len)
{
  len &= ~0x3f;

  uint8_t const* eob = buf + len;
  while (buf < eob) {
    state = sha256_update_single(state, buf);
    buf += 64;
  }

  return state;
}

struct sha256_state
sha256_update_final(struct sha256_state state, uint8_t const* buf, size_t len)
{
  uint8_t const* eob = buf + (len & ~0x3f);
  while (buf < eob) {
    state = sha256_update_single(state, buf);
    buf += 64;
  }
  return sha256_update_lastblock(state, buf, len & 0x3f);
}

void sha256_digest(struct sha256_state state, uint8_t* out) {
  alignas(alignof(__m128i)) uint32_t buf[8]; // febahgdc
  _mm_store_si128((__m128i *) buf, state.abef);
  _mm_store_si128((__m128i *) (buf + 4), state.cdgh);
  for (int i = 0; i < 8; i++) {
    buf[i] = __bswap_32(buf[i]);
  }

  uint32_t* out32 = (uint32_t*) out;
  out32[0] = buf[3];
  out32[1] = buf[2];
  out32[2] = buf[7];
  out32[3] = buf[6];
  out32[4] = buf[1];
  out32[5] = buf[0];
  out32[6] = buf[5];
  out32[7] = buf[4];
}
