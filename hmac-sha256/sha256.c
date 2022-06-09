#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <immintrin.h>

#include "../util.h"

#define sha256_load_message(buf, target) { \
  __m128i const* buf128 = (__m128i const*) buf; \
  __m128i shuffle = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203); \
  target[0] = _mm_load_si128(buf128 + 0); \
  target[1] = _mm_load_si128(buf128 + 1); \
  target[2] = _mm_load_si128(buf128 + 2); \
  target[3] = _mm_load_si128(buf128 + 3); \
  target[0] = _mm_shuffle_epi8(target[0], shuffle); \
  target[1] = _mm_shuffle_epi8(target[1], shuffle); \
  target[2] = _mm_shuffle_epi8(target[2], shuffle); \
  target[3] = _mm_shuffle_epi8(target[3], shuffle); \
}

#define sha256_message_next(w) { \
  __m128i w9c = _mm_castps_si128(_mm_move_ss(_mm_castsi128_ps(w[2]), _mm_castsi128_ps(w[3]))); \
  __m128i next = _mm_sha256msg1_epu32(w[0], w[1]); \
  w9c = _mm_shuffle_epi32(w9c, 0x39); \
  next = _mm_add_epi32(next, w9c); \
  next = _mm_sha256msg2_epu32(next, w[3]); \
  w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = next; \
}

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

int main() {
  __m128i abef = _mm_set_epi32(0x6a09e667, 0xbb67ae85, 0x510e527f, 0x9b05688c);
  __m128i cdgh = _mm_set_epi32(0x3c6ef372, 0xa54ff53a, 0x1f83d9ab, 0x5be0cd19);

  int need_empty_round = 0;
  size_t len = 0;
  uint8_t buf[4096];
  uint8_t* current = buf + 4096;
  uint8_t* eob = NULL;
  while (current != eob) {
    if (current == buf + 4096) {
      if (need_empty_round) {
        eob = buf + 64;
        memset(buf, 0, 64);
      } else {
        size_t read_count = read_exact(STDIN_FILENO, buf, sizeof(buf));
        len += read_count;
        if (read_count < sizeof(buf)) {
          len *= 8;
          buf[read_count] = 0x80;
          read_count++;

          size_t eob_offset = (read_count + 8 + 63) / 64 * 64;
          if (eob_offset > sizeof(buf)) {
            eob_offset = sizeof(buf);
            need_empty_round = 1;
          } else {
            eob = buf + eob_offset;
          }
          memset(&buf[read_count], 0, eob_offset - read_count);
        }
      }

      current = buf;
      if (eob) {
        for (int i = 1; i <= 8; i++) {
          eob[-i] = len & 0xff;
          len >>= 8;
        }
      }
    }

    __m128i h0145 = abef;
    __m128i h2367 = cdgh;
    __m128i w[4];
    sha256_load_message(current, w);
    for (int i = 0; i < 16; i++) {
      // run 2+2 rounds
      __m128i kw = _mm_load_si128((const __m128i *) &K[i * 4]);
      kw = _mm_add_epi32(kw, w[0]);
      cdgh = _mm_sha256rnds2_epu32(cdgh, abef, kw);
      kw = _mm_shuffle_epi32(kw, 0xee);
      abef = _mm_sha256rnds2_epu32(abef, cdgh, kw);
      sha256_message_next(w);
    }

    abef = _mm_add_epi32(h0145, abef);
    cdgh = _mm_add_epi32(h2367, cdgh);

    current += 64;
  }

  uint32_t out[8]; // febahgdc
  _mm_store_si128((__m128i *) out, abef);
  _mm_store_si128((__m128i *) (out + 4), cdgh);
  printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", out[3], out[2], out[7], out[6], out[1], out[0], out[5], out[4]);
  return 0;
}
