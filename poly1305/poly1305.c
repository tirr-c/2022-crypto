#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/random.h>
#include <immintrin.h>

#include "../util.h"

#define AES_ONCE(s, k, rcon, intr) { \
  __m128i rk; \
  rk = _mm_aeskeygenassist_si128(k, rcon); \
  rk = _mm_shuffle_epi32(rk, 0xff); \
  rk = _mm_xor_si128(rk, k); \
  k = _mm_slli_si128(k, 4); \
  rk = _mm_xor_si128(rk, k); \
  k = _mm_slli_si128(k, 4); \
  rk = _mm_xor_si128(rk, k); \
  k = _mm_slli_si128(k, 4); \
  rk = _mm_xor_si128(rk, k); \
  k = rk; \
  s = intr(s, k); \
}

int getrandom_exact(uint8_t* buf, size_t len) {
  size_t count = 0;
  while (count < len) {
    ssize_t ret = getrandom(buf + count, len - count, 0);
    if (ret < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    count += ret;
  }
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <keyfile> <messagefile>\n", argv[0]);
    return EXIT_FAILURE;
  }

  int keyfd = open(argv[1], O_RDONLY);
  if (keyfd == -1) {
    fprintf(stderr, "%s: Failed to open keyfile %s: %s\n", argv[0], argv[1], strerror(errno));
    return EXIT_FAILURE;
  }

  uint8_t key[32];
  {
    ssize_t count = read_exact(keyfd, key, 32);
    if (count < 0) {
      fprintf(stderr, "%s: Failed to read keyfile %s: %s\n", argv[0], argv[1], strerror(errno));
      return EXIT_FAILURE;
    }
    if (count != 32) {
      fprintf(stderr, "%s: Invalid keyfile %s: key is shorter than 32 bytes\n", argv[0], argv[1]);
      return EXIT_FAILURE;
    }

    int invalid = (key[0x13] & 0xf0)
      + (key[0x14] & 0x03) + (key[0x17] & 0xf0)
      + (key[0x18] & 0x03) + (key[0x1b] & 0xf0)
      + (key[0x1c] & 0x03) + (key[0x1f] & 0xf0);
    if (invalid) {
      fprintf(stderr, "%s: Invalid keyfile %s: some bits are not zero\n", argv[0], argv[1]);
      return EXIT_FAILURE;
    }
  }
  close(keyfd);

  int msgfd;
  if (argv[2][0] == '-' && argv[2][1] == 0) {
    msgfd = STDIN_FILENO;
  } else {
    msgfd = open(argv[2], O_RDONLY);
    if (msgfd == -1) {
      fprintf(stderr, "%s: Failed to open message %s: %s\n", argv[0], argv[2], strerror(errno));
      return EXIT_FAILURE;
    }
  }

  /**
   * Key preparation
   */
  __m128i tr0 = _mm_castps_si128(_mm_broadcast_ss((float const*) &key[16])); // r0, r0, r0, r0
  __m256i r0 = _mm256_cvtepu32_epi64(tr0);

  __m128i tr1 = _mm_castps_si128(_mm_broadcast_ss((float const*) &key[20]));
  __m128i shiftparam = _mm_set_epi32(0, 0, 0, 2);
  __m128i mulparam = _mm_set_epi32(1, 1, 1, 5);
  tr1 = _mm_srlv_epi32(tr1, shiftparam);
  tr1 = _mm_mullo_epi32(tr1, mulparam); // r1, r1, r1, 5/4 r1
  __m256i r1 = _mm256_cvtepu32_epi64(tr1);

  __m128i tr2 = _mm_castps_si128(_mm_broadcast_ss((float const*) &key[24]));
  shiftparam = _mm_insert_epi32(shiftparam, 2, 1);
  mulparam = _mm_insert_epi32(mulparam, 5, 1);
  tr2 = _mm_srlv_epi32(tr2, shiftparam);
  tr2 = _mm_mullo_epi32(tr2, mulparam); // r2, r2, 5/4 r2, 5/4 r2
  __m256i r2 = _mm256_cvtepu32_epi64(tr2);

  __m128i tr3 = _mm_castps_si128(_mm_broadcast_ss((float const*) &key[28]));
  shiftparam = _mm_insert_epi32(shiftparam, 2, 2);
  mulparam = _mm_insert_epi32(mulparam, 5, 2);
  tr3 = _mm_srlv_epi32(tr3, shiftparam);
  tr3 = _mm_mullo_epi32(tr3, mulparam); // r3, 5/4 r3, 5/4 r3, 5/4 r3
  __m256i r3 = _mm256_cvtepu32_epi64(tr3);

  /**
   * Compute AES_k(n)
   */
  uint8_t nonce[16];
  getrandom_exact(nonce, sizeof(nonce));

  __m128i n = _mm_load_si128((__m128i const*) nonce);
  __m128i k = _mm_load_si128((__m128i const*) key);

  __m128i aes_n = _mm_xor_si128(n, k);
  AES_ONCE(aes_n, k, 0x01, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x02, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x04, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x08, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x10, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x20, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x40, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x80, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x1b, _mm_aesenc_si128);
  AES_ONCE(aes_n, k, 0x36, _mm_aesenclast_si128);

  /**
   * Main loop
   * Repetedly computes h <- r(h + c_i)
   */
  size_t bufsize = 32768;
  uint8_t* buf = malloc(bufsize);
  __m256i h = _mm256_setzero_si256();
  uint8_t* current = buf + bufsize;
  uint8_t* eob = NULL;
  while (current != eob) {
    if (current == buf + bufsize) {
      size_t read_count = read_exact(STDIN_FILENO, buf, bufsize);
      if (read_count < sizeof(buf)) {
        size_t eob_offset = (read_count + 15) / 16 * 16;
        if (eob_offset != read_count) {
          buf[read_count] = 1;
          read_count++;
        }

        eob = buf + eob_offset;
        memset(&buf[read_count], 0, eob_offset - read_count);
      }

      current = buf;
      if (current == eob) {
        break;
      }
    }

    __m128i data128 = _mm_load_si128((__m128i const *) current);
    __m256i data = _mm256_cvtepu32_epi64(data128);
    if (eob - current >= 16) {
      data = _mm256_insert_epi32(data, 1, 7);
    }
    h = _mm256_add_epi64(h, data); // h := h + c

    __m256i hu = _mm256_srli_epi64(h, 32);
    __m256i ml, mu, ret;

    // 0
    ret = _mm256_mul_epu32(h, r0);
    mu = _mm256_mul_epu32(hu, r0);
    mu = _mm256_slli_epi64(mu, 32);
    ret = _mm256_add_epi32(ret, mu);

    // 1
    h = _mm256_permute4x64_epi64(h, 0x93); // 10 01 00 11
    hu = _mm256_permute4x64_epi64(hu, 0x93);
    ml = _mm256_mul_epu32(h, r1);
    ret = _mm256_add_epi64(ret, ml);
    mu = _mm256_mul_epu32(hu, r1);
    mu = _mm256_slli_epi64(mu, 32);
    ret = _mm256_add_epi32(ret, mu);

    // 2
    h = _mm256_permute4x64_epi64(h, 0x93);
    hu = _mm256_permute4x64_epi64(hu, 0x93);
    ml = _mm256_mul_epu32(h, r2);
    ret = _mm256_add_epi64(ret, ml);
    mu = _mm256_mul_epu32(hu, r2);
    mu = _mm256_slli_epi64(mu, 32);
    ret = _mm256_add_epi32(ret, mu);

    // 3
    h = _mm256_permute4x64_epi64(h, 0x93);
    hu = _mm256_permute4x64_epi64(hu, 0x93);
    ml = _mm256_mul_epu32(h, r3);
    ret = _mm256_add_epi64(ret, ml);
    mu = _mm256_mul_epu32(hu, r3);
    mu = _mm256_slli_epi64(mu, 32);
    ret = _mm256_add_epi32(ret, mu);

    // now ret := r * h
    // do carry
    __m256i shiftparam = _mm256_set_epi64x(34, 32, 32, 32);
    __m256i mulparam = _mm256_set_epi64x(5, 1, 1, 1);
    hu = _mm256_srlv_epi64(ret, shiftparam);
    hu = _mm256_mul_epu32(hu, mulparam);
    hu = _mm256_permute4x64_epi64(hu, 0x93);
    __m256i mask = _mm256_set1_epi64x(0xffffffffLL);
    mask = _mm256_insert_epi32(mask, 0x03, 7);
    ret = _mm256_and_si256(ret, mask);
    h = _mm256_add_epi64(ret, hu);

    current += 0x10;
  }

  // Fully reduce in 2^130-5
  unsigned long long h0 = _mm256_extract_epi64(h, 0);
  unsigned long long h1 = _mm256_extract_epi64(h, 1);
  unsigned long long h2 = _mm256_extract_epi64(h, 2);
  unsigned long long h3 = _mm256_extract_epi64(h, 3);
  h0 += (h3 >> 34) * 5;
  h3 &= 0x3ffffffffULL;
  h1 += (h0 >> 32);
  h0 &= 0xffffffffULL;
  h2 += (h1 >> 32);
  h1 &= 0xffffffffULL;
  h3 += (h2 >> 32);
  h2 &= 0xffffffffULL;

  // Need to subtract 2^130-5 if the result >= 2^130-5
  // We do this by adding 5 and taking lower 130 bits, when h >= 2^130-5
  // After that we add AES_k(n)
  int need_subtract = (h3 == 0x3ffffffffULL) & (h2 == 0xffffffffULL) & (h1 == 0xffffffffULL) & (h0 >= 0xfffffffbULL);
  h0 += need_subtract * 5 + (unsigned int) _mm_extract_epi32(aes_n, 0);
  h1 += (h0 >> 32) + (unsigned int) _mm_extract_epi32(aes_n, 1);
  h2 += (h1 >> 32) + (unsigned int) _mm_extract_epi32(aes_n, 2);
  h3 += (h2 >> 32) + (unsigned int) _mm_extract_epi32(aes_n, 3);

  // Concat
  uint32_t o0 = (uint32_t) h0;
  uint32_t o1 = (uint32_t) h1;
  uint32_t o2 = (uint32_t) h2;
  uint32_t o3 = (uint32_t) h3;

  printf("Nonce:");
  for (int i = 0; i < 16; i++) {
    printf(" %02x", nonce[i]);
  }
  printf("\n");
  printf("MAC: %08x%08x%08x%08x\n", o3, o2, o1, o0);

  free(buf);
  return 0;
}
