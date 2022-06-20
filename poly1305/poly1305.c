#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "../util.h"
#include "poly1305.h"

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

int poly1305_prepare_key(const uint8_t key[32], struct poly1305_key* out) {
  int invalid = (key[0x13] & 0xf0)
    + (key[0x14] & 0x03) + (key[0x17] & 0xf0)
    + (key[0x18] & 0x03) + (key[0x1b] & 0xf0)
    + (key[0x1c] & 0x03) + (key[0x1f] & 0xf0);
  if (invalid) {
    return -1;
  }

  __m128i k = _mm_loadu_si128((__m128i const*) key);
  __m128i r = _mm_loadu_si128((__m128i const*) (key + 16));
  __m128i r54 = _mm_srli_epi32(r, 2);
  r54 = _mm_add_epi32(r54, r);
  __m256i rr = _mm256_set_m128i(r54, r);
  // now rr = (r0, r1, r2, r3, 5/4 r0 [inexact, unused], 5/4 r1, 5/4 r2, 5/4 r3)

  // (r0, r0, r0, r0, 5/4 r1, r1, r1, r1)
  __m256i r0r1 = _mm256_permutevar8x32_epi32(rr, _mm256_set_epi32(1, 1, 1, 5, 0, 0, 0, 0));
  __m128i r0 = _mm256_extractf128_si256(r0r1, 0);
  __m128i r1 = _mm256_extractf128_si256(r0r1, 1);
  __m256i r2r3 = _mm256_permutevar8x32_epi32(rr, _mm256_set_epi32(3, 7, 7, 7, 2, 2, 6, 6));
  __m128i r2 = _mm256_extractf128_si256(r2r3, 0);
  __m128i r3 = _mm256_extractf128_si256(r2r3, 1);

  _mm_store_si128(&out->r0, r0);
  _mm_store_si128(&out->r1, r1);
  _mm_store_si128(&out->r2, r2);
  _mm_store_si128(&out->r3, r3);
  _mm_store_si128(&out->aes_k, k);

  return 0;
}

static inline __m128i poly1305_aes_k(__m128i k, __m128i n) {
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
  return aes_n;
}

static inline __m256i
poly1305_round(__m256i h, __m256i c, __m256i r0, __m256i r1, __m256i r2, __m256i r3)
{
  // h <- h + c
  h = _mm256_add_epi64(h, c);

  // perform parallel carry
  // here we compute 5*h3[63:34] = (1 + 4)*h3[63:34], as we're on p=2^130-5
  // then rotate left once, in order to move carries to the right place
  __m256i carry = _mm256_srlv_epi64(h, _mm256_set_epi64x(34, 32, 32, 32));
  __m256i carry2 = _mm256_sllv_epi64(carry, _mm256_set_epi64x(2, 64, 64, 64));
  carry = _mm256_add_epi64(carry, carry2);
  carry = _mm256_permute4x64_epi64(carry, 0x93);

  // mask out carries
  __m256i mask = _mm256_set_epi64x(0x3ffffffffLL, 0xffffffffLL, 0xffffffffLL, 0xffffffffLL);
  h = _mm256_and_si256(h, mask);
  h = _mm256_add_epi64(h, carry);

  // AVX-2 doesn't have u64*u32 multiplication, so we must split 64-bit integers into two parts.
  // We have 4x u32*u32 -> u64 mult (vpmuludq), so split into two 32-bit integers.
  // Basically we compute h[31:0]*r[31:0] + ((h[63:32]*r[31:0]) << 32), then it's equivalent to
  // h[63:0]*r[31:0]

  // hu <- 4x h[63:32], h <- 4x h[31:0] (do nothing for h, since vpmuludq ignores upper 32 bits)
  __m256i hu = _mm256_srli_epi64(h, 32);
  __m256i ml, mu, ret;

  // ret <- (r0*h0, r0*h1, r0*h2, r0*h3)
  ret = _mm256_mul_epu32(h, r0);
  mu = _mm256_mul_epu32(hu, r0);
  mu = _mm256_slli_epi64(mu, 32);
  ret = _mm256_add_epi32(ret, mu);

  // ret <- ret + (5/4 r1*h3, r1*h0, r1*h1, r1*h2)
  h = _mm256_permute4x64_epi64(h, 0x93); // 10 01 00 11; rotate h left once
  hu = _mm256_permute4x64_epi64(hu, 0x93);
  ml = _mm256_mul_epu32(h, r1);
  ret = _mm256_add_epi64(ret, ml);
  mu = _mm256_mul_epu32(hu, r1);
  mu = _mm256_slli_epi64(mu, 32);
  ret = _mm256_add_epi32(ret, mu);

  // ret <- ret + (5/4 r2*h2, 5/4 r2*h3, r2*h0, r2*h1)
  h = _mm256_permute4x64_epi64(h, 0x93);
  hu = _mm256_permute4x64_epi64(hu, 0x93);
  ml = _mm256_mul_epu32(h, r2);
  ret = _mm256_add_epi64(ret, ml);
  mu = _mm256_mul_epu32(hu, r2);
  mu = _mm256_slli_epi64(mu, 32);
  ret = _mm256_add_epi32(ret, mu);

  // ret <- ret + (5/4 r3*h1, 5/4 r3*h2, 5/4 r3*h3, r3*h0)
  h = _mm256_permute4x64_epi64(h, 0x93);
  hu = _mm256_permute4x64_epi64(hu, 0x93);
  ml = _mm256_mul_epu32(h, r3);
  ret = _mm256_add_epi64(ret, ml);
  mu = _mm256_mul_epu32(hu, r3);
  mu = _mm256_slli_epi64(mu, 32);
  ret = _mm256_add_epi32(ret, mu);

  return ret;
}

static __m256i poly1305_update(struct poly1305_key const* key,
                               __m256i h,
                               uint8_t const* buf,
                               size_t len)
{
  __m256i r0 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r0));
  __m256i r1 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r1));
  __m256i r2 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r2));
  __m256i r3 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r3));
  uint8_t const* current = buf;
  uint8_t const* eob = buf + (len & ~0x0f);
  while (current != eob) {
    // load 4x 32-bit messages and zero-extend to 64-bit
    __m128i c128 = _mm_loadu_si128((__m128i const *) current);
    __m256i c = _mm256_cvtepu32_epi64(c128);
    c = _mm256_insert_epi32(c, 1, 7); // per-message padding

    h = poly1305_round(h, c, r0, r1, r2, r3);
    current += 0x10;
  }

  return h;
}

static void poly1305_finalize(struct poly1305_key const* key,
                              __m256i h,
                              uint8_t const* buf,
                              size_t len,
                              struct poly1305_tag* out)
{
  uint8_t last_message_buf[16];
  uint8_t* last_message = NULL;
  uint8_t const* current = buf;
  uint8_t const* eob = buf + len;
  if (len % 16 != 0) {
    size_t from = len & ~0x0f;
    size_t last_len = len - from;
    memcpy(last_message_buf, &buf[from], last_len);
    last_message_buf[last_len] = 1;
    memset(&last_message_buf[last_len + 1], 0, 16 - last_len - 1);
    last_message = last_message_buf;
    eob = buf + from;
  }

  uint32_t* tag = (uint32_t*) out->tag;
  __m256i r0 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r0));
  __m256i r1 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r1));
  __m256i r2 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r2));
  __m256i r3 = _mm256_cvtepu32_epi64(_mm_load_si128(&key->r3));
  while (1) {
    // load 4x 32-bit messages and zero-extend to 64-bit
    __m256i c;
    if (current < eob) {
      __m128i c128 = _mm_loadu_si128((__m128i const *) current);
      c = _mm256_cvtepu32_epi64(c128);
      c = _mm256_insert_epi32(c, 1, 7); // per-message padding
    } else if (last_message != NULL) {
      __m128i data128 = _mm_loadu_si128((__m128i const *) last_message);
      c = _mm256_cvtepu32_epi64(data128);
      last_message = NULL;
    } else {
      break;
    }

    h = poly1305_round(h, c, r0, r1, r2, r3);
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
  __m128i k = _mm_load_si128(&key->aes_k);
  __m128i n = _mm_loadu_si128((__m128i const*) &out->nonce);
  __m128i aes_n = poly1305_aes_k(k, n);
  int need_subtract = (h3 > 0x3ffffffffULL) |
    ((h3 == 0x3ffffffffULL) & (h2 == 0xffffffffULL) & (h1 == 0xffffffffULL) & (h0 >= 0xfffffffbULL));
  h0 += need_subtract * 5 + (unsigned int) _mm_extract_epi32(aes_n, 0);
  tag[0] = h0;
  h1 += (h0 >> 32) + (unsigned int) _mm_extract_epi32(aes_n, 1);
  tag[1] = h1;
  h2 += (h1 >> 32) + (unsigned int) _mm_extract_epi32(aes_n, 2);
  tag[2] = h2;
  h3 += (h2 >> 32) + (unsigned int) _mm_extract_epi32(aes_n, 3);
  tag[3] = h3;
}

void poly1305_auth_once(struct poly1305_key const* key,
                        uint8_t const* buf,
                        size_t len,
                        struct poly1305_tag* out)
{
  poly1305_finalize(key, _mm256_setzero_si256(), buf, len, out);
}

ssize_t poly1305_auth_stream(struct poly1305_key const* key,
                             int fd,
                             struct poly1305_tag* out)
{
  size_t total_len = 0;
  const size_t bufsize = 32768;
  uint8_t* buf = malloc(bufsize);
  __m256i h = _mm256_setzero_si256();
  while (1) {
    size_t read_count = read_exact(fd, buf, bufsize);
    if (read_count < 0) {
      int t = errno;
      free(buf);
      errno = t;
      return read_count;
    }

    total_len += read_count;
    if (read_count < bufsize) {
      poly1305_finalize(key, h, buf, read_count, out);
      break;
    } else {
      h = poly1305_update(key, h, buf, read_count);
    }
  }

  free(buf);
  return total_len;
}
