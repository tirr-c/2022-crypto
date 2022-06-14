#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <immintrin.h>
#include <sys/random.h>

#include "util.h"

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

ssize_t read_exact(int fd, void* buf, size_t count) {
  size_t read_count = 0;
  while (read_count < count) {
    ssize_t ret = read(fd, buf + read_count, count - read_count);
    if (ret == 0) break;
    if (ret < 0) {
      if (errno == EINTR) continue;
      return ret;
    }
    read_count += ret;
  }
  return read_count;
}

int is_equal_const(const uint8_t a[16], const uint8_t b[16]) {
  __m128i va = _mm_loadu_si128((__m128i const*) a);
  __m128i vb = _mm_loadu_si128((__m128i const*) b);
  __m128i r = _mm_xor_si128(va, vb);
  unsigned long long sum = _mm_extract_epi64(r, 0) | _mm_extract_epi64(r, 1);
  return sum == 0;
}
