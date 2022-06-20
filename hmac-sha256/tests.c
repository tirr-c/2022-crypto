#include <stdio.h>
#include <string.h>
#include <stdalign.h>
#include <time.h>

#include "../util.h"
#include "hmac-sha256.h"

static void generate_key(uint8_t* keybuf) {
  getrandom_exact(keybuf, 32);
}

static void print_tag(uint8_t const* tag) {
  printf("  Tag:");
  for (int i = 0; i < 32; i++) {
    printf("%02x", tag[i]);
  }
  printf("\n");
}

int main() {
  int ret = 0;

  printf("Sanity check...\n");
  {
    uint8_t key[32] = {0};
    uint8_t tag[32];
    uint8_t* buf = malloc(1024);
    memset(buf, 0, 1024);

    struct hmac_sha256_state state = hmac_sha256_init(key, 32);
    state.sha256 = sha256_update_final(state.sha256, buf, 0);
    sha256_digest(state.sha256, tag);
    print_tag(tag);
    hmac_sha256_digest(state, tag);

    print_tag(tag);
    free(buf);
  }
  if (ret != 0) {
    return ret;
  }

  printf("Benchmark 1: single key, long message\n");
  {
    printf("Generating key...\n");
    uint8_t keybuf[32];
    uint8_t tag[32];
    generate_key(keybuf);

    printf("Preparing zero-filled 1 GiB buffer...\n");
    uint8_t* buf = malloc(1 * 1024 * 1024 * 1024);
    memset(buf, 0, 1 * 1024 * 1024 * 1024);

    printf("Performing authentication...\n");
    for (int i = 0; i < 4; i++) {
      struct timespec start, current;
      clock_gettime(CLOCK_MONOTONIC, &start);

      struct hmac_sha256_state state = hmac_sha256_init(keybuf, 32);
      state.sha256 = sha256_update_final(state.sha256, buf, 1 * 1024 * 1024 * 1024);
      hmac_sha256_digest(state, tag);
      clock_gettime(CLOCK_MONOTONIC, &current);

      print_tag(tag);
      current.tv_nsec -= start.tv_nsec;
      current.tv_sec -= start.tv_sec;
      if (current.tv_nsec < 0) {
        current.tv_nsec += 1000000000LL;
        current.tv_sec -= 1;
      }
      printf("Elapsed time: %jd.%09ld\n", (intmax_t) current.tv_sec, current.tv_nsec);
    }

    free(buf);
  }

  printf("\n");
  printf("Benchmark 2: single key, multiple short messages\n");
  {
    printf("Generating key...\n");
    uint8_t keybuf[32];
    generate_key(keybuf);

    int bufcount = 1024;
    printf("Preparing %d random-filled 64 byte buffer...\n", bufcount);
    uint8_t** bufs = calloc(bufcount, sizeof(uint8_t*));
    for (int i = 0; i < bufcount; i++) {
      bufs[i] = malloc(64);
      getrandom_exact(bufs[i], 64);
    }

    printf("Performing authentication...\n");

    uint8_t tag[32];
    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);
    long iter = 0;
    while (1) {
      struct hmac_sha256_state state = hmac_sha256_init(keybuf, 32);
      state.sha256 = sha256_update_final(state.sha256, bufs[iter % bufcount], 64);
      hmac_sha256_digest(state, tag);
      clock_gettime(CLOCK_MONOTONIC, &current);
      if (current.tv_sec > start.tv_sec && current.tv_nsec >= start.tv_nsec) {
        break;
      }
      iter++;
    }

    current.tv_nsec -= start.tv_nsec;
    current.tv_sec -= start.tv_sec;
    if (current.tv_nsec < 0) {
      current.tv_nsec += 1000000000LL;
      current.tv_sec -= 1;
    }
    printf("Processed 64 byte messages: %ld\n", iter);
    printf("Elapsed time: %jd.%09ld\n", (intmax_t) current.tv_sec, current.tv_nsec);

    for (int i = 0; i < bufcount; i++) {
      free(bufs[i]);
    }
    free(bufs);
  }

  printf("\n");
  printf("Benchmark 3: multiple key, multiple short messages\n");
  {
    int bufcount = 1024;

    printf("Generating %d keys...\n", bufcount);
    uint8_t** keybufs = calloc(bufcount, sizeof(uint8_t*));
    for (int i = 0; i < bufcount; i++) {
      keybufs[i] = malloc(32);
      generate_key(keybufs[i]);
    }

    printf("Preparing %d random-filled 64 byte buffer...\n", bufcount);
    uint8_t** bufs = calloc(bufcount, sizeof(uint8_t*));
    for (int i = 0; i < bufcount; i++) {
      bufs[i] = malloc(64);
      getrandom_exact(bufs[i], 64);
    }

    printf("Performing authentication...\n");

    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint8_t tag[32];
    long iter = 0;
    while (1) {
      struct hmac_sha256_state state = hmac_sha256_init(keybufs[iter % bufcount], 32);
      state.sha256 = sha256_update_final(state.sha256, bufs[iter % bufcount], 64);
      hmac_sha256_digest(state, tag);
      clock_gettime(CLOCK_MONOTONIC, &current);
      if (current.tv_sec > start.tv_sec && current.tv_nsec >= start.tv_nsec) {
        break;
      }
      iter++;
    }

    current.tv_nsec -= start.tv_nsec;
    current.tv_sec -= start.tv_sec;
    if (current.tv_nsec < 0) {
      current.tv_nsec += 1000000000LL;
      current.tv_sec -= 1;
    }
    printf("Processed 64 byte messages: %ld\n", iter);
    printf("Elapsed time: %jd.%09ld\n", (intmax_t) current.tv_sec, current.tv_nsec);

    for (int i = 0; i < bufcount; i++) {
      free(keybufs[i]);
      free(bufs[i]);
    }
    free(keybufs);
    free(bufs);
  }
  return 0;
}
