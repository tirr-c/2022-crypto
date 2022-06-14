#ifndef __UTIL_H
#define __UTIL_H

#include <stdlib.h>
#include <stdint.h>

extern int getrandom_exact(uint8_t* buf, size_t len);
extern ssize_t read_exact(int fd, void* buf, size_t count);
extern int is_equal_const(const uint8_t a[16], const uint8_t b[16]);

#endif
