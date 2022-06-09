#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

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
