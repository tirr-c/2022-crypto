CFLAGS = -Wall -mavx2 -msha -O3

all: sha256
sha256: sha256.o ../util.o

.PHONY: clean
clean:
	rm -f *.o sha256
