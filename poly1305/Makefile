CFLAGS = -Wall -mavx2 -maes -O3

all: poly1305
poly1305: poly1305.o ../util.o

.PHONY: clean
clean:
	rm -f *.o poly1305
