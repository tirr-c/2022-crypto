CFLAGS = -Wall -mavx2 -msha -O3

all: sha256
hmac-sha256: main.o sha256.o hmac-sha256.o ../util.o
	$(CC) $(LDFLAGS) -o $@ $(LDLIBS) $^

.PHONY: test
test: hmac-sha256-test
	./hmac-sha256-test
hmac-sha256-test: tests.o sha256.o hmac-sha256.o ../util.o
	$(CC) $(LDFLAGS) -o $@ $(LDLIBS) $^

.PHONY: clean
clean:
	rm -f *.o hmac-sha256 hmac-sha256-test
