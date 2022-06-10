CFLAGS = -Wall -mavx2 -maes -O3

all: poly1305
poly1305: main.o poly1305.o ../util.o
	$(CC) $(LDFLAGS) -o $@ $(LDLIBS) $^

.PHONY: test
test: poly1305-test
	./poly1305-test
poly1305-test: tests.o poly1305.o ../util.o
	$(CC) $(LDFLAGS) -o $@ $(LDLIBS) $^

.PHONY: clean
clean:
	rm -f *.o poly1305 poly1305-test
