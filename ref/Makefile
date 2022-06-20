CFLAGS = -Wall -m32 -march=native -O3
ASFLAGS = --32
LDFLAGS = -m32

poly1305aes_athlon_test: tests.o \
	aes_athlon.o aes_athlon_constants.o poly1305_athlon.o poly1305_athlon_constants.o \
	poly1305aes_athlon_clamp.o poly1305aes_athlon_authenticate.o poly1305aes_athlon_verify.o poly1305aes_athlon_isequal.o
	$(CC) $(LDFLAGS) -o $@ $(LDLIBS) $^

.PHONY: test
test: poly1305aes_athlon_test
	./poly1305aes_athlon_test

.PHONY: clean
clean:
	rm -f poly1305aes_athlon_test *.o
