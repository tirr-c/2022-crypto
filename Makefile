all: poly1305 hmac-sha256

.PHONY: poly1305 hmac-sha256
poly1305 hmac-sha256:
	$(MAKE) -C $@

.PHONY: clean
clean:
	$(MAKE) -C poly1305 clean
	$(MAKE) -C hmac-sha256 clean
	rm -f *.o
