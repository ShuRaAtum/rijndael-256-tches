# Host-side verification for native C implementation
COMMON = ../../common
CFLAGS = -O3 -Wall -I$(COMMON)

verify: verify_host.c rijndael256_native.c rijndael256_native.h rijndael256_sbox.h $(COMMON)/test_vectors.h
	gcc $(CFLAGS) -o $@ verify_host.c rijndael256_native.c
	./$@

clean:
	rm -f verify

.PHONY: verify clean
