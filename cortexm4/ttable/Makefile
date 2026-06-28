# Host-side verification for T-table implementation
COMMON = ../../common
CFLAGS = -O3 -Wall -I$(COMMON)

verify: verify_host.c rijndael256_ttable.c rijndael256_ttable.h rijndael256_tables.h $(COMMON)/test_vectors.h
	gcc $(CFLAGS) -o $@ verify_host.c rijndael256_ttable.c
	./$@

clean:
	rm -f verify

.PHONY: verify clean
