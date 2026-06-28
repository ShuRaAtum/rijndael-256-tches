# Host-side verification for T-table ASM (uses C mirror of ASM logic)
COMMON = ../../common
CFLAGS = -O3 -Wall -I$(COMMON)

verify: verify_host.c rijndael256_impl.c rijndael256_ttable_asm.h $(COMMON)/test_vectors.h
	gcc $(CFLAGS) -o $@ verify_host.c rijndael256_impl.c
	./$@

clean:
	rm -f verify

.PHONY: verify clean
