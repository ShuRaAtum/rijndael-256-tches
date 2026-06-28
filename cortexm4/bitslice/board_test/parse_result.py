#!/usr/bin/env python3
"""Parse board test result for Rijndael-256 bitslice encrypt+decrypt (multi-key-size)."""
import struct, sys

KEY_SIZES = ["128", "192", "256"]

def main():
    f = sys.argv[1] if len(sys.argv) > 1 else '/tmp/r256_result.bin'
    data = open(f, 'rb').read()

    # magic(4) + 3 * (enc_pass(4) + dec_pass(4) + cycles_enc(4)
    #   + cycles_dec(4) + ks_enc(4) + ks_dec(4)) + ct(32)
    # = 4 + 72 + 32 = 108 bytes
    if len(data) < 108:
        print(f"ERROR: got {len(data)} bytes, need 108"); return 1

    magic = struct.unpack('<I', data[:4])[0]

    print("=" * 60)
    print("Rijndael-256 Bitslice ASM Board Test Results")
    print("=" * 60)
    ok = magic == 0xDEADBEEF
    print(f"Magic:  0x{magic:08X}  {'OK' if ok else 'INCOMPLETE!'}")
    print()

    all_pass = ok
    off = 4
    for i, ksz in enumerate(KEY_SIZES):
        enc_pass, dec_pass, cyc_enc, cyc_dec, cyc_ks_enc, cyc_ks_dec = \
            struct.unpack('<IIIIII', data[off:off+24])
        off += 24

        print(f"--- Key={ksz}-bit ---")
        print(f"  Encrypt:  {'PASS' if enc_pass else 'FAIL'}")
        print(f"    KS:  {cyc_ks_enc:,} cycles")
        print(f"    Enc: {cyc_enc:,} cycles  ({cyc_enc/32:.0f} c/B)")
        print(f"  Decrypt:  {'PASS' if dec_pass else 'FAIL'}")
        print(f"    KS:  {cyc_ks_dec:,} cycles")
        print(f"    Dec: {cyc_dec:,} cycles  ({cyc_dec/32:.0f} c/B)")
        print()

        if not enc_pass or not dec_pass:
            all_pass = False

    ct = data[off:off+32]
    print(f"Last CT: {ct.hex().upper()}")
    print(f"Overall: {'ALL PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1

if __name__ == '__main__':
    sys.exit(main())
