#!/usr/bin/env python3
"""Parse board test result for Rijndael-256 T-table encrypt (multi-key-size)."""
import struct, sys

KEY_SIZES = ["128", "192", "256"]

def main():
    f = sys.argv[1] if len(sys.argv) > 1 else '/tmp/r256_result.bin'
    data = open(f, 'rb').read()

    # magic(4) + 3 * (tv_pass(4) + cycles_enc(4) + cycles_ks(4)) + ct(32)
    # = 4 + 36 + 32 = 72 bytes
    if len(data) < 72:
        print(f"ERROR: got {len(data)} bytes, need 72"); return 1

    magic = struct.unpack('<I', data[:4])[0]

    print("=" * 55)
    print("Rijndael-256 T-table Board Test Results")
    print("=" * 55)
    ok = magic == 0xDEADBEEF
    print(f"Magic:  0x{magic:08X}  {'OK' if ok else 'INCOMPLETE!'}")
    print()

    all_pass = ok
    off = 4
    for i, ksz in enumerate(KEY_SIZES):
        tv_pass, cyc_enc, cyc_ks = struct.unpack('<III', data[off:off+12])
        off += 12

        print(f"--- Key={ksz}-bit ---")
        print(f"  Encrypt:      {'PASS' if tv_pass else 'FAIL'}")
        print(f"  KS:  {cyc_ks:,} cycles")
        print(f"  Enc: {cyc_enc:,} cycles  ({cyc_enc/32:.0f} c/B)")
        print()

        if not tv_pass:
            all_pass = False

    ct = data[off:off+32]
    print(f"Last CT: {ct.hex().upper()}")
    print(f"Overall: {'ALL PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1

if __name__ == '__main__':
    sys.exit(main())
