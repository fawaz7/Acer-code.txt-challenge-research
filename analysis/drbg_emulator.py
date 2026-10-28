#!/usr/bin/env python3
"""Emulate the firmware DRBG (RandomSeed + RandomBytes) to study the 8 digits.

This runs the *real* bytes of the InsydeH2O crypto module under Unicorn, exactly
as the firmware would, and demonstrates the central finding of this study:

  * the DRBG is deterministic given its FULL seed, but
  * its output depends on a 30-byte NONCE taken from an uninitialised stack
    buffer in RandomSeed. On real hardware that buffer holds the residue of the
    preceding `GetTime` call (driven by RDTSC + allocator state), which is not
    reconstructable from a saved `code.txt`. See docs/02-cryptanalysis.md.

The demo seeds with a 16-byte EFI_TIME (as the generator does) and shows the
digits move when the emulated stack fill changes — i.e. the timestamp alone does
not determine the output.

Bring your own firmware module. No vendor binary is distributed with this repo.

Usage:
    python3 drbg_emulator.py /path/to/CryptoServiceRuntimeDxe.efi

Requires: pip install unicorn   (tested with unicorn 2.1.x)

Addresses below are for one specific build (SHA-256 7419ef95...). They WILL
differ on other models/versions — locate RandomSeed/RandomBytes and the
AllocatePool/FreePool wrappers in your own module and update the constants.
"""
import argparse
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UcError
from unicorn.x86_const import (
    UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RIP,
)

# --- build-specific offsets (image base 0) -------------------------------------
RANDOM_SEED = 0xC640   # bool RandomSeed(void *seed, int seed_len)
RANDOM_BYTES = 0xC604  # bool RandomBytes(void *out, int n)
ALLOC = 0x7170         # internal AllocatePool wrapper: rcx=size -> rax=ptr
FREE = 0x7148          # internal FreePool wrapper:     rcx=ptr
# -------------------------------------------------------------------------------

IMG = 0x00000000
STACK = 0x70000000
STACK_SZ = 0x100000
HEAP = 0x80000000
HEAP_SZ = 0x1000000
STOP = 0x0F000000      # sentinel return address


class Drbg:
    def __init__(self, path: str, stack_fill: int = 0x00):
        self.img = open(path, "rb").read()
        self.stack_fill = stack_fill & 0xFF
        self._boot()

    def _boot(self):
        uc = self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        size = (len(self.img) + 0xFFF) & ~0xFFF
        uc.mem_map(IMG, max(size, 0x40000))
        uc.mem_write(IMG, self.img)
        uc.mem_map(STACK, STACK_SZ)
        uc.mem_map(HEAP, HEAP_SZ)
        uc.mem_map(STOP & ~0xFFF, 0x1000)
        # fill the whole stack with a chosen byte so we can show nonce dependence
        uc.mem_write(STACK, bytes([self.stack_fill]) * STACK_SZ)
        self.brk = HEAP + 0x1000
        uc.hook_add(UC_HOOK_CODE, self._svc, begin=ALLOC, end=ALLOC)
        uc.hook_add(UC_HOOK_CODE, self._svc, begin=FREE, end=FREE)

    def _svc(self, uc, addr, size, _ud):
        ret = struct.unpack("<Q", uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
        if addr == ALLOC:
            n = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            p = self.brk
            self.brk = (self.brk + n + 0x3F) & ~0x3F
            uc.mem_write(p, b"\x00" * n)
            uc.reg_write(UC_X86_REG_RAX, p)
        else:  # FREE
            uc.reg_write(UC_X86_REG_RAX, 0)
        uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def _call(self, fn, rcx=0, rdx=0, r8=0, r9=0):
        uc = self.uc
        sp = STACK + STACK_SZ - 0x400
        uc.mem_write(sp, struct.pack("<Q", STOP))
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RCX, rcx)
        uc.reg_write(UC_X86_REG_RDX, rdx)
        uc.reg_write(UC_X86_REG_R8, r8)
        uc.reg_write(UC_X86_REG_R9, r9)
        uc.emu_start(fn, STOP)
        return uc.reg_read(UC_X86_REG_RAX)

    def bytes_for_seed(self, seed: bytes, n: int = 8) -> bytes:
        self._boot()  # fresh state per call
        sbuf, obuf = self.brk, self.brk + 0x100
        self.brk += 0x200
        self.uc.mem_write(sbuf, seed)
        self.uc.mem_write(obuf, b"\x00" * 0x100)
        if not self._call(RANDOM_SEED, rcx=sbuf, rdx=len(seed)) & 0xFF:
            raise RuntimeError("RandomSeed returned FALSE")
        if not self._call(RANDOM_BYTES, rcx=obuf, rdx=n) & 0xFF:
            raise RuntimeError("RandomBytes returned FALSE")
        return bytes(self.uc.mem_read(obuf, n))


def efi_time(year=2026, mon=1, day=1, hour=0, minute=0, sec=0,
             nanosec=0, tz=0x07FF, daylight=0) -> bytes:
    """EFI_TIME: Year(2) Month Day Hour Minute Second Pad1 Nanosecond(4) TZ(2) DL Pad2."""
    return struct.pack("<HBBBBBBIhBB", year, mon, day, hour, minute, sec,
                       0, nanosec, tz, daylight, 0)


def digits(rand8: bytes) -> str:
    return "".join(chr(b % 10 + 0x30) for b in rand8)


def main() -> int:
    ap = argparse.ArgumentParser(description="Emulate the InsydeH2O DRBG.")
    ap.add_argument("module", help="path to your own CryptoServiceRuntimeDxe.efi")
    args = ap.parse_args()

    seed = efi_time(2026, 9, 8, 1, 23, 45)

    print("Determinism: same seed + same stack fill -> same digits")
    for fill in (0x00, 0x00):
        out = Drbg(args.module, stack_fill=fill).bytes_for_seed(seed)
        print(f"  fill=0x{fill:02x}  raw={out.hex()}  digits={digits(out)}")

    print("\nNonce dependence: same seed, DIFFERENT stack fill -> DIFFERENT digits")
    print("(on real hardware the fill is the residue of the preceding GetTime call,")
    print(" which is RDTSC/allocator state and cannot be reconstructed from the file)")
    seen = {}
    for fill in (0x00, 0xAA, 0xFF, 0x5A):
        out = Drbg(args.module, stack_fill=fill).bytes_for_seed(seed)
        seen[fill] = digits(out)
        print(f"  fill=0x{fill:02x}  digits={digits(out)}")
    if len(set(seen.values())) > 1:
        print("\n=> the timestamp alone does NOT determine the digits. QED.")
    else:
        print("\n(note: this build did not vary with fill in this harness; inspect the nonce path)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except UcError as e:
        print(f"emulation error: {e}")
        sys.exit(1)
