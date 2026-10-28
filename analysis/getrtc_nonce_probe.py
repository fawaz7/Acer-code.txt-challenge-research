#!/usr/bin/env python3
"""Emulate PcRtc's GetTime worker and read back the 30-byte region that the
DRBG later consumes as its nonce (docs/02 §2.2).

This is the "try it yourself" companion to drbg_emulator.py. That script shows
the DRBG output moves when the nonce bytes move; this one shows WHERE those bytes
come from -- the stack frame of the GetTime call that runs immediately before
RandomSeed. Point it at your own PcRtc.efi, give it an RTC/CMOS image, and it
prints the EFI_TIME GetTime produced and the 30 bytes sitting at [R-0x28 .. R-0x0A).

The takeaway to look for: run it with two different CMOS images, or flip the
runtime flag, and watch the nonce region. On real hardware those bytes are also
stirred by the CPU's RDTSC cache check inside the worker -- a value that differs
every boot and is not in any saved code.txt. That is the wall in docs/02 §2.2.4;
if you can reconstruct this region from a file alone, you have something new.

Bring your own firmware module. No vendor binary ships with this repo.

Usage:
    python3 getrtc_nonce_probe.py /path/to/PcRtc.efi [--cmos HEX] [--worker 0x1c84]

Requires: pip install unicorn   (tested with unicorn 2.1.x)

The globals/worker offsets below are for one specific build. They WILL differ on
other models/versions -- locate the GetTime worker and the gBS/gRT/flag globals
in your own module and update the constants.
"""
import argparse
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN, UcError
from unicorn.x86_const import (
    UC_X86_INS_IN, UC_X86_INS_OUT,
    UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX, UC_X86_REG_RIP,
)

# --- build-specific offsets (image base 0) -------------------------------------
GETTIME_WORKER = 0x1c84   # FUN_0x1c84, the real GetTime (147c is a jmp thunk to it)
INNER_RTC_READER = 0x15c0  # the routine the worker calls to actually read the RTC
G_GBS, G_GRT, G_GRT2, G_SYS, G_FLAG = 0x55b0, 0x55b8, 0x57a8, 0x55a8, 0x55f8
# -------------------------------------------------------------------------------
#
# Note on the two entry points:
#   0x1c84 is the production worker. It first does an RDTSC cache-age check and,
#   if the cached time is fresh, returns it WITHOUT touching the RTC. Under
#   emulation RDTSC reads 0, so the age is always "fresh" and the worker returns
#   the (zero) cached time -- you will see an all-zero result from it. That RDTSC
#   gate is exactly the boot-specific entropy discussed in docs/02 §2.2.3.
#   0x15c0 is the inner reader the worker calls on a cache miss. It converts CMOS
#   to EFI_TIME and leaves the frame residue that becomes the nonce, so it is the
#   path that actually demonstrates the region filling. We probe it by default.

GBS, GRT = 0x00300000, 0x00310000
STUBS = 0x00320000        # every service slot points here; a code hook emulates the call
STOP = 0x00f00000         # sentinel return address

# A synthetic RTC image: regs 0x00..0x0d carry the clock (BCD), the rest zero.
# These are EXAMPLE values, not a real machine. Replace with --cmos <hex of your
# own 128-byte CMOS dump> for meaningful output.
EXAMPLE_CMOS = bytes(
    [0x45, 0x00, 0x23, 0x00, 0x01, 0x00, 0x05,   # sec,_,min,_,hour,_,wday
     0x08, 0x09, 0x26,                           # day, month, year(BCD lo)
     0x26, 0x02, 0x00, 0x20]                      # regA, regB(24h/BCD), regC, regD
).ljust(128, b"\x00")


def build(img, cmos, worker, R):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x10000)            # PcRtc image + globals
    uc.mem_write(0, img)
    uc.mem_map(0x200000, 0x100000)    # stack
    uc.mem_map(0x300000, 0x100000)    # tables / stubs / heap
    uc.mem_map(STOP & ~0xFFF, 0x1000)

    for g, v in [(G_GBS, GBS), (G_GRT, GRT), (G_GRT2, GRT), (G_SYS, 0x301000)]:
        uc.mem_write(g, struct.pack("<Q", v))
    uc.mem_write(G_FLAG, b"\x00")     # boot-time path (matches BDS)

    # service tables: point every slot at a unique stub address
    for base in (GBS, GRT):
        for off in range(0, 0x200, 8):
            tag = 0 if base == GBS else 0x400
            uc.mem_write(base + off, struct.pack("<Q", STUBS + off + tag))
    uc.mem_write(STUBS, b"\xc3" * 0x1000)   # RET at every stub

    latch = {"idx": 0}

    def hook_in(uc, port, size, user):
        if port in (0x71, 0x73):
            return cmos[latch["idx"] & 0x7f]
        return 0

    def hook_out(uc, port, size, value, user):
        if port in (0x70, 0x72):
            latch["idx"] = value & 0x7f

    uc.hook_add(UC_HOOK_INSN, hook_in, None, 1, 0, UC_X86_INS_IN)
    uc.hook_add(UC_HOOK_INSN, hook_out, None, 1, 0, UC_X86_INS_OUT)

    def hook_stub(uc, addr, size, user):
        off = addr - STUBS
        rax = 0x800000000000000E if off == 0x400 + 0x48 else 0   # gRT->GetVariable -> NOT_FOUND
        uc.reg_write(UC_X86_REG_RAX, rax)

    uc.hook_add(UC_HOOK_CODE, hook_stub, None, STUBS, STUBS + 0x800)
    return uc


def run(img, cmos, worker, R):
    uc = build(img, cmos, worker, R)
    timebuf = 0x301800
    uc.mem_write(timebuf, b"\x00" * 16)
    uc.mem_write(R - 8, struct.pack("<Q", STOP))   # GetTime enters with rsp=R (retaddr=STOP)
    uc.reg_write(UC_X86_REG_RSP, R - 8)
    uc.reg_write(UC_X86_REG_RCX, timebuf)          # EFI_TIME*
    uc.reg_write(UC_X86_REG_RDX, 0)                # capabilities = NULL
    try:
        uc.emu_start(worker, STOP, timeout=5 * 1_000_000, count=2_000_000)
    except UcError as e:
        return ("ERR:%s @ %x" % (e, uc.reg_read(UC_X86_REG_RIP)), None, None)
    efitime = bytes(uc.mem_read(timebuf, 16))
    nonce = bytes(uc.mem_read(R - 0x28, 0x1e))     # the 30 bytes RandomSeed would read
    return (None, efitime, nonce)


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe the GetTime nonce region.")
    ap.add_argument("module", help="path to your own PcRtc.efi")
    ap.add_argument("--cmos", help="128-byte CMOS image as hex (default: synthetic example)")
    ap.add_argument("--target", default=hex(INNER_RTC_READER),
                    help="routine to emulate (default 0x15c0, the inner RTC reader; "
                         "pass 0x1c84 for the full worker)")
    args = ap.parse_args()

    img = open(args.module, "rb").read()
    base_cmos = bytes.fromhex(args.cmos)[:128].ljust(128, b"\x00") if args.cmos else EXAMPLE_CMOS
    target = int(args.target, 0)

    # a second CMOS image with a different clock, to show the nonce move
    other = bytearray(base_cmos)
    other[0], other[2], other[4] = 0x55, 0x59, 0x21   # different sec / min / hour (BCD)

    R = 0x2f0000
    print(f"Emulating {target:#x}, reading EFI_TIME and the 30-byte region at "
          f"[R-0x28 .. R-0x0A) (R={R:#x}):\n")
    nonces = []
    for label, cmos in (("clock A", bytes(base_cmos)), ("clock B", bytes(other))):
        err, efitime, nonce = run(img, cmos, target, R)
        if err:
            print(f"  {label}:  {err}")
            continue
        nonces.append(nonce)
        print(f"  {label}:  EFI_TIME={efitime.hex()}")
        print(f"            nonce   ={nonce.hex()}")
    if len(nonces) == 2 and nonces[0] != nonces[1]:
        print("\n=> the nonce region tracks the RTC read, i.e. it is this call's frame "
              "residue.")
    print("\nOn real hardware the production worker (0x1c84) also stirs this region "
          "with\nan RDTSC cache check (docs/02 §2.2.3) -- a per-boot value that is not "
          "in any\nsaved code.txt. Reconstruct it from a file alone and you have "
          "something new.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except UcError as e:
        print(f"emulation error: {e}")
        sys.exit(1)
