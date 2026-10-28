# 2. Can the unlock code be recovered offline?

This is the core of the study. There are four conceivable offline routes from a
`code.txt` to its 8 digits. Each is examined and ruled out. Addresses are
build‑specific (see the README).

## 2.1 Route A — decrypt the file

`code.txt` is `RSA‑4096‑OAEP( AcerPublicKey, "<digits>_<serial>" )`. To read the
plaintext you need the RSA **private** key, which only the vendor holds. The only
way to derive it from the public key is to **factor the 4096‑bit modulus**.

Factoring 4096‑bit RSA is far outside any practical capability. The public
record tops out at RSA‑250 (829 bits, 2020) using thousands of core‑years; 4096
bits is many orders of magnitude harder, and no large‑scale quantum computer
exists to change that. You cannot "try random keys" either: exactly one private
key fits `n`, a wrong key yields garbage with no signal that you are close, and
the chance of guessing a 2048‑bit prime factor is ~`1/2²⁰³⁷`.

**Route A: closed.**

## 2.2 Route B — predict the digits (the interesting one)

The digits come from the DRBG, seeded by the 16‑byte `EFI_TIME`. If the DRBG's
input were *only* that timestamp, the digits would be computable: recover the
timestamp (it is even recoverable from the file's FAT write time) and run the
DRBG forward. This is the attack the "just reproduce the RNG" idea assumes. It
does not work, and following the seed into the code shows why.

### 2.2.1 The DRBG takes a second input: a 30‑byte nonce

`RandomSeed` (`CryptoServiceRuntimeDxe.efi @ 0xc640`):

```c
bool RandomSeed(void *seed, int seed_len) {
    uint8_t local_28[32];                       // <-- never initialised here
    if (ctx) free(ctx);
    ctx = 0;
    if (!seed) { seed_len = 0x21; seed = "UEFI Crypto Library default seed"; }
    return instantiate(&ctx, 0x1e, local_28, seed_len, seed) >= 0;
    //                        ^^^^  ^^^^^^^^
    //                        30    nonce pointer (the local buffer above)
}
```

and the instantiate at `0x14558` copies 30 bytes from that pointer into the DRBG
state as a **nonce**, alongside the timestamp entropy:

```c
// instantiate(ctx, nonce_len=0x1e, nonce_ptr, entropy_len, entropy_ptr)
memcpy(ctx + 0x8a, nonce_ptr, 30);              // FUN_0x224e0
```

So `digits = f( EFI_TIME , 30 bytes of nonce )`. The nonce is **`local_28`, a
stack buffer that `RandomSeed` never writes**. Disassembly of `RandomSeed`
confirms the only writes before the instantiate call are register saves at
`[rsp+8]`, `push rdi`, and the argument at `[rsp+0x20]` — nothing touches the
`[rsp+0x30 .. rsp+0x4d]` region that becomes the nonce.

A naïve emulator that zero‑fills the stack reproduces digits deterministically —
which is exactly the trap. Varying the stack fill shows the output depends on
those 30 bytes. The real question is therefore: **what is in that stack region on
a real boot, and can it be reconstructed from the file?**

### 2.2.2 The nonce is the previous call's leftovers

In the generator, `GetTime` and `RandomSeed` are called back‑to‑back from the
same frame:

```
0xb58   call [gRT+0x18]      ; GetTime(&efi_time, NULL)
0xb67   call [proto+0x148]   ; RandomSeed(&efi_time, 16)
```

Both are entered with the same `rsp` (call it `R`). Working through
`RandomSeed`'s prologue (`push rdi; sub rsp,0x50; lea r8,[rsp+0x30]`), the 30
nonce bytes land at `[R-0x28 .. R-0x0A)` — **below the return address, inside the
frame the immediately preceding `GetTime` call just used and vacated.** The nonce
is literally the stack residue of `GetTime`.

### 2.2.3 Following `GetTime`

`gRT->GetTime` is installed by `PcRtc.efi`. Its module entry (`0x108c`) writes
the runtime‑services pointers directly:

```c
gRT->GetTime       = 0x147c;   // thunk
gRT->SetTime       = 0x1484;
gRT->GetWakeupTime = 0x148c;
gRT->SetWakeupTime = 0x1494;
InstallMultipleProtocolInterfaces(..., RealTimeClockArch, NULL);
```

`0x147c` is an 8‑byte thunk: `jmp 0x1c84`. A tail‑jump creates no frame, so the
real `GetTime` worker, **`FUN_0x1c84`, runs as the top frame** at `rsp = R`.
Its own frame is therefore what fills the nonce region. The whole dispatch is
inside `PcRtc` — there is no separate DXE‑core wrapper to account for.

`FUN_0x1c84` saves `rbx` and `rsi` *above* `R` (`[R+8]`, `[R+0x10]`), pushes
`rdi` at `[R-8]`, then `sub rsp,0x20`. The nonce region `[R-0x28 .. R-0x0A)` is
its **local / shadow area** — the space its own sub‑calls spill into — not A01's
saved registers. What writes that area:

* **`RDTSC`.** `FUN_0x1c84` caches the last RTC read and decides freshness with a
  raw timestamp counter:

  ```c
  tsc = rdtsc();                               // FUN_0x1080  (= RDTSC)
  if ((tsc - stored_tsc) / divisor < 90000000) // threshold 0x55d4a80
      return cached_time;                      // fast path
  // else re-read the RTC via FUN_0x15c0
  ```

  `FUN_0x1080` is literally `rdtsc; shl rdx,0x20; or rax,rdx; ret`. The cache‑age
  math (and the sub‑calls around it) run in exactly the stack slots that become
  the nonce.

* **Allocator leftovers.** The generator calls `AllocatePool(8)` *immediately
  before* `GetTime`. `AllocatePool` lives in the DXE core; its call tree occupies
  the same stack region and leaves pointer‑shaped values there that `GetTime`'s
  short fast path may not fully overwrite.

### 2.2.4 Why that kills offline prediction

The 30 nonce bytes are **deterministic but boot‑specific**. They are a function
of:

* the CPU cycle counter (`RDTSC`) at that instant, which differs on every boot
  and cannot be derived from the file; and/or
* the firmware's runtime memory layout (DXE allocator pointers), which only
  exists during that boot on that machine.

Neither is designed entropy, and neither is "uninitialised garbage" in the loose
sense — but both are **unreconstructable from `code.txt` alone**. An offline
emulator can supply the timestamp, but it cannot manufacture the real `RDTSC`
value or the real allocator state of a past boot. So the digits cannot be
computed after the fact.

**Route B: closed** — for a now‑precise reason, which is *not* the commonly
repeated "2²⁴⁰ of uninitialised stack."

## 2.3 Route C — brute‑force the digits by re‑encryption

We hold the public key, so we can encrypt freely. The digit space is only **10⁸**
— trivial. The idea: encrypt each candidate `"<digits>_<serial>"` and compare to
`code.txt`; a match reveals the digits with no private key.

What stops it: **OAEP randomises every encryption** with a fresh ~512‑bit padding
seed (from `RDRAND`). To reproduce a specific ciphertext you must reproduce that
exact seed, so the search is:

```
10⁸  (digits)   ×   2⁵¹²  (OAEP seed)   ≈   2⁵³⁸
```

dominated entirely by the seed. For intuition: `2⁵¹² ≈ 10¹⁵⁴`; the observable
universe holds ~`10⁸⁰` atoms; exascale hardware (`10¹⁸/s`) on `10⁸⁰` machines for
the age of the universe reaches ~`10¹²⁴` tries — still `10³⁰` short.

The entire design is a **tiny secret (8 digits) locked inside a large random
envelope**. The 10⁸ part is weak on its own; the security is the seed. The only
way this route opens is to make OAEP deterministic for you — i.e. predict the
seed. The seed is `RDRAND`, so that reduces to the same wall as Route B (and
worse, since `RDRAND` is hardware‑random, not even a software DRBG).

**Route C: closed.**

## 2.4 Route D — side‑channel the RNG

The literature *does* break these primitives — but every practical attack is a
**live** side‑channel that requires instrumenting the generator *while it runs*:

* cache‑timing state recovery of CTR‑DRBG (needs concurrent spy code watching
  cache during generation);
* power‑analysis key/nonce recovery (needs physical probes during generation);
* cross‑core leakage of `RDRAND`/`RDSEED` (needs concurrent code on the same
  CPU).

None of these reconstruct a **past** output from a saved file. We have a
`code.txt` produced at some earlier boot with no concurrent access to that boot —
precisely the case none of the attacks address. The entropy was physical and is
gone. See [doc 03](03-primitives-and-references.md) for citations.

**Route D: closed** for the offline/after‑the‑fact setting.

## 2.5 There is also no offline oracle

Even a partial attack usually needs a way to *test* a guess. Here there is none:
you cannot decrypt `code.txt` (no private key), and you cannot re‑encrypt to a
matching ciphertext (unknown OAEP seed). So candidate digits cannot be verified
except by typing one at the real prompt — which permits one attempt per power
cycle and regenerates the file on failure.

## 2.6 Summary

| Route | Requires | Status |
|-------|----------|--------|
| A. Decrypt | factor RSA‑4096 | infeasible |
| B. Predict digits | reproduce DRBG nonce = RDTSC + allocator state of a past boot | not reconstructable offline |
| C. Brute‑force re‑encrypt | guess 10⁸ digits **and** the ~2⁵¹² OAEP seed | infeasible |
| D. Side‑channel | live instrumentation during generation | n/a to a saved file |

All four converge on the same two unbreakable unknowns: **Acer's factorisation**,
or a **≥512‑bit hardware‑random value**. That convergence is the scheme working
as designed. The digits are unrecoverable offline — not because the 8‑digit
secret is large, but because it is bound to one of those two.
