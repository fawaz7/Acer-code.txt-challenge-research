# Analysis scripts

Small, self‑contained tools that back the claims in [`../docs`](../docs), plus
the public key so you can attempt the re‑encryption route yourself. They contain
**no bypass** — they decode a file you already have, or exercise firmware you
supply to demonstrate where the offline routes stop.

| File | What it does |
|------|--------------|
| `decode_code_txt.py` | decode a `code.txt` to its 512‑byte RSA block |
| `drbg_emulator.py` | show DRBG output depends on the stack nonce |
| `getrtc_nonce_probe.py` | show where that nonce comes from (`GetTime`'s frame) |
| `acer_pubkey_n.txt` | the public RSA modulus, for Route C re‑encryption |

## `decode_code_txt.py`

Pure standard library, no dependencies.

```bash
python3 decode_code_txt.py path/to/code.txt
```

Shows that a `code.txt` is one opaque 512‑byte RSA‑4096 ciphertext (high
entropy, no structure to attack) and nothing more.

## `drbg_emulator.py`

Runs the real firmware DRBG under [Unicorn](https://www.unicorn-engine.org/) to
show two things: the DRBG is deterministic given its full seed, and its output
changes when the 30‑byte stack **nonce** changes — i.e. the `EFI_TIME` seed alone
does not determine the digits.

```bash
pip install unicorn
python3 drbg_emulator.py /path/to/CryptoServiceRuntimeDxe.efi
```

**Bring your own firmware module.** No vendor binary ships with this repo. Pull
`CryptoServiceRuntimeDxe.efi` from your own firmware image (e.g. with
[UEFITool](https://github.com/LongSoft/UEFITool)).

The offsets at the top of the script (`RandomSeed`, `RandomBytes`, and the
`AllocatePool`/`FreePool` wrappers) are for one specific build
(SHA‑256 `7419ef95…`). On any other model or firmware version they will differ —
locate the functions in your own module and update the constants. The modules in
this family load at image base `0x0`, so file offsets equal addresses.

## `getrtc_nonce_probe.py`

The companion to `drbg_emulator.py`. That script shows the DRBG output moves with
the nonce; this one shows **where the nonce comes from** — the stack frame of the
`GetTime` call that runs just before `RandomSeed` (see
[`../docs/02` §2.2](../docs/02-cryptanalysis.md)).

```bash
pip install unicorn
python3 getrtc_nonce_probe.py /path/to/PcRtc.efi            # synthetic example clock
python3 getrtc_nonce_probe.py /path/to/PcRtc.efi --cmos <128-byte CMOS hex>
```

It emulates the RTC reader on two different clocks and prints the 30‑byte region
`RandomSeed` later consumes, so you can watch it track the read. On real hardware
the production worker (`0x1c84`) also stirs that region with an `RDTSC` cache
check — the per‑boot value that is not in any saved `code.txt`. Offsets
(`0x15c0` reader, `0x1c84` worker, the `gBS`/`gRT`/flag globals) are build‑
specific; **bring your own `PcRtc.efi`** and update them for your module.

## `acer_pubkey_n.txt`

Acer's RSA‑4096 public modulus (`e = 65537`, OAEP hash SHA‑512), extracted from
`A01UnlockPassword.efi`. A public key is public by design; it is here so you can
encrypt candidate `"<digits>_<serial>"` strings and attempt the re‑encryption
route ([`../docs/02` §2.3](../docs/02-cryptanalysis.md)). It **cannot** decrypt a
`code.txt` — that needs the private key, which only Acer holds.
