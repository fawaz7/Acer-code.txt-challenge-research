# Analysis scripts

Small, self‑contained tools that back the claims in [`../docs`](../docs). They
contain **no bypass** — the first only decodes a file you already have; the
second only exercises the RNG to demonstrate the nonce dependence.

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
