# 1. The `code.txt` file format and how the firmware generates it

All addresses are relative to image base `0x0` and refer to the reference build
(see the module table in the top‑level README). They are build‑specific.

## 1.1 On‑disk format

`code.txt` is ASCII base64 with trailing newline(s). Decoding it yields exactly
one RSA‑4096 ciphertext block (512 bytes):

```
code.txt  ──base64──▶  512‑byte block  ==  c = m_OAEP ^ e  mod n
```

where `n` is Acer's 4096‑bit RSA modulus (embedded in the firmware), `e = 65537`,
and `m_OAEP` is the OAEP‑padded plaintext described below. There is no header,
no metadata, and no second field — the whole file is the single ciphertext.

The plaintext *inside* the encryption is a 31‑byte ASCII string:

```
"<8 decimal digits>_<22‑char machine serial>"
   8 chars          1   22 chars              = 31 bytes
```

The 8 digits are the value the firmware will later compare your typed input
against. The serial is read from SMBIOS and binds the request to one machine.

## 1.2 The generator routine

The file is produced by `A01UnlockPassword.efi`. The generator is the function
at `0xaf4`. Reconstructed control flow:

```c
proto = LocateProtocol(CryptoProtocolGuid);     // [gBS+0x140], GUID @ 0x3820
out8  = AllocatePool(8);                         // 8-byte output buffer

gRT->GetTime(&efi_time, NULL);                   // [gRT+0x18]
proto->RandomSeed(&efi_time, 0x10);              // [proto+0x148]  seed = 16-byte EFI_TIME
proto->RandomBytes(out8, 8);                     // [proto+0x150]  8 random bytes

for (i = 0; i < 8; i++)                          // 0xb81..0xba3
    out8[i] = out8[i] % 10 + '0';                // byte -> decimal digit (magic-div by 10)

sprintf(tmp, "%c%c%c%c%c%c%c%c_", digits...);    // format @ 0x3b68, call @ 0xbfa
serial = SMBIOS Type1 offset 7;                  // protocol 03583ff6-..., GUID @ 0x2d20

plaintext = SetMem(buf, 0x1f, ' ');              // 31-byte space-filled buffer @ 0xd00
memcpy(plaintext,     "DDDDDDDD_", 9);           // digits + underscore
memcpy(plaintext + 9,  serial,    22);           // serial

ct = proto->RsaOaepEncrypt(AcerPubKey, SHA512,   // [proto+0x1f0] @ 0x103f
                           plaintext, 0x1f);      // algo GUID caa4381e = SHA-512
b64 = base64(ct);                                 // @ 0x14b0
write_file("code.txt", b64);                      // SimpleFileSystem, gated on a USB device path
```

Key points:

* The **entropy for the digits** is the 16‑byte `EFI_TIME` passed to
  `RandomSeed`. That is the *only* declared seed input. (Its true dependence on
  additional state is the subject of [doc 02](02-cryptanalysis.md).)
* The RSA step is **OAEP with SHA‑512** (padding‑scheme hash identified by the
  algorithm GUID `caa4381e…`). OAEP draws a fresh random padding seed on every
  call — see §1.4.
* Acer's public key is RSA‑4096, `e = 65537`, stored as a 704‑character base64
  blob inside the module (referenced near `0xd6d`). The modulus is reproduced in
  [`analysis/acer_pubkey_n.txt`](../analysis/acer_pubkey_n.txt) — a public key is
  public by design, and having it lets you encrypt candidates and try Route C
  ([doc 02 §2.3](02-cryptanalysis.md)) yourself. It cannot decrypt a `code.txt`.

## 1.3 The verifier

The matching check is the function at `0x1280`:

* the generated 8 digits are widened to UTF‑16 and held in memory;
* the typed string is read, lower‑case letters are upper‑cased, and it is
  compared byte‑for‑byte against the digits;
* a mismatch is rejected; the firmware permits **one attempt per power cycle**
  and regenerates a **new** `code.txt` on the next boot.

So the expected input is exactly the 8 decimal digits sealed inside `code.txt`.
There is no shortcut input and no partial‑match feedback.

## 1.4 Where the randomness comes from

Two distinct random values feed one `code.txt`:

1. **The 8 digits** — from the firmware's software DRBG
   (`CryptoServiceRuntimeDxe.efi`), seeded as shown above. The DRBG itself is a
   deterministic SP800‑90‑style construction: `RandomSeed` (`0xc640`) frees and
   re‑instantiates the context (`0x14558`), and `RandomBytes` (`0xc604`) runs the
   generate (`0x14664`) and reseed (`0x14820`) steps.

2. **The OAEP padding seed** — a fresh value taken from the CPU's hardware RNG
   (`RDRAND`) on each encryption. This is what makes two encryptions of the same
   plaintext produce different ciphertexts, and it is central to the
   cryptanalysis in [doc 02](02-cryptanalysis.md).

The subtlety that defeats offline prediction of the digits is *not* in this
high‑level flow — it is in what actually seeds the DRBG once you follow
`RandomSeed` into the crypto module and `GetTime` into the RTC driver. That is
the next document.
