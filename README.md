# Acer: `code.txt` challenge research

What the `code.txt` file really is, how a locked Acer laptop generates it, and a
full account of the four routes I tried to turn it back into the 8-digit unlock
code offline — and exactly where each one hit a wall.

This is a working writeup, not a verdict. I could not recover the code from the
file alone; the point of publishing it is to show *why*, hand over every artifact
I used, and let you push on the parts I couldn't get past. If you find a crack in
one of the walls, I want to hear about it.

---

## In plain English

Some recent Intel Acer laptops (the ones running InsydeH2O firmware) will, after
a wrong BIOS Setup password, ask you to *"Enter Unlock Code"* and write a little
file called **`code.txt`** onto a USB stick. The idea is that you send that file
to Acer, and Acer sends you back the code.

A lot of people assume that file *contains* their code, or that it's a scrambled
version a smart tool could unscramble. From taking the firmware apart, here's what
it actually does:

* When your laptop locks, it **makes up a brand-new 8-digit code on the spot, at
  random.** That number is never anything you chose — it's invented in that
  moment.
* It then puts that number in a **sealed envelope that only Acer can open.** The
  envelope is `code.txt`. Technically it's encrypted with Acer's public key, and
  only Acer holds the private key that opens it.
* So `code.txt` is a *request* addressed to Acer — not your code, not a hash of
  it, not a hint. The code is in there, but it's locked to Acer.

People reasonably ask: "it's only 8 digits, so why not just try them all?" The
catch is there's **no way to check a guess** without the laptop in front of you,
and the laptop only lets you try **once per power-on** before it throws the whole
thing away and makes a *new* code next time. The two obvious offline shortcuts —
*unscramble the file* or *predict the random number* — each run into a specific
wall, documented below. I'm laying them out so you can judge them for yourself.

---

## Technical summary

`code.txt` is base64 around a single RSA-4096 ciphertext:

```
code.txt = base64( RSA-4096-OAEP-SHA512( AcerPublicKey, "<8 digits>_<serial>" ) )
```

The 8 decimal digits are produced at lock time by the firmware's DRBG, wrapped
with the machine serial, encrypted to Acer's public key, and written out. The
verifier later compares your typed input against those digits, **one attempt per
power cycle**, regenerating the file on each failure.

I looked at four offline routes from a saved `code.txt` to its digits. Here's
where each stopped:

| Route | What it needs | Where it stopped |
|-------|---------------|------------------|
| **Decrypt the file** | Acer's RSA-4096 private key → factor a 4096-bit modulus | factoring RSA-4096 is far beyond any known capability |
| **Predict the digits** | reproduce the DRBG nonce, which is the live stack frame of `GetTime` — fed by a raw **`RDTSC`** cache check and by `AllocatePool` leftovers | boot-specific runtime state; I couldn't reconstruct it from the file |
| **Brute-force by re-encryption** | guess the 10⁸ digits **and** the ~512-bit **`RDRAND`** OAEP padding seed → `10⁸ × 2⁵¹²` | the random padding seed blinds every candidate |
| **Side-channel the RNG** | live cache-timing / power analysis *during* generation | all known attacks are live; none reconstructs a past, saved output |

There's also **no offline oracle**: you can neither decrypt `code.txt` (no private
key) nor re-encrypt to a matching ciphertext (unknown OAEP seed), so a candidate
can't even be *tested* except by typing it at the real prompt.

A note on a common myth: the digit protection is often described as "2²⁴⁰ of
uninitialised stack." That's imprecise — the DRBG nonce isn't high-entropy
*designed* randomness, it's **deterministic but boot-specific** (`RDTSC` timing +
allocator pointers). I think that's the single most interesting part of the whole
thing, and it's where I'd focus if I picked this back up.

Full detail: [`docs/01`](docs/01-file-format-and-generation.md) (format +
generator), [`docs/02`](docs/02-cryptanalysis.md) (the four routes, the core),
[`docs/03`](docs/03-primitives-and-references.md) (RSA-OAEP / RDRAND / DRBG
background + citations), and [`disassembly/`](disassembly/) for the annotated code
the argument rests on.

---

## Where someone might still push

I'm publishing this because "I couldn't" isn't "nobody can." If you want to pick
up where I stopped, these are the honest openings — and the walls each one has to
get through:

* **The nonce (Route B) is the live one.** The digits are a pure function of the
  DRBG seed, and the only part of that seed I couldn't reconstruct offline is a
  30-byte stack region left behind by `GetTime`. It is *not* designed entropy —
  it's `RDTSC` timing plus allocator pointers. If that region turns out to be
  more predictable than I think (a coarse boot clock, a near-fixed allocator
  layout, a short effective range on some board), the digits fall. Start with
  [`analysis/getrtc_nonce_probe.py`](analysis/getrtc_nonce_probe.py) — it emulates
  `GetTime` on your own module and prints that exact region.
* **Confirm or break my reading of the seed.** I claim the nonce is contaminated
  by `RDTSC` + allocator state. Maybe on your firmware the fast-path doesn't run,
  or the region is overwritten with something stable. The disassembly is in
  [`disassembly/`](disassembly/); check it against your own dump.
* **Route C is only blinded by the OAEP seed.** The digit space is a trivial 10⁸.
  If you can make OAEP deterministic for a given encryption — i.e. recover or
  constrain that `RDRAND` seed — re-encryption becomes a search you can actually
  run. The public key is in [`analysis/acer_pubkey_n.txt`](analysis/acer_pubkey_n.txt)
  so you can encrypt candidates yourself.
* **I only had one machine and one firmware build.** Everything here is one
  reference device. Offsets, the RTC cache behavior, even the RNG wiring may
  differ across the family. More samples might show a weaker variant.

If you get further than I did, open an issue — including a dead end that rules
something out. Negative results are still results.

---

## Locked out of your own Acer? I can get you back in.

This research is about why the **file** is a dead end — it doesn't help *you* get
back into a laptop you own. Being locked out of your own machine is a different,
solvable problem, and I do it as a paid service:

### 👉 **<https://getoutsyde.click>**

- **No fix, no fee** — if I can't recover it, you owe nothing.
- **How it works:** you run a small read-only tool and send me its report → I
  recover the password → you pay → I send you the code. Price and turnaround are
  quoted up front.
- Intel Acer laptops only; the laptop **never leaves your desk**.
- (Your `code.txt` itself won't help — the site explains what to send.)

If this write-up saved you from chasing the file, and you still need in, that's
what the service is for.

---

## Scope and ethics

* This is **research**: it documents what `code.txt` is, how the firmware produces
  it, and how far I got trying to recover its code offline. It contains **no
  bypass, no exploit, and no turnkey unlock tool** — the scripts only decode a
  file you already have or exercise the RNG against firmware you supply.
* It is **only** about the `code.txt` challenge file. It does not cover removing
  or recovering any BIOS password, and nothing here enables unlocking a device you
  do not own.
* **No vendor firmware is redistributed.** The analysis cites module names,
  SHA-256 digests, and internal offsets, and the disassembly is excerpted to the
  functions under discussion, so you can reproduce everything against your **own**
  firmware. (The published public key is public by design — it cannot decrypt
  anything.)
* Work only on hardware you own or are authorised to service.

---

## Platform studied

* **Machine class:** Intel Acer laptops, 12th/13th/14th-gen Core and Core Ultra,
  InsydeH2O firmware. Reference device: Predator Helios 16 (`PH16-71`), board
  `RPL Discovery_RTX`. The design appears shared across the family.
* **Firmware modules (reference build):**

  | Module | Role | SHA-256 (prefix) |
  |--------|------|------------------|
  | `A01UnlockPassword.efi` | builds `code.txt` | `f79e758c…` |
  | `CryptoServiceRuntimeDxe.efi` | DRBG + RSA/OAEP | `7419ef95…` |
  | `PcRtc.efi` | `GetTime` / RTC services | `4cbe07ef…` |

  All load at image base `0x0`; every address in the docs is relative to that
  base and is specific to this build. Offsets differ on other models and firmware
  versions — **scan, don't hardcode.**

---

## Reproducing

See [`analysis/README.md`](analysis/README.md):

* `analysis/decode_code_txt.py` — Python only; shows a `code.txt` decodes to one
  opaque 512-byte RSA block and nothing more.
* `analysis/drbg_emulator.py` — needs [Unicorn](https://www.unicorn-engine.org/)
  and **your own** crypto module; shows the DRBG is deterministic given its full
  seed, and that its output moves when the nonce bytes move.
* `analysis/getrtc_nonce_probe.py` — Unicorn + **your own** `PcRtc.efi`; emulates
  `GetTime` and prints the 30-byte region that becomes the DRBG nonce.
* `analysis/acer_pubkey_n.txt` — the public RSA modulus (e = 65537), so you can
  encrypt candidates and attempt Route C yourself.
* `disassembly/` — annotated disassembly of the generator, the `RDTSC` helper,
  and the `GetTime` worker.

---

## Author

Fawaz Al-Ghzawi — <ghazawe1@gmail.com> · <https://getoutsyde.click>

## License

Original text and code are released under the MIT License (see [`LICENSE`](LICENSE)).
It does **not** cover any third-party firmware, which is not included here.
