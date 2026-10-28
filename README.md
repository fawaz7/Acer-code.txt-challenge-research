# Acer: `code.txt` challenge research

What the `code.txt` file really is, how a locked Acer laptop creates it, and why
you cannot turn it into the unlock code yourself — no matter how clever you are.

---

## In plain English

Some recent Intel Acer laptops (the ones running InsydeH2O firmware) will, after
a wrong BIOS Setup password, ask you to *"Enter Unlock Code"* and write a little
file called **`code.txt`** onto a USB stick. The idea is that you send that file
to Acer, and Acer sends you back the code.

A lot of people assume that file *contains* their code, or that it's a scrambled
version of it that a smart tool could unscramble. **It isn't.** Here's what I
found after taking the firmware apart:

* When your laptop locks, it **makes up a brand-new 8-digit code on the spot, at
  random.** That number is never anything you chose — it's invented in that
  moment.
* It then puts that number in a **sealed envelope that only Acer can open.** The
  envelope is `code.txt`. Technically it's locked with Acer's encryption key, and
  only Acer holds the key that opens it.
* So `code.txt` is a *request* addressed to Acer — not your code, not a hash of
  it, not a hint. **There is nothing inside the file you can "solve."** The code
  is in there, but it's locked to Acer, and nothing you do to the file gets it
  out.

People have guessed it must be "only 8 digits, so just try them all." The catch
is there's **no way to check a guess** without the laptop in front of you, and
the laptop only lets you try **once per power-on** and then throws the whole
thing away and makes a *new* code next time. And the two obvious shortcuts —
*unscramble the file* or *predict the random number* — both run into walls that
would take longer than the age of the universe, for solid mathematical reasons
explained below.

**Bottom line:** the `code.txt` file is a dead end. It was designed so that only
the vendor can read it, and the research confirms that design holds up.

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

Every offline route to the digits is closed:

| Route | What it needs | Verdict |
|-------|---------------|---------|
| **Decrypt the file** | Acer's RSA-4096 private key → factor a 4096-bit modulus | infeasible |
| **Predict the digits** | reproduce the DRBG nonce, which is the live stack frame of `GetTime` — fed by a raw **`RDTSC`** cache check and by `AllocatePool` leftovers | boot-specific runtime state, not reconstructable from the file |
| **Brute-force by re-encryption** | guess the 10⁸ digits **and** the ~512-bit **`RDRAND`** OAEP padding seed → `10⁸ × 2⁵¹²` | infeasible |
| **Side-channel the RNG** | live cache-timing / power analysis *during* generation | n/a to a saved file |

There is also **no offline oracle**: you can neither decrypt `code.txt` (no
private key) nor re-encrypt to a matching ciphertext (unknown OAEP seed), so a
candidate can't even be tested except by typing it at the real prompt.

A note on a common myth: the digit protection is often described as "2²⁴⁰ of
uninitialised stack." That's imprecise — the DRBG nonce isn't high-entropy
*designed* randomness, it's **deterministic but boot-specific** (`RDTSC` timing +
allocator pointers). The conclusion ("can't be predicted offline") stands; the
mechanism is what this research pins down.

Full detail: [`docs/01`](docs/01-file-format-and-generation.md) (format +
generator), [`docs/02`](docs/02-cryptanalysis.md) (the four routes, the core),
[`docs/03`](docs/03-primitives-and-references.md) (RSA-OAEP / RDRAND / DRBG
background + citations).

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

* This is a **negative result**: it documents why `code.txt` is not
  offline-recoverable. It contains **no bypass, no exploit, and no tool**.
* It is **only** about the `code.txt` challenge file — what it is, how the
  firmware produces it, and whether its code can be derived from the file. It does
  not cover removing or recovering any BIOS password, and nothing here enables
  unlocking a device you do not own.
* **No vendor firmware is redistributed.** The analysis cites module names,
  SHA-256 digests, and internal offsets so others can reproduce it against their
  **own** firmware.
* Work only on hardware you own or are authorised to service.

---

## Platform studied

* **Machine class:** Intel Acer laptops, 12th/13th/14th-gen Core and Core Ultra,
  InsydeH2O firmware. Reference device: Predator Helios 16 (`PH16-71`), board
  `RPL Discovery_RTX`. The design is shared across the family.
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

---

## Author

Fawaz Al-Ghzawi — <ghazawe1@gmail.com> · <https://getoutsyde.click>

## License

Original text and code are released under the MIT License (see [`LICENSE`](LICENSE)).
It does **not** cover any third-party firmware, which is not included here.
