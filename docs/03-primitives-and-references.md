# 3. Primitives and references

Background on the three cryptographic primitives this scheme leans on, and why
the published attacks against them do not help an offline attacker holding only
a `code.txt`.

## 3.1 RSA‑OAEP

`code.txt` is RSA with OAEP padding (RFC 8017 / PKCS#1 v2.2), using SHA‑512 as
the OAEP hash in the reference build. The important properties:

* **OAEP is randomised.** Each encryption injects a fresh random seed of one hash
  length (64 bytes for SHA‑512). Encrypting the same message twice gives
  different ciphertexts. This is what makes the re‑encryption brute‑force in
  [doc 02 §2.3](02-cryptanalysis.md) cost `plaintext_space × seed_space` rather
  than just `plaintext_space`.
* **IND‑CCA2 security** is proven in the random‑oracle model, so a small / known
  plaintext space does **not** by itself enable recovery — the randomiser must be
  weak for guessing to help.
* **The one relevant caveat** is Brown's result that *low‑exponent* RSA‑OAEP with
  a *weak randomiser* can fall to Coppersmith‑style small‑root methods. It does
  not apply here: `e = 65537` (not low, unlike `e = 3`), and the randomiser is
  `RDRAND` (not weak).

References:

* RFC 8017, *PKCS #1 v2.2* — <https://datatracker.ietf.org/doc/html/rfc8017>
* D. Brown, *What Hashes Make RSA‑OAEP Secure?*, IACR ePrint 2005/189 —
  <https://eprint.iacr.org/2005/189>
* Fujisaki, Okamoto, Pointcheval, Stern, *RSA‑OAEP Is Secure under the RSA
  Assumption*, J. Cryptology 2004 —
  <https://www.di.ens.fr/~pointche/Documents/Papers/2004_joc.pdf>

## 3.2 `RDRAND` (hardware RNG)

The OAEP padding seed is drawn from the CPU's on‑die RNG via `RDRAND`. Intel's
DRNG is a physical entropy source feeding an AES‑CBC‑MAC conditioner and a
NIST SP800‑90A CTR‑DRBG, reseeded continuously from hardware.

* Its output is predictable *only to someone who knows the internal state at that
  moment* — which lives in the silicon and is not exposed. There is no published
  method to reconstruct a **past** `RDRAND` output from external data.
* Formal analysis (Shrimpton–Terashima) proved forward‑security bounds for
  `RDRAND`‑fetched bits.

References:

* Intel, *Digital Random Number Generator (DRNG) Software Implementation Guide* —
  <https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html>
* *RDRAND* overview — <https://en.wikipedia.org/wiki/RDRAND>
* NIST SP 800‑90A Rev. 1 (DRBG constructions) —
  <https://csrc.nist.gov/pubs/sp/800/90/a/r1/final>

## 3.3 CTR‑DRBG and the firmware DRBG

The firmware's software DRBG (used for the 8 digits) is an SP800‑90‑style
construction with an instantiate/generate/reseed split and a derivation function
over `entropy || nonce`. Note that the seed material is a timestamp **plus** the
30‑byte stack nonce analysed in [doc 02](02-cryptanalysis.md); the DRBG algorithm
being deterministic does not help when part of its seed is boot‑specific.

The academic attacks on CTR‑DRBG are **live side‑channels**, not offline
prediction — they recover state from an *ongoing* generation you are observing:

* **Cache‑timing** state recovery (Cohney et al., *Pseudorandom Black Swans*) —
  needs concurrent code watching cache during generation —
  <https://web.eecs.umich.edu/~genkin/papers/DRBG.pdf>
* **Power analysis** recovering CTR‑DRBG key/nonce in ~256 traces (De Meyer,
  CHES 2020) — needs physical traces during generation —
  <https://tches.iacr.org/index.php/TCHES/article/view/8392>

Neither reconstructs a value produced at a past boot from a saved file, which is
the setting here.

## 3.4 Note on the "2²⁴⁰" / "uninitialised stack" framing

Earlier informal analyses described the digit protection as either "~10⁸ guesses"
or "2²⁴⁰ of uninitialised stack feeding the DRBG." Both are misleading:

* The 10⁸ figure ignores that there is no offline oracle and that the OAEP seed
  blinds any re‑encryption check.
* The "uninitialised stack" figure treats the 30‑byte nonce as high‑entropy
  random. It is not. It is **deterministic but boot‑specific** — the stack
  residue of a `GetTime` call that is itself driven by `RDTSC` timing and
  allocator pointers. The correct statement is not "2²⁴⁰ of entropy" but
  "unreconstructable from the file," which is a different and more accurate claim.

The practical conclusion (the digits cannot be predicted offline) is the same;
the mechanism is what this study corrects.
