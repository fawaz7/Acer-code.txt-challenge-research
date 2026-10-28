# Annotated disassembly

The functions the analysis actually turns on, lifted from the reference build and
commented. These are **excerpts**, not full module dumps — enough to follow the
argument in [`../docs`](../docs) and check it against your own firmware. No vendor
binary is redistributed; pull the modules from your own image (e.g. with
[UEFITool](https://github.com/LongSoft/UEFITool)) and disassemble to compare.

All addresses are relative to image base `0x0` and are specific to this build
(see the module table in the [README](../README.md)). **Scan, don't hardcode** —
they move on other models and firmware versions.

---

## 1. The generator — `A01UnlockPassword.efi @ 0xaf4`

This is where the 8 digits are born and sealed. The interesting parts:

```asm
; --- locate the crypto protocol, allocate the 8-byte digit buffer ---
 af4:  mov    [rsp+8], rbx
 ...
 b27:  lea    rcx, [rip+0x2cf2]      ; GUID @ 0x3820 (crypto protocol)
 b2e:  call   [rax+0x140]           ; gBS->LocateProtocol -> proto
 b43:  call   0x1778                ; AllocatePool(8) -> rdi (digit buffer)

; --- seed the DRBG from EFI_TIME, then pull 8 random bytes ---
 b58:  call   [r8+0x18]             ; gRT->GetTime(&efi_time, NULL)      <-- see §3
 b67:  call   [r8+0x148]            ; proto->RandomSeed(&efi_time, 0x10) <-- seed = 16-byte EFI_TIME
 b77:  call   [r8+0x150]            ; proto->RandomBytes(rdi, 8)         <-- 8 raw bytes

; --- reduce each byte to a decimal digit: b % 10 + '0' ---
; the compiler turned "% 10" into a reciprocal multiply by 0xCCCCCCCD:
 b81:  movzx  ecx, byte [r8]        ; b
 b85:  mov    eax, 0xcccccccd
 b8a:  mul    ecx                   ; edx = (b * 0xCCCCCCCD) >> 32
 b8c:  shr    edx, 3                ; edx = b / 10
 b8f:  lea    eax, [rdx+rdx*4]      ; eax = (b/10) * 5
 b92:  add    eax, eax             ; eax = (b/10) * 10
 b94:  sub    ecx, eax             ; ecx = b - (b/10)*10 = b % 10
 b96:  add    cl, 0x30             ; + '0'
 b99:  mov    byte [r8], cl
 b9c:  inc    r8
 b9f:  sub    rbx, 1
 ba3:  jne    0xb81                 ; loop over all 8 bytes
```

Read it top to bottom: `GetTime` → `RandomSeed` → `RandomBytes` → map each byte
into `'0'..'9'`. The digits are a pure function of whatever `RandomSeed` actually
mixed in — which is the whole question in [doc 02](../docs/02-cryptanalysis.md).

After this, the routine reads the SMBIOS serial (`LocateProtocol` of the SMBIOS
GUID `@ 0x2d20`, walk to Type-1 offset 7), `sprintf`s `"%c%c%c%c%c%c%c%c_"`
(format string `@ 0x3b68`), appends the serial, and hands the 31-byte string to
`proto->RsaOaepEncrypt` (`[proto+0x1f0]`, SHA-512) before base64-ing the result
into `code.txt`.

---

## 2. The RDTSC helper — `PcRtc.efi @ 0x1080`

A four-instruction leaf that returns the 64-bit timestamp counter. It is the
entropy that contaminates the nonce (doc 02 §2.2.3):

```asm
 1080:  rdtsc
 1082:  shl    rdx, 0x20
 1086:  or     rax, rdx            ; rax = (edx:eax) = full 64-bit TSC
 1089:  ret
```

Nothing seeds it, nothing resets it — it is the raw CPU cycle counter, different
on every boot and unrecoverable from a saved file.

---

## 3. `GetTime` dispatch — `PcRtc.efi`

The module entry (`0x108c`) installs the runtime-services time functions as bare
`jmp` thunks:

```asm
; module entry @ 0x108c installs the thunks into gRT:
 10c3:  mov    rax, [rip+0x44ee]     ; 0x55b8 = &gRT
 10ca:  lea    rcx, [rip+0x3ab]      ; 0x147c
 10de:  mov    [rax+0x18], rcx       ; gRT->GetTime       = 0x147c
 10e2:  lea    rcx, [rip+0x39b]      ; 0x1484
 10e9:  mov    [rax+0x20], rcx       ; gRT->SetTime       = 0x1484
 ...                                 ; GetWakeupTime=0x148c, SetWakeupTime=0x1494

; the thunk table (each is a tail-jump, so it creates NO stack frame):
 147c:  jmp    0x1c84                ; GetTime  -> worker
 1484:  jmp    0x1e4c                ; SetTime
 148c:  jmp    0x2044                ; GetWakeupTime
 1494:  jmp    0x21e0                ; SetWakeupTime
```

Because `0x147c` is a tail-jump, the real `GetTime` worker **`FUN_0x1c84` runs as
the top frame** with the same `rsp` the generator called in with. Its frame is
what later becomes the DRBG nonce.

### The worker and its RDTSC cache check — `FUN_0x1c84`

```asm
 1c84:  mov    [rsp+8], rbx          ; save regs ABOVE the return addr
 1c89:  mov    [rsp+0x10], rsi
 1c8e:  push   rdi                   ; [R-8]
 1c8f:  sub    rsp, 0x20             ; local/shadow area = the nonce region
 ...
 1cad:  cmp    byte [rip+0x3944], 0  ; 0x55f8  (runtime-vs-boot flag)
 1cb4:  jne    0x1d57                ; runtime path -> re-read RTC
 1cba:  call   0x1080               ; <-- RDTSC (§2)
 1cbf:  sub    rax, [rip+0x3af2]     ; 0x57b8 = stored_tsc
 1cc9:  call   0x2adc               ; age = (tsc - stored_tsc) / divisor
 1cce:  cmp    rax, 0x55d4a80        ; 90,000,000 threshold
 1cd4:  jae    0x1d49                ; stale -> re-read RTC via 0x15c0
 ; else FAST PATH: copy the cached EFI_TIME out and return
 1cd6:  movzx  eax, word [rip+0x3ae3]  ; 0x57c0 cached year
 1cdd:  mov    word [rbx], ax
 1ce0:  mov    al,  byte [rip+0x3adc]  ; cached month ...
 ...
```

The fast path does its cache-age arithmetic (`RDTSC`, subtract, divide, compare)
in exactly the stack slots `[R-0x28 .. R-0x0A)` that `RandomSeed` later reads as
its 30-byte nonce. That is the mechanism: **the nonce is the residue of this
`GetTime` call, and this call is driven by `RDTSC`.** See
[doc 02 §2.2](../docs/02-cryptanalysis.md) for the full chain.
