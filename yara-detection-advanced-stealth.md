# YARA Detection Engineering for Advanced / Stealth Malware

A practical guide to writing YARA rules that catch modern evasive Windows
malware — fileless loaders, direct/indirect syscalls, sleep obfuscation,
module stomping, reflective injection, LOLBin chains, .NET/Go/Rust implants.

Pairs with:
- `malware-reversing-techniques.md` — the techniques being detected
- `driver-internals-detection.md` / `edr-detection-mechanics.md` — kernel side
- `malware_pocs/` — local samples to test rules against

---

## Table of Contents

1. [YARA Mental Model — What Actually Persists](#1-yara-mental-model)
2. [Rule Anatomy & Hex String Syntax Deep Dive](#2-rule-anatomy--hex-string-syntax)
3. [The `pe` Module — Structure-Aware Detection](#3-the-pe-module)
4. [The `math` Module — Entropy & Math Conditions](#4-the-math-module)
5. [Rules: Dynamic Resolution / PEB Walking](#5-rules-dynamic-resolution)
6. [Rules: Direct & Indirect Syscalls](#6-rules-direct--indirect-syscalls)
7. [Rules: Injection & Hollowing](#7-rules-injection--hollowing)
8. [Rules: Sleep Obfuscation (Ekko / Foliage / Nighthawk)](#8-rules-sleep-obfuscation)
9. [Rules: Hooking, Unhooking, AMSI/ETW Patching](#9-rules-hooking-unhooking-amsi-etw)
10. [Rules: Module Stomping / Reflective Loading / Fileless](#10-rules-module-stomping--reflective--fileless)
11. [Rules: Crypto Identification](#11-rules-crypto-identification)
12. [Rules: Embedded Configs & C2](#12-rules-embedded-configs--c2)
13. [Rules: Anti-Analysis / Sandbox Evasion](#13-rules-anti-analysis)
14. [Rules: Script & LOLBin Malware (PS1/JS/VBS/DOC)](#14-rules-script--lolbin)
15. [Rules: .NET Malware](#15-rules-net-malware)
16. [Rules: Go & Rust Implants](#16-rules-go--rust-implants)
17. [Memory-Scanning YARA (pe-sieve / hollows_hunter / yarascan)](#17-memory-scanning-yara)
18. [Detection Engineering Methodology](#18-methodology)
19. [Complete Example: Stealth Loader Ruleset](#19-complete-example)
20. [Appendix: Opcode Reference Card](#20-appendix-opcode-card)

---

## 1. YARA Mental Model — What Actually Persists

Before writing rules, internalize what changes fast vs. what doesn't:

| Layer | Stability | YARA-able? |
|---|---|---|
| Strings (URLs, mutexes, keys, bot tokens) | **days** — rotated per campaign | yes, but high FP / fast decay |
| Encrypted blobs | per-sample | only via decryptor, not YARA |
| **Code patterns** (syscall stubs, PEB walks, hook writes) | **months-years** — compiler/runtime stable | **yes — primary signal** |
| Crypto constants (AES S-box, ChaCha sigma) | years | yes, but also in legit software |
| Import/API combos | months | weak alone, strong combined |
| PE structure anomalies (EP in .rsrc, weird sections) | per-builder | yes via `pe` module |
| TTP combinations | years | best detection = multiple weak signals ANDed |

**Golden rule for stealth malware:** strings are useless (encrypted/stack-built),
so your rules must key on *instruction encodings*, *constants*, and *structure*.
A rule that fires on `0F 05` + `4C 8B D1` + `B8 ?? ?? ?? ??` survives every
string rotation the family does.

### The three string types

```yara
strings:
    $text   = "powershell"              // ASCII text (nocase optional)
    $wide   = "powershell" wide         // UTF-16LE — Windows APIs are wide
    $hex    = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }   // raw bytes — the important one
    $re     = /https?:\/\/[a-z0-9.]+/   // regexp — use sparingly (slow)
```

### The condition grammar essentials

```yara
condition:
    any of them                    // any string matched
    all of them                    // all must match
    2 of ($a,$b,$c)                // at least 2 of these
    $a at entrypoint               // match at PE entry point
    $a in (entrypoint..entrypoint+0x1000)   // within range
    for any i in (1..#a) : ( $a[i] at entrypoint )   // iterate matches
    pe.number_of_sections > 5      // PE module
    uint16(0) == 0x5A4D            // file starts with MZ
    filesize < 1MB                 // file size in bytes
    math.entropy(0, filesize) > 7.0
```

---

## 2. Rule Anatomy & Hex String Syntax Deep Dive

### 2.1 Hex byte patterns — the wildcard grammar

```
{ 48 8B 04 25 60 00 00 00 }        // exact bytes
{ 48 8B ?? 60 }                    // ?? = any byte (ModRM varies by compiler)
{ 48 8B ?4 60 }                    // ?X = high nibble fixed, low nibble wildcard
{ 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }  // SSN is a wildcard — changes per build
{ ( 48 | 4C ) 8B D1 }              // (a|b) alternatives
{ 0F 05 [4] C3 }                   // [n] = exactly n skipped bytes (jump)
{ 0F 05 [2-6] C3 }                  // [n-m] = variable skip 2..6 bytes
{ 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }  // mov rax,imm64; jmp rax — addr wildcarded
```

**Nibble wildcards matter:** ModRM bytes encode registers. `48 8B ?? 60` —
the `??` covers `04 25`/`0D`/`45`/etc. depending on which register the compiler
picked. If you hardcode `48 8B 04 25` you'll miss `48 8B 0D` variants. Learn to
wildcard the ModRM (`??`) while keeping opcodes+displacement (`60 00 00 00`)
exact.

### 2.2 Jump syntax `[n]` vs alternatives

```
{ E8 ?? ?? ?? ?? }        // call rel32 — WRONG-ish: ?? wildcards each byte,
                           // better:  { E8 [4] }  means "call, skip 4 bytes"
{ E8 [4] }                 // cleaner: opcode + 4-byte jump = call rel32
{ 68 [4] C3 }              // push imm32; ret   (4 bytes skipped = imm32)
{ EB [1] }                 // jmp rel8
{ E9 [4] }                 // jmp rel32
```

`[n]` skips n bytes entirely — better than `??` chains because it documents
intent and doesn't accidentally match modified lengths.

### 2.3 `wide` and `ascii` on hex strings

Not applicable — hex strings are raw. For text strings matching UTF-16:

```yara
$a = "kernel32.dll" wide ascii nocase
```

`wide` alone misses ASCII; `ascii wide` covers both encodings of the same
string. For API names malware stores as UTF-16 (module names in PEB), use
`wide`; for ASCII strings in shellcode/configs, `ascii` (default).

### 2.4 Anchoring & position

```yara
$a at 0                    // must be at file offset 0 (e.g., MZ check)
$a at entrypoint           // at PE AddressOfEntryPoint (pe module)
$a in (0..filesize)        // anywhere (default for `any of them` anyway)
for any i in (1..#a) : ( @a[i] < 0x1000 )   // match offset < 4KB
```

### 2.5 Performance rules

- **Shorter strings = faster.** `{ 0F 05 }` alone matches everything — always
  combine with context bytes.
- **Text strings scan faster than huge hex patterns.** Prefer 4-8 byte
  signatures with 1-2 wildcards over 30-byte exact sequences (compiler
  variance breaks exact matches anyway).
- **Regex is slow** — only on small files or with `pe` filters first.
- Put cheap conditions first: `pe.is_pe and uint16(0)==0x5A4D and ...`

---

## 3. The `pe` Module — Structure-Aware Detection

Import in rule header: `import "pe"` then `pe.` functions:

```yara
pe.is_pe                        // valid PE
pe.machine == pe.MACHINE_AMD64  // x64 only
pe.number_of_sections
pe.entry_point                  // RVA of EP
pe.image_base
pe.section_characteristics(0)   // flags of section 0
pe.sections[i].name             // ".text", ".rsrc", ...
pe.sections[i].raw_data_offset
pe.sections[i].raw_data_size
pe.sections[i].virtual_address
pe.sections[i].virtual_size
pe.sections[i].characteristics
pe.imports("kernel32.dll","VirtualAlloc")   // bool
pe.imports("ntdll.dll","NtAllocateVirtualMemory")
pe.exports("...")
pe.imphash()                    // import hash — fragile but useful
pe.timestamp
pe.resource_language_list
pe.rva_to_offset(rva)
```

### 3.1 Structural anomaly rules (very effective vs packers/stagers)

```yara
rule Suspicious_EntryPoint_NotInCode
{
    meta:
        description = "PE entry point lands in a non-executable or non-.text section"
    import "pe"
    condition:
        pe.is_pe and
        for any i in (1..pe.number_of_sections) : (
            pe.entry_point >= pe.sections[i].virtual_address and
            pe.entry_point < pe.sections[i].virtual_address + pe.sections[i].virtual_size and
            not (pe.sections[i].characteristics & 0x20000000)   // IMAGE_SCN_MEM_EXECUTE
        )
}
```

```yara
rule Packed_HighSectionCount_Or_Entropy
{
    meta:
        description = "unusual section names / count typical of crypters"
    import "pe" import "math"
    condition:
        pe.is_pe and
        pe.number_of_sections >= 8 and
        for any i in (1..pe.number_of_sections) : (
            pe.sections[i].name matches /\.[A-Za-z0-9]{1,6}$/ or
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) > 7.0
        )
}
```

`math.entropy(offset, size)` reads the file — very powerful for packed
payloads. Note it reads FILE offsets, so use `raw_data_offset`/`raw_data_size`,
not virtual addresses.

### 3.2 Minimal-import detection (dynamic-resolution tell)

```yara
rule Minimal_Import_Dynamic_Resolver
{
    meta:
        description = "suspiciously small IAT — everything resolved dynamically"
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","LoadLibraryA") and
        pe.imports("kernel32.dll","GetProcAddress") and
        pe.imports("kernel32.dll","VirtualAlloc") and
        // and NOT the APIs you'd expect a normal app to import:
        not pe.imports("kernel32.dll","CreateFileA") and
        not pe.imports("kernel32.dll","RegOpenKeyExA") and
        pe.number_of_imports() < 25     // pseudo — see note below
}
```

(`pe.number_of_imports` doesn't exist as such — count via `for` over
`pe.imports` isn't iterable either; instead approximate by checking absence of
common imports, or compute import count offline and hardcode. In practice:
check "has LoadLibrary+GetProcAddress+VirtualAlloc but lacks typical app
imports" — that's the real signal.)

### 3.3 TLS callbacks (unpackers run before EP)

```yara
rule TLS_Callback_Present
{
    meta:
        description = "TLS directory exists — possible pre-entry unpacker"
    import "pe"
    condition:
        pe.is_pe and
        pe.data_directory[9].virtual_address != 0   // IMAGE_DIRECTORY_ENTRY_TLS
}
```

`pe.data_directory[N]` gives `{virtual_address, size}` — index 9 = TLS.
Combine with high-entropy `.text` → strong packer signal.

---

## 4. The `math` Module — Entropy & Math Conditions

```yara
import "math"
math.entropy(offset, length)     // Shannon entropy 0-8 of file region
math.mean(data)                  // for files loaded as data
```

**Entropy cheat sheet:**

| Entropy | Meaning |
|---|---|
| < 5.5 | code/text/structured data |
| 5.5–6.5 | mixed code+data, some packed |
| 6.5–7.2 | compressed or encrypted |
| > 7.2 | encrypted/compressed blob — payload or packed section |

Whole-file entropy > 7.2 on a small PE = almost certainly packed.
Per-section entropy via `pe.sections[i]` loop (see §3.2) is more precise —
a legit installer has high entropy in `.rsrc` (icons) but low in `.text`.

**Caveat:** `math.entropy` reads file bytes — doesn't work on memory dumps
(there it's just byte entropy of the dump region; still useful, see §17).

---

## 5. Rules: Dynamic Resolution / PEB Walking

### 5.1 PEB anchor access (x64)

The `gs:[0x60]` access is the most reliable indicator — every PEB walker
starts here. ModRM varies: `48 8B 04 25`, `48 8B 0D`, `4C 8B`, `65 48 8B`...

```yara
rule win_x64_PEB_Access
{
    meta:
        description = "reads PEB via gs:[60h] — loader-list walking / anti-debug"
    strings:
        // mov r?, gs:[60h]  — ModRM wildcarded, disp32 = 60 00 00 00
        $gs60  = { 65 48 8B ?? 60 00 00 00 }
        $gs60b = { 65 4C 8B ?? 60 00 00 00 }
        // mov r?, gs:[60h] with SIB form
        $gs60c = { 65 48 8B 04 25 60 00 00 00 }
        // BeingDebugged check: cmp byte ptr [rax+2], 0  (PEB+2)
        $dbg   = { 80 78 02 00 }              // cmp byte [rax+2],0
        $dbg2  = { 80 B8 02 00 00 00 00 }     // cmp byte [rax+2],0 (disp32)
    condition:
        any of ($gs60*) and any of ($dbg*)
}
```

**x86 variant** (`fs:[0x30]`):

```yara
rule win_x86_PEB_Access
{
    strings:
        $fs30 = { 64 A1 30 00 00 00 }         // mov eax, fs:[30h]
        $fs30b= { 64 8B ?? 30 00 00 00 }      // mov r?, fs:[30h]
    condition:
        any of them
}
```

### 5.2 Ldr traversal + DllBase/BaseDllName offsets

Once PEB is found, walkers hit `+0x18` (Ldr), `+0x10` (InLoadOrder), `+0x30`
(DllBase), `+0x58` (BaseDllName). These offsets appear as displacements:

```yara
rule win_Ldr_Walk_Offsets
{
    meta:
        description = "PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY offset access pattern"
    strings:
        $ldr    = { 48 8B ?? 18 }             // mov r?, [r?+18h]  PEB->Ldr
        $dllbase= { 48 8B ?? 30 }             // mov r?, [r?+30h]  DllBase
        $basename={ 48 8B ?? 58 }             // mov r?, [r?+58h]  BaseDllName
        $ordlink= { 48 8B ?? 10 }             // InLoadOrderModuleList +0x10
    condition:
        3 of them
}
```

These are WEAK alone (offsets are common) — always AND with `$gs60` or a hash
loop to avoid FPs on legit software that walks PEB (some debuggers, AVs do).

### 5.3 API-name hashing loops

ROR13/DJB2 hashing = rotate + add in a tight loop over characters:

```yara
rule win_API_Hash_Loop
{
    meta:
        description = "ror/rol + add loop = API/export name hashing"
    strings:
        // ror r32, 13  = C1 C8 0D ; ror r64,13 = 48 C1 C8 0D
        $ror13_32 = { C1 C8 0D }
        $ror13_64 = { 48 C1 C8 0D }
        $rol5_32 = { C1 C0 05 }               // rol 5 (djb2 h*33 variant)
        $rol5_64 = { 48 C1 C0 05 }
        // also common: ror r?,13 with other regs -> C1 C9..CF 0D
        $ror13_any = { C1 C? 0D }
    condition:
        any of ($ror13*) and any of ($rol5*)
}
```

**Better:** combine hash loop + PEB access + export-walk offsets — the
triple is nearly unique to dynamic resolvers:

```yara
rule win_Dynamic_API_Resolver_Full
{
    meta:
        description = "PEB walk + hashing = API-hashing resolver (pair with minimal-import check)"
    strings:
        $peb = { 65 48 8B ?? 60 00 00 00 }
        $ror = { C1 C? 0D }                  // ror r?,13
        $rol = { C1 C? 05 }                  // rol r?,5
    condition:
        $peb and ($ror or $rol)
}
```

*(The export-table walk itself — three parallel RVA arrays via `base+RVA` —
is hard to signature in pure bytes because the offsets are computed at
runtime. In practice `$peb + ($ror or $rol)` is specific enough when ANDed
with the minimal-import structural check from §3.3.)*

---

## 6. Rules: Direct & Indirect Syscalls

### 6.1 The money rule — direct syscall stub

```
mov r10, rcx        4C 8B D1
mov eax, <SSN>      B8 xx xx xx xx
syscall             0F 05
ret                 C3
```

```yara
rule win_Direct_Syscall_Stub
{
    meta:
        description = "mov r10,rcx; mov eax,imm; syscall; ret — direct syscall"
        author = "analyst"
    strings:
        $stub    = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3 }
        $stub_nore = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }   // without ret
        // variant: mov eax first then r10 (rare)
        $stub2   = { B8 ?? ?? ?? ?? 4C 8B D1 0F 05 }
    condition:
        any of them
}
```

**CRITICAL caveat:** this matches *legitimate ntdll stubs too* — ntdll is full
of `4C 8B D1 B8 ?? 0F 05 C3`. For FILE scanning, exclude ntdll or require the
pattern in a non-ntdll context:

```yara
rule win_Direct_Syscall_In_PE
{
    meta:
        description = "direct syscall stub inside a PE file (not ntdll itself)"
    strings:
        $stub = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3 }
    condition:
        pe.is_pe and
        // exclude actual ntdll.dll by name check done at scan time,
        // or require additional suspicious context:
        $stub and pe.imports("kernel32.dll","VirtualAlloc")
}
```

For MEMORY scanning (§17) you scan per-module so ntdll is excluded by path —
the rule then catches only rogue stubs.

### 6.2 Indirect syscall — jump to syscall;ret gadget

Indirect syscalls `jmp`/`call` a `0F 05 C3` gadget inside ntdll. The malware
code has the SSN load + a register-indirect jump, NOT an inline `0F 05`:

```yara
rule win_Indirect_Syscall_Pattern
{
    meta:
        description = "SSN load + jmp/call reg — indirect syscall via ntdll gadget"
    strings:
        // mov r10,rcx; mov eax,imm; jmp/call r??  (no inline syscall!)
        $ind1 = { 4C 8B D1 B8 ?? ?? ?? ?? FF E? }   // jmp r??
        $ind2 = { 4C 8B D1 B8 ?? ?? ?? ?? FF 1? }   // call [r?] / call r?
        $ind3 = { 4C 8B D1 B8 ?? ?? ?? ?? 41 FF }   // jmp r8-r15
    condition:
        any of them
}
```

Also detect the **gadget itself** when scanning ntdll copies — a clean
`0F 05 C3` inside a *remapped* ntdll is normal; inside a *patched* ntdll it's
the hook point.

### 6.3 Halo's Gate / SSN-from-neighbor

Halo's Gate resolves the SSN of a *neighboring* function when the target stub
is hooked — reads `mov eax, imm` at `func ± N`. Pattern: a function that
walks an array of ntdll function pointers and reads `[ptr+4]`:

```yara
rule win_SSN_DownLevel_HaloGate
{
    meta:
        description = "reads mov eax,imm SSN from stub+4 — Halo's/Tartarus Gate"
    strings:
        // mov eax, [reg+4]  = 8B 4? 04  or  41 8B 4? 04
        $ssnread1 = { 8B ?? 04 }
        $ssnread2 = { 41 8B ?? 04 }
        // syscall stub anchor nearby
        $syscall = { 0F 05 }
    condition:
        any of ($ssnread*) and any of ($syscall*)
}
```

(Weak — combine with direct/indirect syscall rules.)

### 6.4 Syscall via byte-array stub (fileless style)

Some malware stores the stub as a **data array** not code — `{ 4C 8B D1 B8 ... }`
in `.data` then VirtualAllocs+copies. The YARA above catches the byte pattern
anywhere in the file regardless of section — good.

---

## 7. Rules: Injection & Hollowing

### 7.1 Classic injection — API import combination

```yara
rule win_Classic_Injection_APIs
{
    meta:
        description = "OpenProcess+VirtualAllocEx+WriteProcessMemory+CreateRemoteThread"
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","OpenProcess") and
        pe.imports("kernel32.dll","VirtualAllocEx") and
        pe.imports("kernel32.dll","WriteProcessMemory") and
        pe.imports("kernel32.dll","CreateRemoteThread")
}
```

**FP note:** legit software (debuggers, some AV, installers) uses these.
Strengthen by adding `NtCreateThreadEx` or requiring absence of GUI imports:

```yara
rule win_Injection_APIs_NoLegitContext
{
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","OpenProcess") and
        pe.imports("kernel32.dll","VirtualAllocEx") and
        pe.imports("kernel32.dll","WriteProcessMemory") and
        pe.imports("kernel32.dll","CreateRemoteThread") and
        // suspicious: also resolves APIs dynamically (minimal other imports)
        pe.imports("kernel32.dll","LoadLibraryA") and
        pe.imports("kernel32.dll","GetProcAddress") and
        not pe.imports("user32.dll","MessageBoxA") and
        not pe.imports("kernel32.dll","CreateFileA")
}
```

### 7.2 Process hollowing — the API fingerprint

`CREATE_SUSPENDED` + `NtUnmapViewOfSection` + `SetThreadContext` +
`ResumeThread` is the hollowing signature:

```yara
rule win_Process_Hollowing_APIs
{
    meta:
        description = "suspended create + unmap + SetThreadContext = hollowing"
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","CreateProcessA") or
        pe.imports("kernel32.dll","CreateProcessW")
    // note: CreateProcess flags aren't visible in IAT — see §7.3 for the
    // constant check
}
```

The `CREATE_SUSPENDED` flag (0x4) is passed as an immediate to CreateProcess —
look for the constant `4` in the flags arg. Hard to YARA directly; instead
rely on the API combo:

```yara
rule win_Hollowing_Full_Chain
{
    import "pe"
    condition:
        pe.is_pe and
        (pe.imports("kernel32.dll","CreateProcessA") or
         pe.imports("kernel32.dll","CreateProcessW")) and
        (pe.imports("ntdll.dll","NtUnmapViewOfSection") or
         pe.imports("kernel32.dll","WriteProcessMemory")) and
        pe.imports("kernel32.dll","SetThreadContext") and
        pe.imports("kernel32.dll","ResumeThread") and
        pe.imports("kernel32.dll","GetThreadContext")
}
```

### 7.3 APC injection

```yara
rule win_APC_Injection
{
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","QueueUserAPC") and
        pe.imports("kernel32.dll","OpenThread") and
        pe.imports("kernel32.dll","VirtualAllocEx")
}
```

### 7.4 Thread hijacking

```yara
rule win_Thread_Hijack
{
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","SuspendThread") and
        pe.imports("kernel32.dll","GetThreadContext") and
        pe.imports("kernel32.dll","SetThreadContext") and
        pe.imports("kernel32.dll","ResumeThread") and
        pe.imports("kernel32.dll","OpenThread")
}
```

### 7.5 Nt* transaction/doppelgänging sequences

```yra
rule win_Transaction_Doppelganging
{
    meta:
        description = "NtCreateTransaction+NtCreateSection+NtRollbackTransaction = doppelgänging"
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("ntdll.dll","NtCreateTransaction") and
        pe.imports("ntdll.dll","NtCreateSection") and
        pe.imports("ntdll.dll","NtRollbackTransaction")
}
```

### 7.6 RWX allocation constant

`PAGE_EXECUTE_READWRITE` = 0x40 passed as arg — appears as `mov r9d, 40h` or
`mov edx, 40h` or `mov ecx, 40h` before VirtualAlloc:

```yara
rule win_RWX_Alloc_Constant
{
    meta:
        description = "PAGE_EXECUTE_READWRITE (0x40) immediate before alloc call"
    strings:
        $r9_40  = { 41 B9 40 00 00 00 }   // mov r9d, 40h  (6th arg = flProtect)
        $edx_40 = { BA 40 00 00 00 }      // mov edx, 40h
        $ecx_40 = { B9 40 00 00 00 }      // mov ecx, 40h
        $r8d_40 = { 41 B8 40 00 00 00 }   // mov r8d, 40h
    condition:
        any of them and pe.is_pe
}
```

**FP warning:** 0x40 is common — combine with VirtualAlloc import or syscall
stub presence.

---

## 8. Rules: Sleep Obfuscation (Ekko / Foliage / Nighthawk)

Sleep obfuscation encrypts the implant's `.text` while it sleeps, decrypts on
wake — defeats memory scanners. Three main flavors:

| Tool | Encrypt region | Cipher | Key storage |
|---|---|---|---|
| **Ekko** | own `.text` | RC4 via `SystemFunction032` (advapi32) | ROR13-derived key on heap |
| **Foliage** | `.text` | AES-256 | key derived from timers |
| **Nighthawk** | `.text` | custom stream cipher | per-build key |

### 8.1 Ekko signature — RC4 + ROR13 + timer wait

Ekko's tell: calls `SystemFunction032` (advapi32 RC4) in a loop +
`WaitForSingleObjectEx`/`SleepEx` for the sleep + ROR13 key math:

```yara
rule win_Ekko_SleepObfuscation
{
    meta:
        description = "Ekko timer-sleep obfuscation: RC4(SystemFunction032)+ROR13+alertable wait"
    import "pe"
    strings:
        $rc4api = "SystemFunction032" ascii wide
        $waitex = "WaitForSingleObjectEx" ascii wide
        $sleepex= "SleepEx" ascii wide
        $ror13  = { C1 C? 0D }                  // ror r?,13 key derivation
        $rc4loop= { ?? ?? ?? ?? ?? ?? ?? ?? 0F B6 } // RC4-ish byte loop (weak)
    condition:
        any of ($rc4api,$waitex,$sleepex) and $ror13
}
```

### 8.2 Generic "encrypt-own-.text-while-sleeping" heuristic

The universal pattern: `VirtualProtect(.text→RW)` → crypto loop →
`WaitForSingleObjectEx(alertable)` → crypto loop → `VirtualProtect(→RX)`. In
YARA: look for VirtualProtect + WaitForSingleObjectEx + crypto constants:

```yara
rule win_SleepObfuscation_Generic
{
    meta:
        description = "VirtualProtect + alertable wait + crypto = sleep obfuscation"
    import "pe"
    strings:
        $vp    = "VirtualProtect" ascii wide
        $wfs   = "WaitForSingleObjectEx" ascii wide
        $aes   = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $chacha= "expand 32-byte k" ascii
    condition:
        all of ($vp,$wfs) and any of ($aes,$chacha)
}
```

### 8.3 Nighthawk/Foliage — AES-NI instructions

```yara
rule win_AESNI_Instructions
{
    meta:
        description = "AES-NI aesenc/aesenclast — Foliage/Nighthawk sleep obf + C2 crypto"
    strings:
        $aesenc  = { 66 0F 38 DC }              // aesenc xmm, xmm/m128
        $aesencl = { 66 0F 38 DD }              // aesenclast
        $aesimc  = { 66 0F 38 DB }              // aesimc
        $aeskey  = { 66 0F 3A DF }              // aeskeygenassist
    condition:
        2 of them
}
```

---

## 9. Rules: Hooking, Unhooking, AMSI/ETW Patching

### 9.1 Inline-hook write stub (the `48 B8 .. FF E0` pattern)

```yara
rule win_InlineHook_Stub_Bytes
{
    meta:
        description = "mov rax,imm64; jmp rax = inline hook prologue"
    strings:
        $movrax_jmp = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
        $jmp_rip0   = { FF 25 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }  // jmp [rip+0]; dq addr
        $push_ret   = { 68 ?? ?? ?? ?? C7 44 24 04 ?? ?? ?? ?? C3 } // push/jmp [rsp+4] style
    condition:
        any of them and pe.is_pe
}
```

### 9.2 ntdll unhooking — remap from disk

Signature: file I/O on `ntdll.dll` + `CreateFileMapping`/`MapViewOfFile` +
memcpy into ntdll `.text`:

```yara
rule win_Ntdll_Unhook_Remmap
{
    meta:
        description = "maps ntdll.dll from disk to restore clean stubs"
    strings:
        $ntdll_path = "ntdll.dll" ascii wide nocase
        $sys32      = "\\System32\\" ascii wide nocase
        $mapview    = "MapViewOfFile" ascii wide
        $createfile = "CreateFileW" ascii wide
        $createfileA= "CreateFileA" ascii wide
    condition:
        $ntdll_path and any of ($mapview,$createfile,$createfileA)
}
```

### 9.3 AMSI/ETW patch bytes

The patched function's first bytes become a tiny stub — these byte patterns
appear in the *payload* that writes them, or in memory dumps of patched
amsi/ntdll:

```yara
rule win_AMSI_ETW_Patch_Stubs
{
    meta:
        description = "ret / xor eax,eax;ret / mov eax,0;ret patch stubs"
    strings:
        $p1 = { 31 C0 C3 }                  // xor eax,eax; ret  (x64/x86)
        $p2 = { 33 C0 C3 }                  // xor eax,eax; ret  (alt)
        $p3 = { B8 00 00 00 00 C3 }        // mov eax,0; ret
        $p4 = { 48 31 C0 C3 }               // xor rax,rax; ret (x64 64-bit ret val)
        $p5 = { C3 }                        // bare ret — too common alone
    condition:
        2 of ($p1,$p2,$p3,$p4)             // require multiple patch stubs
}
```

For FILE scanning, `$p5` alone is useless; the combo rule catches droppers
carrying patch shellcode. For MEMORY scanning (§17), a bare `C3` at
`amsi!AmsiScanBuffer` offset 0 is the precise check — see §17.4.

### 9.4 Trampoline buffer pattern

Trampolines end with `jmp target+N` — look for `mov rax,imm64; jmp rax`
appended after copied bytes. The `48 B8 ?? FF E0` rule above catches it.

---

## 10. Rules: Module Stomping / Reflective / Fileless

### 10.1 Module stomping — WriteProcessMemory on own module

Stomping overwrites a legit DLL's `.text` in-memory. Signature: `LoadLibrary`
+ `WriteProcessMemory` targeting own process + no `VirtualAllocEx` (it's
self-injection):

```yara
rule win_Module_Stomping_APIs
{
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","LoadLibraryA") and
        pe.imports("kernel32.dll","WriteProcessMemory") and
        pe.imports("kernel32.dll","GetModuleHandleA") and
        pe.imports("kernel32.dll","VirtualProtect") and
        // self-injection: WriteProcessMemory but NOT VirtualAllocEx/remote
        not pe.imports("kernel32.dll","VirtualAllocEx") and
        not pe.imports("kernel32.dll","OpenProcess")
}
```

### 10.2 Reflective DLL injection

sRDI payloads are position-independent DLLs with NO imports — they resolve
everything via PEB walk. Detect: PE with export dir but ~0 imports + PEB
walk + export resolution:

```yara
rule win_Reflective_DLL_NoImports
{
    meta:
        description = "DLL with export table but virtually no imports = reflective loader"
    import "pe"
    condition:
        pe.is_pe and
        pe.exports("ReflectiveLoader") or
        (
            pe.is_pe and
            pe.number_of_sections > 0 and
            // PEB walk present
            for any i in (1..#dummy) : ( true )
        )
}
```

*(Better approach: check `pe.imports` count is tiny AND `$peb` pattern
present AND it's a DLL (`pe.characteristics & 0x2000` = IMAGE_FILE_DLL).)*

```yara
rule win_Reflective_DLL_Proper
{
    import "pe"
    strings:
        $peb = { 65 48 8B ?? 60 00 00 00 }
    condition:
        pe.is_pe and
        (pe.characteristics & 0x2000) != 0 and        // DLL
        $peb and
        // almost no imports — sRDI resolves everything manually
        not pe.imports("kernel32.dll","CreateFileA") and
        not pe.imports("kernel32.dll","WriteFile")
}
```

### 10.3 Fileless / no-PE-on-disk payloads

Stage-2 payloads often have **no valid PE header** — they're shellcode blobs.
Detect via shellcode patterns (NOP sleds, API-hash stubs, syscall stubs) in
non-PE files:

```yara
rule win_Shellcode_Blob_NoMZ
{
    meta:
        description = "shellcode-like byte patterns in a file without MZ header"
    strings:
        $syscall = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
        $peb     = { 65 48 8B ?? 60 00 00 00 }
        $hook    = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
        $nop_sled= { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        not uint16(0) == 0x5A4D and                 // no MZ
        2 of them
}
```

### 10.4 PE header anomalies — overwritten MZ/PE signatures

Some fileless techniques wipe the MZ/PE magic after loading:

```yara
rule win_Wiped_PE_Signature
{
    meta:
        description = "file claims PE-ish structure but MZ/PE magic destroyed"
    strings:
        $mz = { 4D 5A }                              // MZ
        $pe = { 50 45 00 00 }                        // PE\0\0
    condition:
        // file has PE-ish size/structure hints but magic missing —
        // combined with shellcode patterns above for confidence
        not $mz at 0 and filesize > 0x1000 and filesize < 0x100000
}
```

*(Weak alone — use as a supporting signal.)*

---

## 11. Rules: Crypto Identification

### 11.1 AES constants

```yara
rule win_AES_Constants
{
    meta:
        description = "AES S-box / inverse S-box / Rcon"
    strings:
        $sbox    = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $isbox   = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
        $rcon    = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 }
    condition:
        any of them
}
```

**FP warning:** AES S-box appears in legit crypto software, OpenSSL, etc.
Strengthen by requiring it alongside suspicious imports or in a small binary:

```yara
rule win_AES_In_Suspicious_Context
{
    import "pe"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox and pe.is_pe and pe.number_of_sections < 10 and
        pe.imports("kernel32.dll","VirtualAlloc")
}
```

### 11.2 AES-NI instructions (hardware crypto — different from tables)

```yara
rule win_AESNI_OpCodes
{
    strings:
        $enc  = { 66 0F 38 DC }        // aesenc
        $encl = { 66 0F 38 DD }        // aesenclast
        $imc  = { 66 0F 38 DB }        // aesimc
        $key  = { 66 0F 3A DF }        // aeskeygenassist
    condition:
        2 of them
}
```

### 11.3 ChaCha20/Salsa20

```yara
rule win_Chacha20
{
    meta:
        description = "ChaCha20 'expand 32-byte k' constant"
    strings:
        $sigma = "expand 32-byte k" ascii
        $tau   = "expand 16-byte k" ascii
    condition:
        any of them
}
```

### 11.4 SHA-256 constants

```yra
rule win_SHA256_Constants
{
    strings:
        $k = { 67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5 }
    condition:
        $k
}
```

### 11.5 RC4 — no constants, but the pattern

RC4 has no magic constant — detect via the KSA structure: 256-byte init loop
+ nested shuffle with `& 0xFF`. Hard in pure YARA; instead look for the
`SystemFunction032` API (advapi32's RC4 export — what Ekko/many families call):

```yara
rule win_RC4_SystemFunction032
{
    import "pe"
    strings:
        $fn = "SystemFunction032" ascii wide
    condition:
        $fn
}
```

### 11.6 XOR-decrypt loop signature

The byte-wise XOR loop is too generic for YARA alone, but combined with a
high-entropy `.data` blob it works:

```yara
rule win_XOR_Decrypt_Loop_Heuristic
{
    meta:
        description = "xor byte [mem],reg/imm in loop over .data — weak, combine"
    strings:
        // xor al, [rbx+rcx] style — too compiler-specific; use as supporting
        $xor1 = { 30 ?? }              // xor r/m8, r8
        $xor2 = { 32 ?? }              // xor r8, r/m8
    condition:
        pe.is_pe and any of them and math.entropy(0, filesize) > 6.0
}
```

*(Honestly: XOR loops are nearly impossible to signature reliably — better
to detect the RESULT: high-entropy blob + minimal imports + PEB walk = the
resolver+decryptor combo from §5.)*

---

## 12. Rules: Embedded Configs & C2

### 12.1 Telegram/Discord exfil C2

```yara
rule win_Telegram_Discord_C2
{
    meta:
        description = "hardcoded Telegram bot API / Discord webhook = stealer/RAT C2"
    strings:
        $tg    = "api.telegram.org/bot" ascii wide nocase
        $tg2   = "api.telegram.org" ascii wide nocase
        $dc    = "discord.com/api/webhooks/" ascii wide nocase
        $dc2   = "discordapp.com/api/webhooks/" ascii wide nocase
        $sendm = "sendMessage" ascii wide
        $sendd = "sendDocument" ascii wide
        $tgfile= "sendPhoto" ascii wide
    condition:
        any of ($tg*) or (any of ($dc*) and any of ($sendm,$sendd,$tgfile))
}
```

### 12.2 Hardcoded C2 URL patterns

```yara
rule win_Suspicious_C2_URLs
{
    meta:
        description = "HTTP(S) URLs to bulletproof-ish TLDs/hosts in binary"
    strings:
        $https = "https://" ascii wide
        $http  = "http://" ascii wide
        $tld1  = ".top" ascii wide nocase
        $tld2  = ".xyz" ascii wide nocase
        $tld3  = ".ru" ascii wide nocase
        $tld4  = ".cn" ascii wide nocase
        $tld5  = ".info" ascii wide nocase
        $ip    = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:\/]/   // IP:port or IP/path
    condition:
        any of ($http,$https) and any of ($tld*)
}
```

### 12.3 Config blob in resources/overlay

High-entropy `.rsrc` or overlay data:

```yara
rule win_HighEntropy_Resource_Or_Overlay
{
    meta:
        description = "encrypted config/payload in resources or overlay"
    import "pe" import "math"
    condition:
        pe.is_pe and (
            for any i in (1..pe.number_of_sections) : (
                pe.sections[i].name == ".rsrc" and
                math.entropy(pe.sections[i].raw_data_offset,
                             pe.sections[i].raw_data_size) > 7.0
            )
        )
}
```

### 12.4 Mutex / campaign markers

```yara
rule win_Malware_Mutex_Patterns
{
    meta:
        description = "common malware mutex/global object naming"
    strings:
        $m1 = "Global\\" ascii wide
        $m2 = "Local\\" ascii wide
        $m3 = /mutex/i ascii
    condition:
        any of them
}
```

*(Weak — mutex strings appear in legit software too. Combine with other
signals.)*

### 12.5 DNS tunneling indicators

Long encoded subdomains, base32/base64-looking labels:

```yara
rule win_DNS_Tunnel_Indicators
{
    meta:
        description = "long base32/64 subdomain labels = possible DNS C2"
    strings:
        $longlabel = /[a-z0-9]{40,}\.[a-z0-9.-]+/i
        $base64ish= /[A-Za-z0-9+/]{50,}={0,2}/
    condition:
        any of them
}
```

### 12.6 JA3/JARM — can't YARA, but note for analysts

TLS fingerprinting (JA3/JA3S/JARM) happens at the network layer, not file —
use it in Suricata/Zeek, not YARA. Go/Rust implants have distinctive JA3s.

---

## 13. Rules: Anti-Analysis / Sandbox Evasion

### 13.1 Anti-debug API combos

```yara
rule win_AntiDebug_APIs
{
    import "pe"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll","IsDebuggerPresent") and
        pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and
        pe.imports("ntdll.dll","NtQueryInformationProcess")
}
```

### 13.2 VM/sandbox artifact strings

```yara
rule win_VM_Sandbox_Artifacts
{
    meta:
        description = "VM drivers, sandbox artifacts, analysis tool names"
    strings:
        $vm1  = "vmtools" ascii wide nocase
        $vm2  = "vbox" ascii wide nocase
        $vm3  = "vmware" ascii wide nocase
        $vm4  = "qemu" ascii wide nocase
        $vm5  = "xen" ascii wide nocase
        $sb1  = "SbieDll" ascii wide          // Sandboxie
        $sb2  = "cuckoo" ascii wide nocase
        $sb3  = "wireshark" ascii wide nocase
        $sb4  = "fiddler" ascii wide nocase
        $dbg1 = "x64dbg" ascii wide nocase
        $dbg2 = "x32dbg" ascii wide nocase
        $dbg3 = "ollydbg" ascii wide nocase
        $dbg4 = "ida" ascii wide nocase      // careful — "ida" substring FP
        $wine = "wine_get_version" ascii
    condition:
        2 of them
}
```

**FP note:** `$dbg4 "ida"` will match "candidate", "validate" etc — use
`fullword` modifier or drop it. Always test rules against benign corpus.

### 13.3 Timing checks — rdtsc / GetTickCount loops

```yara
rule win_Timing_Checks
{
    meta:
        description = "rdtsc instruction or tight timing loop = anti-debug"
    strings:
        $rdtsc = { 0F 31 }                    // rdtsc
        $rdtscp= { 0F 01 F9 }                 // rdtscp
    condition:
        any of them and pe.is_pe
}
```

### 13.4 Sleep-with-encrypted-memory setup

Covered in §8 — the combination VirtualProtect+WaitForSingleObjectEx+crypto
is the sleep-obfuscation signature.

### 13.5 Parent process / environment checks

Look for strings: `explorer.exe`, parent PID checks via
`NtQueryInformationProcess(ProcessBasicInformation)`, username/hostname
blocklists. Hard to YARA reliably — focus on the API:

```yra
rule win_Environment_Checks
{
    import "pe"
    strings:
        $pbi = "ProcessBasicInformation" ascii wide
        $cur = "CurrentDirectory" ascii wide
    condition:
        pe.is_pe and any of them
}
```

---

## 14. Rules: Script & LOLBin Malware (PS1/JS/VBS/DOC)

Malware increasingly arrives as scripts or macro-laden docs that download/run
payloads. YARA scans these file types directly.

### 14.1 PowerShell cradle patterns

```yara
rule ps_suspicious_cradles
{
    meta:
        description = "PowerShell download/execute cradle patterns"
    strings:
        $b64    = "FromBase64String" ascii nocase
        $iex    = "Invoke-Expression" ascii nocase
        $iex2   = "IEX" ascii nocase
        $wcdl   = "WebClient" ascii nocase
        $dl     = "DownloadString" ascii nocase
        $dl2    = "DownloadFile" ascii nocase
        $enc    = "-enc" ascii nocase
        $ep     = "-ep" ascii nocase
        $wha    = "-w hidden" ascii nocase
        $byp    = "-ExecutionPolicy" ascii nocase
        $encbyp = "Bypass" ascii nocase
        $amsi   = "AmsiScanBuffer" ascii nocase
        $refl   = "Reflection.Assembly" ascii nocase
        $load   = "[Reflection.Assembly]::Load" ascii nocase
    condition:
        (any of ($b64,$iex,$iex2) and any of ($wcdl,$dl,$dl2)) or
        ($enc and $byp) or
        ($amsi and any of ($iex,$refl,$load))
}
```

### 14.2 JavaScript / HTA / VBS droppers

```yra
rule script_js_hta_droppers
{
    meta:
        description = "JS/HTA/VBS download-and-execute patterns"
    strings:
        $wscript = "WScript.Shell" ascii nocase
        $shell   = "Shell.Application" ascii nocase
        $run     = "Run(" ascii nocase
        $http    = "MSXML2.XMLHTTP" ascii nocase
        $http2   = "WinHttp.WinHttpRequest" ascii nocase
        $adodb   = "ADODB.Stream" ascii nocase
        $cert    = "certutil" ascii nocase
        $bits    = "bitsadmin" ascii nocase
        $powersh = "powershell" ascii nocase
        $cmd     = "cmd.exe" ascii nocase
        $regsvr  = "regsvr32" ascii nocase
        $mshta   = "mshta" ascii nocase
        $eval    = "eval(" ascii nocase
        $unescape= "unescape(" ascii nocase
        $fromch  = "String.fromCharCode" ascii nocase
    condition:
        any of ($http,$http2,$adodb) and any of ($wscript,$shell,$run,$powersh,$cmd) or
        any of ($cert,$bits,$regsvr,$mshta) and any of ($http,$powersh,$run)
}
```

### 14.3 Office macro indicators

```yara
rule office_macro_suspicious
{
    meta:
        description = "VBA macro download/execute patterns in Office docs"
    strings:
        $autoopen = "AutoOpen" ascii nocase
        $document = "Document_Open" ascii nocase
        $shell    = "Shell(" ascii nocase
        $createobj= "CreateObject" ascii nocase
        $powersh  = "powershell" ascii nocase
        $cmd      = "cmd.exe" ascii nocase
        $http     = "MSXML2" ascii nocase
        $url      = "http://" ascii nocase
        $url2     = "https://" ascii nocase
        $eval     = "Eval" ascii nocase
        $chr      = "Chr(" ascii nocase
        $base64   = "Base64" ascii nocase
    condition:
        (any of ($autoopen,$document) and any of ($shell,$powersh,$cmd,$http)) or
        (any of ($createobj,$eval) and any of ($url,$url2,$chr,$base64))
}
```

### 14.4 LOLBin command lines (for process cmdline telemetry — pair with Sigma)

YARA scans file content; process command lines are better in Sigma, but if
you YARA scan script/log files containing cmdlines:

```yara
rule lolbin_execution_strings
{
    meta:
        description = "LOLBin abuse command patterns (in scripts/logs/dumps)"
    strings:
        // certutil
        $cert    = "certutil" ascii nocase
        $certdec = "-decode" ascii nocase
        $certurl = "-urlcache" ascii nocase
        // bitsadmin
        $bits    = "bitsadmin" ascii nocase
        $bitstr  = "/transfer" ascii nocase
        // mshta / script hosts
        $mshta   = "mshta" ascii nocase
        $vbs     = "vbscript" ascii nocase
        $js      = "javascript" ascii nocase
        // regsvr32 scrobj
        $regsvr  = "regsvr32" ascii nocase
        $scrobj  = "/s /i" ascii nocase
        // rundll32 js
        $rundll  = "rundll32" ascii nocase
        // wmic process create
        $wmic    = "wmic" ascii nocase
        $wmicps  = "process call create" ascii nocase
        // forfiles / pcalua proxies
        $forfiles= "forfiles" ascii nocase
        $fc      = "/c " ascii nocase
        $pcalua  = "pcalua" ascii nocase
        $pca     = "-a " ascii nocase
        // msbuild / installutil / regasm inline-task abuse
        $msbuild = "msbuild" ascii nocase
        $xml     = ".xml" ascii nocase
        $instutil= "installutil" ascii nocase
        $iu      = "/u" ascii nocase
        $regasm  = "regasm" ascii nocase
        $msxsl   = "msxsl" ascii nocase
    condition:
        ($cert and any of ($certdec,$certurl)) or
        ($bits and $bitstr) or
        ($mshta and any of ($vbs,$js)) or
        ($regsvr and $scrobj) or
        ($rundll and $js) or
        ($wmic and $wmicps) or
        ($forfiles and $fc) or
        ($pcalua and $pca) or
        ($msbuild and $xml) or
        ($instutil and $iu) or
        ($regasm and $iu) or
        $msxsl
}
```

### 14.5 Shellcode in scripts — FromBase64String + Invoke

```yra
rule ps_encoded_shellcode_loader
{
    meta:
        description = "base64-encoded payload + invoke = fileless loader"
    strings:
        $b64   = "FromBase64String" ascii nocase
        $invo  = "Invoke-" ascii nocase
        $mem   = "VirtualAlloc" ascii nocase
        $marshal= "Marshal" ascii nocase
        $ptr    = "GetDelegateForFunctionPointer" ascii nocase
        $shellcode_hint = /[A-Za-z0-9+/]{200,}={0,2}/   // long b64 blob
    condition:
        $b64 and any of ($invo,$mem,$ptr) and $shellcode_hint
}
```

---

## 15. Rules: .NET Malware

.NET stealers/RATs (AgentTesla, Formbook, AsyncRAT, Quasar, many stealers)
are best analyzed in dnSpy, but YARA can catch them at file level:

### 15.1 .NET assembly detection

```yra
rule dotnet_assembly_present
{
    meta:
        description = "PE contains CLR header = .NET assembly"
    import "pe"
    condition:
        pe.is_pe and pe.data_directory[14].virtual_address != 0   // COM descriptor dir
}
```

### 15.2 ConfuserEx/obfuscation indicators

```yra
rule dotnet_confuserex_indicators
{
    meta:
        description = "ConfuserEx/Obfuscar constants and renamed patterns"
    strings:
        $cf1 = "Confuser" ascii wide nocase
        $cf2 = "KoiVM" ascii nocase
        $anti   = "AntiTamper" ascii nocase
        $ctrl   = "ControlFlow" ascii nocase
        $priv   = "PrivateImplementationDetails" ascii nocase
    condition:
        any of them
}
```

### 15.3 .NET injection / Assembly.Load patterns

```yra
rule dotnet_reflective_load
{
    meta:
        description = ".NET Assembly.Load(byte[]) = reflective .NET injection"
    strings:
        $al = "Assembly.Load" ascii wide nocase
        $invoke = "Invoke" ascii wide nocase
        $gettype = "GetType" ascii wide nocase
        $unmanaged = "UnmanagedFunctionPointer" ascii nocase
        $marshal = "Marshal" ascii wide nocase
    condition:
        $al and any of ($invoke,$gettype,$marshal)
}
```

### 15.4 AgentTesla/stealer config indicators

```yra
rule dotnet_stealer_config_indicators
{
    meta:
        description = "stealer config fields: FTP/email/telegram/build IDs"
    strings:
        $ftp = "ftp://" ascii wide nocase
        $smtp = "smtp." ascii wide nocase
        $mail = "MAIL" ascii wide nocase
        $tg = "api.telegram.org" ascii wide nocase
        $mutex = "Mutex" ascii wide nocase
        $build = "Build" ascii wide nocase
        $version = "Version" ascii wide nocase
        $keylog = "Keylog" ascii wide nocase
        $screenshot = "Screenshot" ascii wide nocase
    condition:
        2 of them
}
```

### 15.5 .NET packers

```yra
rule dotnet_packer_indicators
{
    meta:
        description = ".NET packer/protector indicators"
    strings:
        $reactor = ".NET Reactor" ascii wide nocase
        $bamboo = "Bamboo" ascii nocase
        $boxedapp = "BoxedApp" ascii nocase
        $themida = "Themida" ascii wide nocase
        $vmprotect = "VMProtect" ascii wide nocase
        $confuser = "ConfuserEx" ascii nocase
        $agile = "Agile.NET" ascii nocase
        $babel = "Babel" ascii nocase
    condition:
        any of them
}
```

---

## 16. Rules: Go & Rust Implants

Modern stealers/RATs are increasingly Go or Rust — distinctive build artifacts.

### 16.1 Go binary indicators

```yra
rule go_binary_indicators
{
    meta:
        description = "Go build artifacts: build ID, runtime symbols, pclntab"
    strings:
        $go_build = "Go build ID:" ascii
        $go_ver   = /go1\.\d+/ ascii
        $runtime  = "runtime.main" ascii
        $gopcln   = "go:buildid" ascii
        $gopkg    = /github\.com\/[a-z0-9_-]+\/[a-z0-9_-]+/ ascii
        $goroot   = "/usr/local/go/" ascii
        $gomod    = "go.mod" ascii
        $nethttp  = "net/http" ascii
        $crypto   = "crypto/tls" ascii
        $mainpkg  = "main.main" ascii
        $syscall  = "syscall\." ascii
    condition:
        any of ($go_build,$go_ver,$goroot) and any of ($runtime,$mainpkg,$nethttp,$crypto,$syscall)
}
```

**Go-specific notes:** Go binaries embed full type info and module paths —
strings like `github.com/sirupsen/logrus` or `golang.org/x/crypto` reveal
dependencies. `GoReSym`/`gore` recover function names from stripped Go
binaries for analysis.

### 16.2 Rust binary indicators

```yra
rule rust_binary_indicators
{
    meta:
        description = "Rust build artifacts: rustc version, panic paths, cargo deps"
    strings:
        $rustc   = "rustc/" ascii nocase
        $rustver = /rustc [0-9a-f]{40}/ ascii
        $panic   = "panicked at" ascii
        $srcpath = /src\\[a-zA-Z0-9_\\\\]+\.rs/ ascii
        $srcpath2= /src\/[a-zA-Z0-9_\/]+\.rs/ ascii
        $cargo   = /\.cargo\\registry\\src/ ascii nocase
        $cargo2  = /\.cargo\/registry\/src/ ascii nocase
        $ring    = "ring-" ascii
        $aws-lc  = "aws-lc" ascii
        $tokio   = "tokio" ascii
        $serde   = "serde" ascii
        $reqwest = "reqwest" ascii
        $rustls  = "rustls" ascii
    condition:
        any of ($rustc,$rustver,$panic) and any of ($srcpath,$srcpath2,$cargo,$cargo2,$ring,$aws-lc,$tokio,$serde,$reqwest,$rustls)
}
```

**Rust notes:** panic messages embed absolute source paths like
`C:\Users\builder\.cargo\registry\src\...\ring-0.17.0\src\ec\...` — great for
attribution. Stripped Rust still has panic strings unless `panic=abort` +
`strip=symbols`.

### 16.3 Go/Rust direct syscalls

Go's `syscall` package and Rust's `syscalls` crate still end in ntdll `Nt*`
stubs — same §6 rules apply. Rust `syscalls` crate uses indirect syscalls
(jumps to gadgets) — §6.2 patterns catch it.

---

## 17. Memory-Scanning YARA

Static YARA scans files on disk. **Fileless/in-memory malware needs memory
scanning** — this is where most advanced stealth lives.

### 17.1 Tools that integrate YARA memory scanning

| Tool | What it scans |
|---|---|
| **yarascan** (VirusTotal) | memory dumps, live processes |
| **pe-sieve** | injected/hollowed code in running processes |
| **hollows_hunter** | same, batch mode |
| **Moneta** | in-memory PE detection |
| **Malcat / memprocfs** | full memory forensics |
| **Volatility yarascan** | memory images offline |

### 17.2 Memory-scanning rule adjustments

In memory you scan **regions**, not files — `pe.is_pe` works on dumped PE
images but shellcode regions have no PE header. Adjust rules:

```yra
rule mem_direct_syscall_anywhere
{
    meta:
        description = "direct syscall stub in ANY memory region (not ntdll)"
    strings:
        $stub = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3 }
    condition:
        $stub
    // NOTE: when scanning per-module, exclude ntdll.dll path;
    // in raw memory scan, this also hits legit ntdll stubs —
    // require the module path check or additional context.
}
```

### 17.3 Detecting injected code (no PE header)

```yra
rule mem_injected_shellcode
{
    meta:
        description = "shellcode patterns in non-image memory"
    strings:
        $syscall = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
        $peb     = { 65 48 8B ?? 60 00 00 00 }
        $hook    = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
        $api_hash= { C1 C? 0D }                  // ror r?,13
        $sleep_obf = { 66 0F 38 DC }              // AES-NI
    condition:
        2 of them
}
```

### 17.4 Precise patch detection in memory

When scanning a *specific module's* memory (e.g., amsi.dll, ntdll.dll), check
if the function's first byte is a patch:

```yra
rule mem_amsi_patched
{
    meta:
        description = "AmsiScanBuffer first byte = ret/patch stub"
    strings:
        // these are checked AT the function offset, not anywhere:
        $ret     = { C3 }
        $xor_ret = { 31 C0 C3 }
        $mov_ret = { B8 00 00 00 00 C3 }
    condition:
        // in practice: scan amsi.dll .text at AmsiScanBuffer RVA
        // for these byte sequences — implement in your scanner script
        any of them
}
```

*(Pure YARA can't express "at function X offset" for arbitrary modules —
you typically scan the whole module and check if patch bytes appear at
function-start offsets, or use a script that resolves exports first.)*

### 17.5 Sleep-obfuscated memory — the hard case

When `.text` is encrypted during sleep, memory scanners see high-entropy
code pages. Detect via:

- `.text` section entropy > 7.0 while process is sleeping (normal .text is
  ~5.5-6.5)
- RWX or RW private memory regions (not image-backed)
- The timer objects / wait chains pointing to obfuscated regions

```yra
rule mem_high_entropy_text_section
{
    meta:
        description = ".text section with entropy >7 = possibly sleep-obfuscated"
    import "pe" import "math"
    condition:
        pe.is_pe and
        for any i in (1..pe.number_of_sections) : (
            pe.sections[i].name == ".text" and
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) > 7.0
        )
}
```

### 17.6 YARA-Sandbox / any.run integration

- **ANY.RUN / Triage**: submit sample → they run YARA rules on memory dumps
- **CAPE Sandbox**: has YARA module for memory scanning
- **Vince's / Neo23x0 sigs**: community YARA rulesets for malware families

---

## 18. Methodology

### 18.1 The detection engineering loop

```
1. Get sample (MalwareBazaar, Triage, YOUR corpus)
2. Run capa → know the capability set → know which rules apply
3. FLOSS → strings (even if encrypted, decrypted-at-runtime ones appear)
4. Write rule targeting the MOST STABLE indicator (code pattern > constant > string)
5. Test:  yara -s rule.yar sample.exe   (see which strings matched)
6. FP test: run against benign corpus (Windows system32, common apps)
7. Iterate: tighten with pe module conditions, add second string, narrow wildcards
8. Version the rule, document what it catches and known bypasses
```

### 18.2 Testing against benign corpus

**Critical:** a rule that fires on `kernel32.dll` or `notepad.exe` is useless.
Build a benign corpus:

- `C:\Windows\System32\*.dll` and `*.exe` (thousands of samples)
- Common legit software (browsers, Office, dev tools)
- Your own compiled PoCs in `malware_pocs/` (they SHOULD fire — they're malware-like)

```bash
# quick FP test
yara -r rules/ C:/Windows/System32/ 2>/dev/null | head -50
```

### 18.3 yarGen — automated rule generation

`yarGen` (Neo23x0) generates YARA rules from samples by extracting strings
and opcode patterns:

```bash
python yarGen.py -m exefile -o rules/ --opcodes --exectuables malware_samples/
```

- `--opcodes` extracts instruction-level patterns (what you want for stealth)
- `--exectuables` limits to PE files
- Review generated rules manually — yarGen produces FP-heavy rules

### 18.4 Chaining weak signals

Single indicators FP constantly. The power is in ANDing:

```yara
// Weak alone, deadly together:
$peb_walk AND $hash_loop AND minimal_imports AND high_entropy_section
= dynamic resolver + encrypted payload = almost certainly malicious
```

Think in **TTP combinations**, not single artifacts.

### 18.5 Rule versioning & documentation

```yara
rule win_Ekko_SleepObfuscation
{
    meta:
        description = "Ekko timer-sleep obfuscation"
        author = "you"
        date = "2026-11-14"
        reference = "https://github.com/Cracked5pider/Ekko"
        version = "1.2"
        family = "sleep-obfuscation"
        falsepositives = "legit software using RC4+alertable waits (rare)"
        confidence = "high"
    strings: ...
    condition: ...
}
```

### 18.6 When YARA isn't enough

| Situation | Better tool |
|---|---|
| Process cmdline / parent-child | **Sigma** (log-source based) |
| Network traffic / JA3 | **Suricata / Zeek** |
| Behavioral sequence (inject→sleep→exfil) | **EDR telemetry / Sysmon** |
| Encrypted config extraction | **Dynamic analysis + IDA scripting** |
| .NET deobfuscation | **de4dot / dnSpy** |
| Go/Rust symbol recovery | **GoReSym / gore / rustfilt** |

YARA = static pattern matching on file/memory content. It's one layer.

---

## 19. Complete Example: Stealth Loader Ruleset

A realistic ruleset for a hypothetical "advanced stealer loader" combining:
PEB-walk API resolution + XOR-encrypted config + direct syscalls +
sleep obfuscation + Telegram exfil:

```yara
import "pe"
import "math"

rule StealthLoader_Combo_High_Confidence
{
    meta:
        description = "PEB-walk resolver + direct syscalls + Telegram C2 + sleep obf"
        confidence = "high"
        family = "stealer-loader"
    strings:
        // PEB walk (x64)
        $peb = { 65 48 8B ?? 60 00 00 00 }
        // API hashing
        $hash = { C1 C? 0D }
        // direct syscall stub
        $syscall = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
        // Telegram C2
        $tg = "api.telegram.org" ascii wide nocase
        // sleep obfuscation: RC4 + alertable wait
        $rc4 = "SystemFunction032" ascii wide
        $waitex = "WaitForSingleObjectEx" ascii wide
        // injection APIs
        $wpm = "WriteProcessMemory" ascii wide
        $cma = "CreateRemoteThread" ascii wide
    condition:
        pe.is_pe and
        $peb and $hash and $syscall and
        $tg and
        ($rc4 or $waitex) and
        any of ($wpm,$cma)
}

rule StealthLoader_Combo_Medium_Confidence
{
    meta:
        description = "subset of stealth loader indicators"
        confidence = "medium"
    strings:
        $peb = { 65 48 8B ?? 60 00 00 00 }
        $syscall = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
        $tg = "api.telegram.org" ascii wide nocase
        $aes = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        pe.is_pe and $peb and $syscall and $tg
}

rule EncryptedConfig_HighEntropy_Section
{
    meta:
        description = "high-entropy .data/.rsrc = encrypted config/payload"
        confidence = "low"   // needs combination
    import "pe" import "math"
    condition:
        pe.is_pe and
        for any i in (1..pe.number_of_sections) : (
            (pe.sections[i].name == ".data" or pe.sections[i].name == ".rsrc") and
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) > 7.2
        )
}
```

**Usage:** the high-confidence rule catches known-bad combos; medium catches
variants; low-confidence entropy rule is a *pivot* — when it fires alongside
ANY other signal, escalate.

---

## 20. Appendix: Opcode Reference Card

Quick lookup for the byte patterns used above:

| Instruction | Encoding | Notes |
|---|---|---|
| `mov rax, gs:[60h]` | `65 48 8B 04 25 60 00 00 00` | PEB x64 |
| `mov eax, fs:[30h]` | `64 A1 30 00 00 00` | PEB x86 |
| `mov r10, rcx` | `4C 8B D1` | syscall arg setup |
| `mov eax, imm32` | `B8 xx xx xx xx` | SSN / constant load |
| `syscall` | `0F 05` | the syscall instruction |
| `ret` | `C3` | patch stub / function end |
| `xor eax,eax; ret` | `31 C0 C3` | AMSI/ETW patch |
| `mov eax,0; ret` | `B8 00 00 00 00 C3` | alt patch |
| `mov rax, imm64` | `48 B8 <8 bytes>` | hook stub / address load |
| `jmp rax` | `FF E0` | hook stub jump |
| `jmp [rip+0]` | `FF 25 00 00 00 00` | indirect jmp (addr follows) |
| `call rel32` | `E8 <4 bytes>` | `{ E8 [4] }` in YARA |
| `jmp rel32` | `E9 <4 bytes>` | `{ E9 [4] }` |
| `ror r?, 13` | `C1 C? 0D` | ROR13 hash (ModRM varies) |
| `rol r?, 5` | `C1 C? 05` | DJB2-ish hash |
| `aesenc xmm,xmm` | `66 0F 38 DC` | AES-NI |
| `aesenclast` | `66 0F 38 DD` | AES-NI |
| `aeskeygenassist` | `66 0F 3A DF` | AES-NI key schedule |
| `rdtsc` | `0F 31` | timing check |
| `cpuid` | `0F A2` | anti-VM / fingerprinting |
| `int 2e` | `CD 2E` | legacy syscall (rare) |
| `sysenter` | `0F 34` | legacy syscall (rare) |

### ModRM wildcard guide

ModRM byte = `mod(2) reg(3) rm(3)`. The `reg` field selects the register —
that's what varies. Wildcard the WHOLE ModRM (`??`) when the register is
compiler-dependent; keep opcode + displacement exact.

```
48 8B 04 25 60 00 00 00   mov rax, gs:[60h]   (SIB form)
48 8B 0D 60 00 00 00      mov rcx, gs:[60h]   (mod=00, rm=101 = RIP-rel... no, gs: prefix)
4C 8B 0D 60 00 00 00      mov r9,  gs:[60h]
```

When you see `??` in a pattern, ask: "is this byte compiler-dependent
(ModRM/SIB) or semantically important (opcode/displacement)?" Wildcard the
former, keep the latter.

---

*Document generated for defensive detection engineering. All rules are
templates — test against your corpus, tune wildcards, and expect to iterate.
Real families rotate IOCs faster than code patterns, so weight your rules
toward instruction encodings and structural anomalies.*
