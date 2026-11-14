# Windows Driver Internals for Detection & Telemetry

A technical deep-dive into how kernel-mode drivers work on Windows, and how Endpoint Detection & Response (EDR) / anti-cheat / anti-tamper products use them to collect low-level telemetry.

---

## 1. The Big Picture: Why Kernel Drivers?

User-mode processes run in **Ring 3** with heavy isolation: virtual memory separation, no direct hardware access, all privileged operations mediated by the OS. Kernel-mode drivers run in **Ring 0**, sharing one flat address space with the OS itself, with direct access to:

- Every process's memory (via the kernel address space / section objects)
- The object manager (all handles, all processes, all threads)
- The file system and registry stacks
- The network stack
- Hardware (via HAL, NDIS, storport)

This is why EDRs live in kernel mode: anything a user-mode process does **must** eventually cross into the kernel (file reads, registry writes, process creation, network sends, thread injection). A kernel driver can observe these transitions at the source, before user-mode hooks can be bypassed.

### Privilege rings

```
Ring 3  ── user-mode apps, services, EDR user-mode service (limited)
Ring 0  ── kernel: ntoskrnl.exe, hal.dll, drivers (.sys files), EDR kernel driver
Ring -1 ── hypervisor (VBS/HVCI, Hyper-V based security)
```

---

## 2. User → Kernel Transition (the full path)

Everything interesting starts when a user-mode program calls an OS API.

### 2.1 Example: `CreateFileW()` → kernel

```
User app calls CreateFileW("C:\\temp\\x.bin")
        │
        ▼  (ntdll.dll — the "gateway" DLL, NOT kernel32/kernelbase)
ntdll!NtCreateFile — a tiny stub that:
        │
        ├─ loads syscall number into EAX (or moves SSN)
        ├─ loads first 4 args into RCX, RDX, R8, R9 (MS x64 ABI)
        └─ executes  SYSCALL  instruction  ──────────────► CPU switches to Ring 0,
                                                            RIP = IA32_LSTAR (KiSystemCall64)
        │
        ▼  Kernel side (ntoskrnl.exe)
KiSystemCall64:
        ├─ swaps GS (per-CPU kernel data: KPCR)
        ├─ copies user args / probes pointers
        ├─ indexes the SSDT  (System Service Descriptor Table)
        │      SSDT[SSN] → nt!NtCreateFile  (or a hooked version — see §9)
        ▼
NtCreateFile (kernel implementation):
        ├─ ObOpenObjectByName on \Device\HarddiskVolumeX → FILE_OBJECT
        ├─ IoCreateFile / IoGetRelatedDeviceObject → builds an IRP (IRP_MJ_CREATE)
        └─ IoCallDriver → enters the device stack
```

**Key insight for detection:** the SSDT and `ntdll` stubs are the oldest hook points. Modern malware avoids `syscall` directly ("direct syscalls") precisely to skip user-mode hooks — which is exactly why EDRs moved into kernel mode.

### 2.2 IRP — the currency of kernel I/O

Almost all kernel I/O is expressed as **IRPs (I/O Request Packets)**. An IRP is a struct describing:

- `MajorFunction` — what operation (IRP_MJ_CREATE, READ, WRITE, DEVICE_CONTROL, ...)
- Associated `FILE_OBJECT`, target device/driver
- Buffers, parameters, a `Tail.Overlay.Thread` (issuing thread → used for impersonation & attribution)

Flow: `IoBuildDeviceIoControlRequest` / `IoAllocateIrp` → `IoCallDriver` walks the **device stack**, each driver either completes the IRP or passes it down. Filters attach above/below and observe every IRP.

### 2.3 Return path

Kernel fills output buffer / status → `IofCompleteRequest` → completion routines run **bottom-up** through the stack → `Nt*` syscall returns to `ntdll` stub → back to user code.

---

## 3. IRQL — the scheduler's permission level

Drivers execute at various **Interrupt Request Levels**. Higher IRQL = more privileged, fewer things allowed.

| IRQL | Name | What runs |
|---|---|---|
| 0 | PASSIVE_LEVEL | Normal thread context. Can touch paged memory, wait, do most everything. |
| 1 | APC_LEVEL | Kernel APCs |
| 2 | DISPATCH_LEVEL | DPCs, deferred work. **No paged memory, no waits.** |
| DIRQL | Device IRQ | Hardware interrupt handlers |

**Why it matters:**

- Callbacks (process notify, object callbacks, registry callbacks) arrive at **PASSIVE_LEVEL** — safe to allocate, log, queue work.
- File-system minifilter pre/post ops can arrive at **<= APC_LEVEL**; some post-ops at DISPATCH for fast I/O.
- You **cannot** wait at raised IRQL — classic BSOD cause (`IRQL_NOT_LESS_OR_EQUAL`).
- Detection drivers must **defer** heavy work: capture data in the callback, queue a work item (`IoQueueWorkItem`) or DPC (§7) to process at PASSIVE_LEVEL.

---

## 4. Driver models

| Model | Ring | Use case |
|---|---|---|
| **WDM** (Windows Driver Model) | Kernel (Ring 0) | Raw drivers, filters, anything needing full control |
| **KMDF** (Kernel-Mode Driver Framework) | Kernel | Most modern drivers — Microsoft wraps IRP handling, you write event callbacks (`EvtDeviceAdd`, `EvtIoDeviceControl`...) |
| **UMDF** (User-Mode Driver Framework) | **User mode** | USB/audio/etc. drivers that don't need kernel power. *Cannot* be used for EDR-style telemetry since it can't see kernel objects |

Detection products are essentially always **WDM or KMDF kernel drivers**.

Driver entry: `DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)` — registers dispatch routines (`MajorFunction[IRP_MJ_*]`), unload routine, and optional `DriverUnload`. KMDF uses `DriverEntry` → `WdfDriverCreate` → `EvtDriverDeviceAdd`.

---

## 5. The Callback Arsenal (EDR's bread & butter)

Callbacks are how a driver **registers interest** in OS events. The kernel then invokes the driver's function when the event happens.

### 5.1 Process creation — `PsSetCreateProcessNotifyRoutineEx`

```c
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove);
```

Callback signature:

```c
VOID ProcessNotify(
    PEPROCESS Process,          // EPROCESS of new process
    HANDLE ProcessId,           // PID
    PPS_CREATE_NOTIFY_INFO Info // ← NULL on process exit, non-NULL on create
);
```

`Info` contains: `CreatingThreadId`, `FileOpenNameAvailable`/`ImageFileName` (path to the EXE), `CommandLine`, `ParentProcessId`, `CreatingProcessId`, environment, **mitigation flags** (e.g., `ProhibitDynamicCode`, `ExtensionPointDisable`), token info.

**EDR use:** every `CreateProcess`/`exec` is observed with parent-child lineage, image path, and command line — the backbone of process-creation telemetry.

`PsSetCreateProcessNotifyRoutine` (non-Ex) is the older variant, doesn't expose all fields.

### 5.2 Thread creation — `PsSetCreateThreadNotifyRoutineEx`

```c
VOID ThreadNotify(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create,
    PPS_CREATE_THREAD_NOTIFY_INFO Info // NULL on exit; has StartAddress, Win32StartAddress on create
);
```

**EDR use:** sees every thread ever created — including threads started via `CreateRemoteThread` / injection (`StartAddress` pointing into foreign/unbacked memory is a red flag).

### 5.3 Image load — `PsSetLoadImageNotifyRoutine`

```c
VOID ImageNotify(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,        // PID, or NULL for kernel-mode images
    PIMAGE_INFO ImageInfo    // {ImageBase, ImageSize, ImageSectionObject, Process}
);
```

Fires when a DLL/EXX/driver image is mapped — covers `LoadLibrary`, manual-map detection partial, and **every driver load** (`System` process loads `.sys` files).

**EDR use:** DLL injection detection (module loaded from suspicious path), tracking of known-bad modules, kernel driver load monitoring.

### 5.4 Handle operations — `ObRegisterCallbacks` (the "handle stripping" callback)

```c
OB_OPERATION_REGISTRATION Ops[1] = {{
    OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
    PreCallback, PostCallback
}};
ObRegisterCallbacks(&Alt, Ops, &RegHandle);
```

Called when a handle to a protected object type (typically `PsProcessType`, `PsThreadType`, `MmSectionObjectType`, `IoFileObjectType`, `TmTransactionManagerObjectType`...) is **created or duplicated**.

```c
OB_PREOP_CALLBACK_STATUS PreOp(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION Info
    // Info->ObjectType, Info->Object (EPROCESS/ETHREAD...), Info->DesiredAccess
);
```

Pre-op can **strip access rights**: `Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;` — this is how EDRs *block* `OpenProcess(PROCESS_VM_WRITE)` on protected processes instead of just logging it.

**EDR use:** detects and optionally denies `OpenProcess`/`DuplicateHandle` targeting sensitive processes — the #1 injection primitive (process hollowing, reflective DLL injection all need a handle).

### 5.5 Registry — `CmRegisterCallbackEx`

```c
NTSTATUS CmRegisterCallbackEx(
    PEX_CALLBACK_FUNCTION Function,  // RegistryCallback
    PLARGE_INTEGER Altitude,          // e.g. 1000
    PVOID Driver, PVOID Context, PCUNICODE_STRING AltName, PEX_CALLBACK_REGISTRATION* Cookie);
```

Callback receives `REG_NOTIFY_CLASS`:

- `RegNtPreCreateKeyEx` / `RegNtPostCreateKeyEx`
- `RegNtPreSetValueKey` / `RegNtPostSetValueKey`
- `RegNtPreDeleteKey` / `RegNtPostDeleteKey`
- `RegNtPreRenameKey`, `RegNtPreEnumerateKey`, `RegNtPreQueryKey`...

Each has `REG_QUERY_VALUE_KEY_INFORMATION`/`SetValueKeyInformation` etc. with the key path, value name, and **data** — plus `Object` (the CM key object) and `UserBuffer`.

**EDR use:** monitors `HKLM\...\Run` keys, service creation (`HKLM\SYSTEM\...\Services`), `Image File Execution Options` debuggers, COM hijacks — plus LSASS access attempts (credential dumping via registry).

### 5.6 Others worth knowing

| API | Watches |
|---|---|
| `CmRegisterCallback` (legacy) | Older registry callback, less info |
| `KeRegisterBugCheckCallback` | Bugcheck data — for crash dumps/telemetry |
| `IoRegisterBootDriverCallback` | Early-boot driver activity |
| `NMR` (`NmrRegisterProvider`) | Network module registration — modern replacement for some NDIS hooks |
| `FltRegisterFilter` | File system minifilter (§6) |
| `FwpsCalloutRegister` | WFP network callouts (§8) |
| `PoRegisterPowerSettingCallback` | Power events |
| `ExCreateCallback`/`ExRegisterCallback` | Kernel-internal named callbacks (mostly used by AV/EDR to coordinate, e.g. `\Callback\PowerState`) |

---

## 6. Minifilter Drivers (file system telemetry)

Minifilters are **file system filter drivers** that attach to the NTFS/FAT/ReFS stacks at an **altitude** (a signed 32-bit value defining order — e.g., 360000 for antivirus, 140000 for backup).

### Registration & lifecycle

```c
NTSTATUS FltRegisterFilter(PDRIVER_OBJECT, CONST FLT_REGISTRATION* FltReg, PFLT_FILTER*);
// in DriverEntry:
FltRegisterFilter(DriverObject, &gRegData, &gFilter);
FltStartFiltering(gFilter);   // activates — instances get created on volumes
```

### Callbacks (mini-IRPs)

Instead of raw IRPs, minifilters get structured callbacks:

| Callback | Fires on | Info available |
|---|---|---|
| `IRP_MJ_CREATE` pre/post | File/directory open | path, desired access, disposition |
| `IRP_MJ_READ`/`WRITE` pre/post | File data I/O | byte offset, length, MDL |
| `IRP_MJ_SET_INFORMATION` | Rename, delete, set disposition | **file rename/move/delete detection** |
| `IRP_MJ_QUERY_INFORMATION` | Metadata queries | size, times, attributes |
| `IRP_MJ_DIRECTORY_CONTROL` | Directory enumeration | listing contents |
| `IRP_MJ_ACQUIRE_FOR_SECTION` | Memory-mapping a file | which image/DLL is being mapped |
| `IRP_MJ_ACQUIRE_FOR_MODWRITE` | Opening a file for write+execute | suspicious write-to-executable |
| `IRP_MJ_FILE_SYSTEM_CONTROL` | FSCTLs | e.g. `FSCTL_SET_REPARSE_POINT`, `FSCTL_SPARSE_OVERHEAD` |
| `IRP_MJ_DEVICE_CONTROL` | IOCTLs to the FS | volume-level control |

Each callback gets `PFLT_CALLBACK_DATA` — contains the target file name (`FltGetFileNameInformation`), process/thread IDs (`Data->Thread` → ETHREAD → CID), desired access, and IO status. **Pre-op** runs before the I/O hits disk/lower FS; **post-op** gets the result.

### Communication port — talking to user mode

Minifilters can't easily talk to their user-mode service directly. Solution: **filter communication port**.

```c
FltCreateCommunicationPort( Filter, &ServerPort, &ConnectNotify, &DisconnectNotify, &MessageNotify, ... );
// kernel → user:  FilterSendMessage(Filter, &ClientPort, &Input, ...)
// user → kernel:  FilterGetMessage / FilterReplyMessage via port handle
```

Flow: user-mode service calls `FilterConnectCommunicationPort("\MyFilterPort")` → gets a port handle → sends messages; kernel `MessageNotify` receives `FilterGetMessage`-formatted requests and replies via `FilterReplyMessage`.

**EDR use:** every file create/write/rename/delete with full path + process attribution — catches ransomware encryption patterns, detects writes to sensitive paths (`System32`, LSASS memory dumps, browser credential stores), watches `.exe` writes (dropper detection).

### Legacy note

Pre-Vista, filesystems were filtered by attaching device objects (`IoAttachDeviceToDeviceStack`). Minifilters replaced this — modern EDRs exclusively use `FltRegisterFilter`.

---

## 7. Deferred execution: DPCs, Work Items, APCs

Callbacks must be fast. Heavy telemetry processing happens later via:

### 7.1 DPC — Deferred Procedure Call

```c
KeInitializeDpc(&Dpc, MyDpcRoutine, Context);
KeInsertQueueDpc(&Dpc, Arg1, Arg2);  // or KeSetTimer + DPC for periodic
```

DPC runs at **DISPATCH_LEVEL** on the target CPU — no paged memory, no blocking calls. Used for: completing hardware IRPs quickly, deferred processing after an ISR, high-frequency sampling (timers).

For detection: DPCs are used to *batch* telemetry, rate-limit, and perform periodic scans without stalling the callback path.

### 7.2 Work Items — `IoQueueWorkItem`

```c
IO_WORKITEM* Wi = IoAllocateWorkItem(DeviceObject);
IoQueueWorkItem(Wi, MyWorkRoutine, DelayedWorkQueue, Context);
```

Runs at **PASSIVE_LEVEL** in a system worker thread — can allocate memory, take locks, do logging, call user-mode via ALPC/APC. **This is where EDR drivers actually build telemetry events** after a callback fires.

### 7.3 APCs — Asynchronous Procedure Calls

```c
KeInitializeApc / KeInsertQueueApc  // kernel APC
KeStackAttachProcess + queue user APC
```

APCs run in the context of a specific thread at APC_LEVEL — used for: injecting code into user threads (`QueueUserAPC`-equivalent from kernel — also an attack technique), completing async I/O, forcing a thread to run a function. EDRs watch APC-based injection as a technique; drivers themselves use APCs for controlled callbacks into monitored processes (e.g., in-process scanning agents).

---

## 8. Network telemetry: WFP & NDIS

### 8.1 WFP — Windows Filtering Platform

`FwpsCalloutRegister` registers a **callout** at a layer (ALE_AUTH_CONNECT, OUTBOUND_TRANSPORT, INBOUND_TRANSPORT, ALE_FLOW_ESTABLISHED, DATAGRAM...). Each layer fires per-packet or per-flow.

```c
FWPS_CALLOUT0 Callout = { ..., ClassifyFn, NotifyFn, FlowDeleteFn };
FwpsCalloutRegister(device, &Callout, &id);
// also need: filter (FwpsFilterAdd) at a sublayer/weight, plus provider/sublayer GUIDs
```

`ClassifyFn` gets `FWPS_INCOMING_VALUES`/`FWPS_OUTGOING_VALUES` — **source/dest IP, ports, process ID (ALE layers)** — and returns `FWP_ACTION_PERMIT`/`BLOCK`/`CONTINUE`. This is how EDRs:

- Log every outbound connection with owning PID
- Block C2 domains/IPs (deny action)
- Detect DNS tunneling, scanning, exfil

### 8.2 NDIS Lightweight Filters (LWF)

`NdisFRegisterFilterDriver` attaches a lightweight filter to the NDIS miniport stack — sees every Ethernet frame pre/post. More raw (MAC-level) than WFP. Some EDRs use LWF for packet capture; most prefer WFP for flow attribution.

### 8.3 WSK — Winsock Kernel

`WskRegister`, `WskSocket` — lets a driver open TCP/UDP sockets in kernel mode. Used by EDRs for: sending telemetry directly to the cloud backend without user-mode proxying, and by malware too (fileless C2).

### 8.4 TDI — deprecated

`TdiRegisterDeviceObject` — the old transport driver interface. Mostly gone post-Vista; mention for completeness only.

---

## 9. Attacker vs. Defender: the hook landscape

Understanding detection means understanding what attackers tamper with — and what survives.

| Technique | What it does | Who still sees it |
|---|---|---|
| **User-mode API hooks** (IAT/EAT/inline) on `ntdll` | Hides activity from user-mode EDR sensors | Kernel callbacks still fire — kernel path is unhookable from user mode |
| **SSDT hooking** (patching `nt!Nt*`) | Intercepts syscalls in kernel | PatchGuard (Kernel Patch Protection) bugchecks on SSDT modification — rarely viable on x64 |
| **Inline hooks on `Nt*` exports** | Same, per-function | PatchGuard doesn't cover all functions; ETW-TI (Threat Intelligence) sees kernel-side anyway |
| **`ObRegisterCallbacks` removal** | Malware with admin tries to unregister EDR callbacks (needs to find the registration cookie — it's in `PsProcessType` callback list) | Multiple EDRs register redundantly; tampering itself is telemetry |
| **Minifilter altitude games / unload** | Unload or detach the filter | Filter unload requires admin + triggers ETW events; altitude conflicts block load |
| **Direct syscalls / Hell's Gate / Halo's Gate** | Skip `ntdll` stubs entirely | Kernel callbacks unaffected — this is *why* kernel telemetry exists |
| **BYOVD (Bring Your Own Vulnerable Driver)** | Load a signed-but-vulnerable driver to kill/disable EDR | The driver load itself is `PsSetLoadImageNotifyRoutine` telemetry + driver blocklist (Microsoft Vulnerable Driver Blocklist / HVCI) |
| **DKOM (Direct Kernel Object Manipulation)** | Unlink EPROCESS from `PsActiveProcessHead` | Object callbacks, ETW-TI, and memory scanning still see threads/handles; PatchGuard may catch some list corruption |
| **ETW patching** (`EtwEventWrite` hooks, `EtwThreatIntelligence` provider disable) | Blind user/kernel ETW consumers | EDRs treat ETW-TI as supplementary; kernel callbacks remain ground truth |

**Modern consensus architecture:** kernel callbacks + minifilter + WFP produce raw events → driver packages them → sends to user-mode service via filter port / ALPC / shared memory → user service does ML/rule detection → response actions loop back down (kill process via `ZwTerminateProcess`, block handle via pre-op strip, isolate host via WFP blocks).

---

## 10. I/O Manager deep dive: IRP_MJ table

`DRIVER_OBJECT->MajorFunction[]` is a 28-entry dispatch table. Key entries:

| IRP_MJ | Operation | Who sees it |
|---|---|---|
| `IRP_MJ_CREATE` | Open file/device | FS minifilters, disk class drivers |
| `IRP_MJ_CLOSE` | Close handle | same |
| `IRP_MJ_READ`/`WRITE` | Data transfer | FS filters, disk, net |
| `IRP_MJ_DEVICE_CONTROL` | **IOCTLs** — the generic "do something" | Every driver stack |
| `IRP_MJ_INTERNAL_DEVICE_CONTROL` | Private/driver-to-driver IOCTLs | stacked drivers |
| `IRP_MJ_PNP` | Plug and play | all device drivers |
| `IRP_MJ_POWER` | Sleep/resume | all device drivers |
| `IRP_MJ_SYSTEM_CONTROL` | ACPI/thermal | rare |
| `IRP_MJ_CLEANUP` | Last handle closing | FS filters |
| `IRP_MJ_DIRECTORY_CONTROL` | Dir enumeration | FS filters |
| `IRP_MJ_QUERY/SET_INFORMATION` | Metadata/rename/delete | FS filters |
| `IRP_MJ_SHUTDOWN` | OS shutdown | all drivers |
| `IRP_MJ_FILE_SYSTEM_CONTROL` | FSCTLs (defrag, compression, reparse) | FS filters |

Filters attach via `IoAttachDeviceToDeviceStack` (legacy) or altitude-based minifilter instances — the I/O manager walks the stack calling each driver's dispatch routine or minifilter pre/post op.

---

## 11. IOCTLs — user↔driver control channel

Custom drivers expose functionality to user mode via DeviceIoControl → IRP_MJ_DEVICE_CONTROL.

### Encoding

```c
#define CTL_CODE( DeviceType, Function, Method, Access ) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
```

Example:

```c
#define IOCTL_MYDRV_READ_MEM  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
// DeviceType: FILE_DEVICE_UNKNOWN(0x22) | Access: FILE_ANY_ACCESS(0) | Function: 0x800 | Method: METHOD_BUFFERED(0)
// = 0x00222000
```

| Method | Buffer handling |
|---|---|
| `METHOD_BUFFERED` (0) | I/O mgr allocates one kernel buffer; `Irp->AssociatedIrp.SystemBuffer` — input copied in, output copied back. **Safest — use this.** |
| `METHOD_IN_DIRECT` / `OUT_DIRECT` | User buffer locked via MDL; kernel writes directly to user pages |
| `METHOD_NEITHER` | **Raw user pointers passed through** — driver must `ProbeForRead/Write` + be in caller's context (attach to process or use `Irp->RequestorMode` checks). Dangerous — most bugs live here. |

### Handling in the driver

```c
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT Dev, PIRP Irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (code) {
    case IOCTL_MYDRV_READ_MEM: /* validate inLen, copy out */ break;
    default: status = STATUS_INVALID_DEVICE_REQUEST;
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
```

User side: `CreateFile("\\\\.\\MyDriver")` → `DeviceIoControl(h, IOCTL_..., inBuf, inLen, outBuf, outLen, &ret, NULL)`.

### Why IOCTLs matter for detection

- **EDR telemetry products themselves** expose IOCTLs so their user-mode service can ask the kernel driver to do things (get process list, scan memory, respond to alerts).
- Malware abuses **vulnerable signed drivers'** IOCTLs (BYOVD): e.g., `RTCore64.sys` exposes arbitrary physical memory read/write via IOCTL — attackers don't write a driver, they *borrow* one.
- Monitoring unusual IOCTL patterns to known-vulnerable drivers is a detection signal.

---

## 12. Process/Thread/Object internals (what callbacks hand you)

### EPROCESS / ETHREAD

- `EPROCESS` — kernel object for a process: PID, token, image file name, `ActiveProcessLinks` (the linked list DKOM attacks), VAD tree, handle table pointer, mitigation flags, `SectionBaseAddress` (image base).
- `ETHREAD` — per-thread: `Cid` (PID+TID), `StartAddress`/`Win32StartAddress` (thread entry point — injection detection), `ApcState`, kernel stack.
- From `PETHREAD` → `PsGetThreadProcess` → EPROCESS. From EPROCESS → `PsGetProcessId`, `PsGetProcessImageFileName`, `PsGetProcessSectionBaseAddress`.

### Handles & the object manager

- Every open resource = a **handle** (index into per-process `HANDLE_TABLE`).
- `ObOpenObjectByPointer`/`ObOpenObjectByName` resolve names→objects.
- `ObRegisterCallbacks` intercepts handle creation — you can inspect `DesiredAccess` and strip rights.
- `ObGetObjectType`/`ObGetObjectSecurity` for auditing; `SeAccessCheck` for manual access validation.

### Reading another process's memory

```c
KeStackAttachProcess(TargetEprocess, &ApcState);  // switch address space context
// or MmCopyVirtualMemory(SourceProcess, SourceAddr, TargetProcess, TargetAddr, Size, KernelMode, &Copied)
ZwReadVirtualMemory / ZwWriteVirtualMemory  // respects access checks
```

EDRs use `MmCopyVirtualMemory` for memory scanning of suspicious processes (payload detection) — works at PASSIVE_LEVEL, cross-process, no handle needed.

---

## 13. End-to-end example: EDR sees an attack

Scenario: malware does `OpenProcess(PROCESS_VM_WRITE|VM_OPERATION)` on notepad, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.

```
1. OpenProcess
   └─► ObRegisterCallbacks pre-op fires (kernel)
       EDR strips PROCESS_VM_WRITE → returns ACCESS_DENIED to user mode
       Event logged: "handle strip attempt on notepad.exe by evil.exe"

2. VirtualAllocEx/WriteProcessMemory (if handle obtained)
   └─► Requires section object / memory ops — visible via:
       - PsSetCreateThreadNotifyRoutineEx (remote thread start addr in unbacked mem)
       - Minifilter sees nothing (no file I/O) but WFP/ETW may correlate

3. CreateRemoteThread
   └─► PsSetCreateThreadNotifyRoutineEx fires: new thread, StartAddress =
       address NOT backed by any image section → injected code heuristic

4. Payload executes
   └─► PsSetLoadImageNotifyRoutine on any DLL it loads
       Minifilter on file writes (ransomware stage)
       WFP callouts on C2 connections (ALE_AUTH_CONNECT: PID + dest IP)

5. EDR user service
   └─► Receives batched telemetry via filter port
       Correlates: child-of-notepad + unbacked thread + outbound conn
       → alert; optionally responds: ZwTerminateProcess, WFP block
```

---

## 14. Key structures cheat-sheet

| Struct | Represents | Get it via |
|---|---|---|
| `EPROCESS` | Process | `PsGetCurrentProcess`, callback arg, `PsLookupProcessByProcessId` |
| `ETHREAD`/`KTHREAD` | Thread | `PsGetCurrentThread`, `PsLookupThreadByThreadId` |
| `PFLT_CALLBACK_DATA` | File I/O event | minifilter callback arg |
| `PUNICODE_STRING` | Path/name | callback args, `RtlInitUnicodeString` |
| `PIO_STACK_LOCATION` | Current IRP params | `IoGetCurrentIrpStackLocation(Irp)` |
| `CLIENT_ID` | {PID, TID} | `PsGetThreadId`, thread notify |
| `PEPROCESS` SectionBase | Image base | `PsGetProcessSectionBaseAddress` |
| `HANDLE_TABLE` | Per-process handles | `ExMapHandleToPointer` (undocumented) |

---

## 15. Practical notes for building your own detection driver

1. **DriverEntry**: call `IoCreateDevice`/`IoCreateSymbolicLink` (for IOCTL channel), `FltRegisterFilter`+`FltStartFiltering` (minifilter), register all `Ps*`/`Ob*`/`Cm*` callbacks, then complete init.
2. **Altitude**: pick a unique signed altitude for your minifilter (query `fltmc instances` to see existing ones — avoid collisions).
3. **Signing**: test cert via `bcdedit /set testsigning on` in VM; production needs EV cert + WHQL attestation.
4. **Callback teardown**: store registration cookies; unregister in `DriverUnload` **in reverse order**; always check for the "unload while callback in flight" race — use a refcount or `FltUnregisterFilter` waits for callbacks.
5. **IRQL discipline**: assume callbacks can arrive at APC_LEVEL; do minimal work, queue work items for anything heavy.
6. **Buffer safety**: in IOCTL handlers always validate lengths; for METHOD_NEITHER use `ProbeForRead/Write` and `MmIsAddressValid`.
7. **Telemetry transport**: filter port (`FltSendMessage`) or ALPC port or shared memory section — pick one; keep payloads small.
8. **Test**: load in a VM with `sc create`/`sc start`, watch `DbgPrintEx` output in WinDbg/DebugView, then trigger events (create a process, write a file, open a connection) and verify callbacks fire.

---

## References

- Microsoft Learn — Windows driver docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/
- `Windows-driver-samples` repo (Kernel-Mode Driver, Minifilter samples): https://github.com/microsoft/Windows-driver-samples
- Alex Ionescu's `ntoskrnl`/`wdk` research; `VergiliusProject` struct layouts: https://www.vergiliusproject.com
- Matt Miller / Connor McGarr writeups on EDR telemetry & callbacks (SpecterOps/MalwareTech)
- `fltmc`, `sc query`, WinDbg `!process`, `!thread`, `!handle` for live inspection
