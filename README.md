# workspace

A Windows x64 kernel **manual mapper** built as two Visual Studio projects: a user-mode **loader** that drives the mapping pipeline, and a minimal **KMDF driver** that acts as the kernel-side payload template.

The loader resolves kernel symbols from Microsoft's public PDB servers, loads a signed helper driver via the Service Control Manager, discovers the system Directory Table Base (CR3) by walking physical memory, hijacks an SSDT entry to build a syscall bridge, resolves the kernel routines it needs, and finally manually maps a target `.sys` image into kernel space before transferring control to its entry point.

> ⚠️ **For educational and research purposes only.** This project exists to document and study Windows internals (paging, SSDT, PE loading, kernel symbol resolution). Running it requires kernel debugging and/or test-signing mode on Windows 10/11 x64.

---

## Repository layout

```
workspace/
├── workspace.sln             ← Visual Studio 2022 solution (x64 + ARM64 configs)
│
├── loader/                   ← user-mode orchestrator (.exe)
│   ├── loader.vcxproj
│   ├── src/
│   │   ├── main.cpp              pipeline entry point
│   │   ├── common/
│   │   │   ├── includes.hpp      shared includes / prelude
│   │   │   ├── log.hpp           klog:: colored logger (VT, Raster Fonts, resize)
│   │   │   └── types.hpp         shared type aliases
│   │   ├── symbols/
│   │   │   ├── pdb.hpp           ntoskrnl.exe PDB download + symbol parse
│   │   │   └── exports.hpp       kernel export resolver
│   │   ├── driver/
│   │   │   ├── service.hpp       SCM service: create / start / stop / delete
│   │   │   ├── driver.hpp        device handle + IOCTL channel
│   │   │   └── bytes.hpp         request payload helpers
│   │   └── memory/
│   │       ├── paging.hpp        physical-memory walker, system CR3 discovery
│   │       ├── paging_split.hpp  internal split-page helpers
│   │       ├── syscall.hpp       SSDT hijack / syscall bridge
│   │       └── map/
│   │           ├── map.hpp           manual map orchestrator
│   │           ├── entry.hpp         kernel-side entry contract (map_entry_t)
│   │           ├── allocator.hpp     kernel allocator (via driver primitives)
│   │           └── dependency.hpp    PE image loader / section parser
│   └── third_party/
│       └── oxorany/              compile-time string / integer obfuscation
│
└── driver/                   ← kernel-mode payload (.sys, KMDF, Universal)
    ├── driver.vcxproj
    ├── driver.inf                KMDF install metadata
    └── main.cpp                  `entry( map_entry_t* )` reference payload
```

---

## How it works

The loader's `main.cpp` executes the following pipeline, with every stage logged by the `klog` subsystem:

| # | Stage        | What happens                                                                                           |
|---|--------------|--------------------------------------------------------------------------------------------------------|
| 1 | `pdb`        | Downloads `ntoskrnl.exe`'s PDB from Microsoft symbol servers and parses its symbol table.              |
| 2 | `service`    | Registers and starts a signed helper driver through the Service Control Manager.                       |
| 3 | `driver`     | Opens a `\\.\` device handle to the helper driver for IOCTL communication.                           |
| 4 | `paging`     | Walks physical memory via the helper driver to locate the **system Directory Table Base (CR3)**.       |
| 5 | `syscall`    | Prepares an **SSDT hijack bridge** so chosen syscalls route through the loader's kernel primitives.    |
| 6 | `exports`    | Resolves the kernel routines required by the mapper from the parsed PDB symbol set.                    |
| 7 | `dependency` | Loads the target `.sys` from disk and parses its PE sections.                                          |
| 8 | `map`        | Allocates kernel memory, copies sections, fixes relocations, resolves imports, then calls the payload. |
| 9 | `shutdown`   | Closes the device handle, stops the service, and unregisters it.                                       |

All literal strings are wrapped in `oxorany( ... )` so they never appear in the final binary as plain text.

### Driver ↔ loader contract

The loader hands the mapped payload a `map_entry_t` structure and jumps to its `entry` export. The current reference payload (`driver/main.cpp`) simply prints the fields back through `DbgPrintEx`:

```cpp
typedef struct _map_entry_t {
    entry_pdb_t      m_pdb;                   // kernel function pointers resolved by loader
    unsigned __int64 m_directory_table_base;  // system CR3
    unsigned __int64 m_ntoskrnl_base;         // ntoskrnl image base
    unsigned __int64 m_image_size;            // mapped image size
    unsigned __int64 m_image_base;            // mapped image base
} map_entry_t;

bool entry( map_entry_t* entry_data );        // returns true on success
```

Replace `driver/main.cpp`'s `entry( )` body with your own research payload while keeping the signature.

---

## Logger (`klog`)

The loader ships a header-only logger in `loader/src/common/log.hpp` with:

- Six levels: `trace`, `debug`, `info`, `warn`, `error`, `fatal` (+ `off`).
- `print_info / print_warn / print_error / print_fatal / print_stage` helpers.
- Timestamped output with a cool cyan → steel-blue gradient on the prefix and soft gray body text.
- Automatic console setup on first include:
  - Enables **VT escape sequence processing** (`ENABLE_VIRTUAL_TERMINAL_PROCESSING`).
  - Forces the classic **Raster Fonts** (`Terminal` 8×12) in `conhost.exe`.
  - Resizes the console window to **140 × 40** with a 9000-line scroll buffer.
- Thread-safe output guarded by an internal mutex.

> The font and resize calls only take effect in the classic Windows Console Host (`conhost.exe`). Modern terminals (Windows Terminal, VS Code integrated terminal, PowerShell 7) silently ignore them and use their own renderer.

---

## Build

### Requirements

- Windows 10 / 11 x64
- Visual Studio 2022 with:
  - **Desktop development with C++** workload
  - **Windows 10/11 SDK**
  - **Windows Driver Kit (WDK)** matching the SDK version
  - Spectre-mitigated libraries (installed via VS Installer → Individual components)

### Steps

1. Open `workspace.sln` in Visual Studio 2022.
2. Select the `Release | x64` configuration.
3. Build the solution (`Ctrl+Shift+B`).

Build artifacts land under `build/output/<config>/<project>/`:

```
build/output/release/loader/loader.exe
build/output/release/driver/driver.sys
```

The driver project targets `WindowsKernelModeDriver10.0` as a **Universal KMDF** driver and is configured for both x64 and ARM64 (the loader is x64 only).

---

## Usage

```
loader.exe <path-to-driver.sys>
```

Example:

```
loader.exe driver.sys
```

If no argument is passed, the loader prints a usage message and exits.

### Enabling test-signing (required for unsigned drivers)

As an administrator:

```
bcdedit /set testsigning on
```

Reboot afterwards. To disable it again:

```
bcdedit /set testsigning off
```

---

## Dependencies

- [`oxorany`](https://github.com/llxiaoyuan/oxorany) — compile-time literal obfuscation. Vendored under `loader/third_party/oxorany/`.

No other external libraries. Symbol information for `ntoskrnl.exe` is fetched at runtime from Microsoft's public symbol server (`msdl.microsoft.com/download/symbols`).

---

## Disclaimer

This repository is published for **educational and defensive security research** purposes: understanding Windows kernel internals, PE loading, symbol resolution, and the mechanics of manual mapping. The author is not responsible for any misuse. Do not use this software to tamper with systems you do not own or do not have explicit written authorization to test on.
