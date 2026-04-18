<div align="center">
  <h1>EDR Map</h1>
  <img src="https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/logo.png" width="256">
  
  <p><b>An educational Proof of Concept demonstrating how to dynamically detect EDR userland hooks and enumerate active ETW telemetry sessions.</b></p>
</div>

## Overview
**EDR Map** is a lightweight scanner that detects AV/EDR userland hooks and lists active ETW telemetry sessions.

<div align="center">
  <img src="https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/hooks.png" alt="EDR-Map Showcase">
</div>

## Features

* **Dynamic Hook Detection:** Maps the `ntdll.dll` loaded in the current process memory against a pristine, unhooked copy read directly from disk (`C:\Windows\System32\ntdll.dll`).
* **Targeted Scanning:** Specifically checks high-value APIs targeted by EDRs for evasion and injection detection, including:
  * `Nt*` / `Zw*` (Syscall stubs)
  * `Etw*` (Event Tracing)
  * `Ldr*` (Loader functions)
  * `Rtl*` (Runtime Library)
  * `Ki*` (Kernel Interface)
  * `RegNt*` (Registry APIs)
* **ETW Enumeration:** Queries the OS using `QueryAllTracesW` to list actively running ETW trace sessions.
* **Heuristic Alerts:** Automatically flags high-interest telemetry providers watching the system (Defender, Sysmon, CrowdStrike, SentinelOne, Cylance).
* **Modular Execution:** Use command-line flags to isolate scanning modules or run the tool silently.

## How It Works

### 1. Hook Scanning
EDR-Map bypasses standard opcode scanning (like looking for `E9` JMP instructions) which can easily be fooled by complex trampolines. Instead, it parses the PE headers of a raw disk copy of `ntdll.dll`, calculates the exact offsets of exported functions, and uses `memcmp` to compare the first 16 bytes of those functions against the live `ntdll.dll` loaded in memory. Any discrepancy flags a patch or inline hook.

### 2. ETW Telemetry 
The tool allocates the necessary memory structures for `EVENT_TRACE_PROPERTIES` and queries the kernel for active trace sessions. It then parses the wide strings returned by the OS and checks them against a hardcoded list to identify known security logging services.

## Examples
- Bitdefender ([bitdefender_hooks.md](https://github.com/N3agu/EDR-Map/Examples/bitdefender_hooks.md))

## Screenshots

<details open>
  <summary><strong>Screenshot of a Full Scan</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/full.png)
</details>

<details>
  <summary><strong>Screenshot of EDR-Map with --etwonly</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/etw.png)
</details>

<details>
  <summary><strong>Screenshot of EDR-Map with --hooksonly</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/hooks.png)
</details>

<details>
  <summary><strong>Screenshot of Bitdefender Hooks</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/bitdefender.png)
</details>

## Usage
EDR-Map can be run with full visual output or silently to only output critical alerts.
```
Usage: EDR_Map.exe [OPTIONS]

Options:
  -h, --help      Show this help message and exit.
  -s, --silent    Disable verbose output (shows debug info).
  --etwonly       Skip userland hook scanning; ONLY enumerate ETW trace sessions.
  --hooksonly     Skip ETW enumeration; ONLY scan for userland API hooks.

Examples:
  EDR_Map.exe                    # Run both modules with full debug output
  EDR_Map.exe -s                 # Run both modules silently (alerts only)
  EDR_Map.exe --etwonly          # Run only ETW
  EDR_Map.exe --hooksonly -s     # Run silently only Hooks
```
Examples:
```
# Run both modules with full debug output (Standard run)
EDR_Map.exe

# Run both modules silently (Only prints actual hooks and flagged ETW sessions)
EDR_Map.exe -s

# Skip ntdll disk reads and only check ETW telemetry
EDR_Map.exe --etwonly

# Check for API hooks silently, ignoring ETW entirely
EDR_Map.exe --hooksonly -s
```

## Disclaimer
***This tool is strictly for educational purposes, security research, and authorized red team engagements. The author is not responsible for any misuse or damage caused by this software. Never deploy this tool in environments where you do not have explicit permission.***
