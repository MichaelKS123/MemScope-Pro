# MemScope Pro v1.0
**Memory Forensics Toolkit**  
**Analyse System Memory for Hidden Processes & Malware**  
**by Michael Semera**

---

## 🔍 Overview

MemScope Pro is a comprehensive memory forensics toolkit written in C++ for analysing system memory dumps to detect hidden processes, injected code, rootkits, and other suspicious activity. It uses advanced pattern recognition and OS internals knowledge to identify anomalies in memory that could indicate system compromise.

## ⚠️ CRITICAL DISCLAIMER

**THIS IS AN EDUCATIONAL IMPLEMENTATION FOR LEARNING PURPOSES!**

- ✅ **DO** use it to learn about memory forensics
- ✅ **DO** use it for educational demonstrations
- ✅ **DO** study the implementation for forensics concepts
- ❌ **DO NOT** use it for production forensics investigations
- ❌ **DO NOT** use it as evidence in legal proceedings
- ❌ **DO NOT** rely on it for critical security decisions

**For production forensics, use:**
- **Volatility Framework** - Industry-standard memory forensics
- **Rekall** - Advanced memory forensics
- **Redline** - FireEye's memory analyser
- **FTK Imager** - Commercial forensics suite

---

## ✨ Features

### Core Analysis Capabilities

- **🕵️ Hidden Process Detection**
  - EPROCESS structure parsing
  - PsActiveProcessHead traversal
  - DKOM (Direct Kernel Object Manipulation) detection
  - Process tree reconstruction

- **💉 Code Injection Detection**
  - Shellcode pattern recognition
  - Suspicious memory allocation detection
  - IAT (Import Address Table) hooking detection
  - Inline hooking detection

- **👻 Rootkit Detection**
  - Hidden driver identification
  - SSDT (System Service Descriptor Table) hooks
  - IRP (I/O Request Packet) hooking
  - Kernel-mode code analysis

- **🔐 Memory Region Analysis**
  - Permission analysis (RWX regions)
  - Entropy calculation for packed code
  - Suspicious memory patterns
  - Executable region validation

- **📊 Pattern Matching**
  - Known malware signature detection
  - Suspicious API call identification
  - String extraction and analysis
  - Behavioural pattern recognition

- **📝 Comprehensive Reporting**
  - Detailed analysis reports
  - Risk level assessment
  - Actionable recommendations
  - Export to text files

---

## 🛠️ Technology Stack

### Core Technologies
- **C++17** - Modern C++ with filesystem support
- **STL** - Standard Template Library
- **UK English** - Spellings and terminology

### Forensics Techniques
- **OS Internals** - Windows kernel structures
- **Pattern Recognition** - Malware signatures
- **Entropy Analysis** - Packed code detection
- **String Analysis** - Suspicious content identification

---

## 📦 Installation

### Prerequisites

**Linux/macOS:**
- g++ 7.0+ or clang++ 5.0+
- C++17 support
- Standard C++ library

**Windows:**
- MinGW-w64 or MSVC 2017+
- C++17 support

### Compilation

**Linux/macOS:**
```bash
# Standard compilation
g++ -std=c++17 -o memscope memscope.cpp

# With optimisations
g++ -std=c++17 -O3 -o memscope memscope.cpp

# With debugging symbols
g++ -std=c++17 -g -o memscope memscope.cpp
```

**Windows (MinGW):**
```bash
g++ -std=c++17 -o memscope.exe memscope.cpp
```

**Windows (MSVC):**
```bash
cl /EHsc /std:c++17 memscope.cpp
```

### Verification

```bash
# Test compilation
./memscope --demo
```

---

## 🚀 Quick Start

### Demo Mode

```bash
# Run with demonstration data
./memscope --demo
```

This will:
1. Generate a sample memory dump
2. Perform all analysis techniques
3. Display comprehensive report
4. Save results to file

### Analyse Memory Dump

```bash
# Analyse a real memory dump
./memscope memory_dump.dmp

# Analyse with specific name
./memscope /path/to/suspicious_memory.bin
```

---

## 🎮 Usage Examples

### Example 1: Basic Analysis

```bash
$ ./memscope memory.dmp
```

**Output:**
```
╔═══════════════════════════════════════════════════════════╗
║              MEMSCOPE PRO v1.0                            ║
║           Memory Forensics Toolkit                       ║
║              by Michael Semera                            ║
╚═══════════════════════════════════════════════════════════╝

[INFO] Initialising MemScope Pro Memory Analyser
[INFO] Target dump file: memory.dmp
[INFO] Loading memory dump file...
[INFO] Memory dump size: 512.00 MB
✓ Memory dump loaded successfully

╔═══════════════════════════════════════════════════════════╗
║               MEMORY ANALYSIS IN PROGRESS                 ║
╚═══════════════════════════════════════════════════════════╝

[1/6] Scanning for known malware patterns...
  ⚠️  WARNING: Detected malware pattern: mimikatz
✓ Malware pattern scan complete

[2/6] Detecting hidden processes...
  ⚠️  Hidden process detected: svchost32.exe (PID: 666)
✓ Process detection complete (4 total processes)

[3/6] Analysing memory regions...
  ⚠️  Suspicious memory region: 0x0000000010000000 (RWX permissions)
  ⚠️  High entropy region detected: 0x0000000020000000 (Entropy: 7.80)
✓ Memory region analysis complete

[4/6] Detecting code injection...
  ⚠️  Potential code injection detected
✓ Code injection scan complete

[5/6] Scanning for suspicious API calls...
  ⚠️  Suspicious API found: CreateRemoteThread
  ⚠️  Suspicious API found: WriteProcessMemory
✓ API scan complete

[6/6] Extracting and analysing strings...
  ✓ Extracted 1234 strings
  ⚠️  Suspicious string: password123
  ⚠️  Suspicious string: keylogger
✓ String analysis complete

╔═══════════════════════════════════════════════════════════╗
║               FORENSICS ANALYSIS REPORT                   ║
╚═══════════════════════════════════════════════════════════╝

═══ SUMMARY STATISTICS ═══
Memory Dump Size: 512.00 MB
Processes Analysed: 4
Memory Regions Analysed: 4
Total Suspicious Findings: 12

═══ SUSPICIOUS FINDINGS ═══
  • Malware Pattern Found: mimikatz: 1
  • Hidden Process: 1
  • RWX Memory Region: 1
  • High Entropy Region: 1
  • Code Injection: 1
  • Suspicious API: CreateRemoteThread: 1
  • Suspicious API: WriteProcessMemory: 1
  • Suspicious String: 5

═══ RISK ASSESSMENT ═══
🔴 Risk Level: CRITICAL

═══ RECOMMENDATIONS ═══
  ⚠️  Immediate Actions Required:
    1. Isolate affected system from network
    2. Conduct full malware scan
    3. Review suspicious processes and memory regions
    4. Check for rootkit presence
    5. Consider full system reimaging if compromised
    6. Review security logs for initial infection vector
    7. Update antivirus definitions and security policies

✓ Detailed report saved to: memscope_report.txt
```

### Example 2: Clean System

```bash
$ ./memscope clean_system.dmp
```

**Output:**
```
[6/6] Extracting and analysing strings...
  ✓ Extracted 987 strings
✓ String analysis complete

╔═══════════════════════════════════════════════════════════╗
║               FORENSICS ANALYSIS REPORT                   ║
╚═══════════════════════════════════════════════════════════╝

═══ SUMMARY STATISTICS ═══
Memory Dump Size: 256.00 MB
Processes Analysed: 45
Memory Regions Analysed: 128
Total Suspicious Findings: 0

═══ SUSPICIOUS FINDINGS ═══
✓ No suspicious activity detected

═══ RISK ASSESSMENT ═══
🟢 Risk Level: LOW

═══ RECOMMENDATIONS ═══
  ✓ System appears clean
  ✓ Continue regular security monitoring

✓ Detailed report saved to: memscope_report.txt
```

---

## 🔬 Analysis Techniques

### 1. Hidden Process Detection

**Technique**: EPROCESS Structure Traversal

```
┌────────────────────────────────────────────────────┐
│          EPROCESS Detection Methods                │
├────────────────────────────────────────────────────┤
│                                                    │
│  Method 1: PsActiveProcessHead Traversal          │
│    • Walk linked list of processes                │
│    • Compare with task manager list               │
│    • Identify missing processes (DKOM)            │
│                                                    │
│  Method 2: Pool Tag Scanning                      │
│    • Search for "Proc" pool tags                  │
│    • Validate EPROCESS structures                 │
│    • Find unlinked processes                      │
│                                                    │
│  Method 3: Thread-based Discovery                 │
│    • Enumerate all threads                        │
│    • Extract parent EPROCESS                      │
│    • Find orphaned threads                        │
│                                                    │
└────────────────────────────────────────────────────┘
```

**Indicators:**
- Process in pool memory but not in ActiveProcessHead
- Mismatched PID in different enumerations
- Thread without valid parent process

### 2. Code Injection Detection

**Patterns Detected:**
- **Remote Thread Injection**: CreateRemoteThread API
- **Process Hollowing**: Unmapped PE sections
- **DLL Injection**: LoadLibrary in foreign process
- **APC Injection**: Queued APCs to other processes
- **Reflective Loading**: PE in non-image memory

**Shellcode Signatures:**
```
Common Patterns:
  0x90909090  →  NOP sled
  0xebfe      →  jmp $ (infinite loop)
  0xcccccc    →  int3 breakpoints
  0x558bec    →  push ebp; mov ebp, esp
```

### 3. Rootkit Detection

**DKOM (Direct Kernel Object Manipulation)**:
- Process unlinked from EPROCESS list
- Driver hidden from PsLoadedModuleList
- Registry key hidden from enumeration

**Hooking Detection**:
```
1. SSDT Hooks
   └─ Compare SSDT entries with ntoskrnl.exe exports
   
2. IRP Hooks
   └─ Verify driver dispatch routines
   
3. IDT Hooks
   └─ Check Interrupt Descriptor Table entries

4. Inline Hooks
   └─ Disassemble function prologues for jumps
```

### 4. Memory Region Analysis

**Entropy Calculation**:
```cpp
// Shannon Entropy Formula
entropy = -Σ(p(x) * log2(p(x)))

Interpretation:
  0.0 - 3.0  →  Low entropy (plain text, zeros)
  3.0 - 6.0  →  Medium entropy (normal code)
  6.0 - 7.0  →  High entropy (compressed)
  7.0 - 8.0  →  Very high (encrypted/packed)
```

**Suspicious Permissions**:
- **RWX (Read-Write-Execute)**: Most suspicious
  - Allows code modification and execution
  - Common in malware
  
- **WX (Write-Execute)**: Highly suspicious
  - DEP bypass indicator
  - Self-modifying code

### 5. String Analysis

**Extracted Strings Indicate**:
- **File paths**: Malware installation locations
- **URLs**: C2 servers, download URLs
- **Registry keys**: Persistence mechanisms
- **Function names**: Capabilities (keylog, screenshot)
- **Credentials**: Stolen passwords

**Suspicious Patterns**:
```
Keywords:        Significance:
─────────────────────────────────────────
password         Credential theft
keylog           Keylogger
inject           Code injection
exploit          Exploitation tool
backdoor         Remote access
trojan           Malware type
root/admin       Privilege escalation
cmd/powershell   Command execution
```

---

## 📊 Output Files

### Generated Reports

**memscope_report.txt** - Comprehensive analysis report
```
═══════════════════════════════════════════════════════════
              MEMSCOPE PRO FORENSICS REPORT
                   by Michael Semera
═══════════════════════════════════════════════════════════

Analysis Date: 2025-01-15 14:30:00
Memory Dump: suspicious_system.dmp
Dump Size: 512.00 MB

═══ FINDINGS ═══
Malware Pattern Found: mimikatz: 1
Hidden Process: 1
RWX Memory Region: 1
High Entropy Region: 1
Code Injection: 1
Suspicious API: CreateRemoteThread: 1
Suspicious API: WriteProcessMemory: 1
Suspicious String: 5

═══ PROCESS LIST ═══
PID: 4 | Name: System | Hidden: NO
PID: 500 | Name: svchost.exe | Hidden: NO
PID: 1024 | Name: explorer.exe | Hidden: NO
PID: 666 | Name: svchost32.exe | Hidden: YES

═══ MEMORY REGIONS ═══
0x0000000000400000-0x0000000000500000 | R-X | Entropy: 6.80
0x0000000000600000-0x0000000000700000 | RW- | Entropy: 5.20
0x0000000010000000-0x0000000010010000 | RWX | Entropy: 7.90
0x0000000020000000-0x0000000020100000 | R-X | Entropy: 7.80
```

---

## 🔐 Understanding EPROCESS

### Windows EPROCESS Structure

```c
typedef struct _EPROCESS {
    KPROCESS Pcb;                    // Process Control Block
    EX_PUSH_LOCK ProcessLock;        // Lock for process
    LARGE_INTEGER CreateTime;        // Process creation time
    LARGE_INTEGER ExitTime;          // Process exit time
    EX_RUNDOWN_REF RundownProtect;   // Rundown protection
    HANDLE UniqueProcessId;          // Process ID (PID)
    LIST_ENTRY ActiveProcessLinks;   // Linked list of processes
    ULONG_PTR QuotaPoolUsage[2];     // Pool usage
    HANDLE InheritedFromUniqueProcessId; // Parent PID (PPID)
    ULONG SessionId;                 // Session ID
    PVOID Peb;                       // Process Environment Block
    MM_AVL_TABLE VadRoot;            // Virtual Address Descriptors
    // ... many more fields
    CHAR ImageFileName[15];          // Process name
    // ...
} EPROCESS, *PEPROCESS;
```

**Key Fields for Forensics**:
- `UniqueProcessId` - Process ID
- `ActiveProcessLinks` - Link to next/prev process
- `ImageFileName` - Process name
- `Peb` - User-mode structures
- `InheritedFromUniqueProcessId` - Parent process

### DKOM Attack

**Direct Kernel Object Manipulation**:
```
Normal Process List:
System → svchost.exe → explorer.exe → chrome.exe

After DKOM (Hiding svchost32.exe):
System → svchost.exe → explorer.exe → chrome.exe
                ↓
         svchost32.exe (hidden, unlinked)
```

**Detection**: Compare multiple enumeration methods

---

## 🎓 Educational Topics

### Memory Forensics Concepts

1. **Physical vs. Virtual Memory**
   - Page tables and address translation
   - Memory management structures
   - Kernel vs. user mode

2. **Process Structures**
   - EPROCESS in Windows
   - task_struct in Linux
   - Process Control Block (PCB)

3. **Memory Artifacts**
   - Pagefile/swap analysis
   - Hibernation files
   - Crash dumps

4. **Volatility Analysis**
   - RAM volatility
   - Evidence preservation
   - Timeline reconstruction

### Malware Analysis

1. **Code Injection Techniques**
   - DLL injection
   - Process hollowing
   - APC injection
   - Reflective loading

2. **Rootkit Mechanisms**
   - DKOM attacks
   - Hooking techniques
   - Filter drivers

3. **Evasion Techniques**
   - Anti-forensics
   - Anti-debugging
   - VM detection

---

## 🐛 Troubleshooting

### Common Issues

**Issue**: `Compilation error: filesystem not found`
```bash
# Solution: Ensure C++17 support
g++ -std=c++17 -o memscope memscope.cpp

# Or link filesystem explicitly
g++ -std=c++17 -o memscope memscope.cpp -lstdc++fs
```

**Issue**: `Permission denied` when reading dump
```bash
# Solution: Check file permissions
chmod +r memory_dump.dmp

# Or run with elevated privileges
sudo ./memscope memory_dump.dmp
```

**Issue**: `Out of memory` with large dumps
```bash
# Solution: Analyse in chunks or increase system memory
# For large dumps (>4GB), consider streaming analysis
```

**Issue**: No suspicious findings in known-bad dump
```bash
# This tool uses simplified detection
# For comprehensive analysis, use Volatility:
volatility -f memory.dmp --profile=Win10x64 pslist
volatility -f memory.dmp --profile=Win10x64 malfind
```

---

## 📚 Further Learning

### Recommended Resources

**Books:**
1. **"The Art of Memory Forensics"** by Michael Hale Ligh et al.
   - Comprehensive memory forensics guide
   - Volatility framework usage

2. **"Malware Analyst's Cookbook"** by Michael Ligh et al.
   - Practical malware analysis
   - Memory analysis recipes

3. **"Windows Internals"** by Mark Russinovich
   - Deep Windows OS knowledge
   - Essential for understanding structures

**Online Resources:**
- **Volatility Wiki**: github.com/volatilityfoundation/volatility/wiki
- **SANS DFIR**: digital-forensics.sans.org
- **Memory Forensics Blog**: volatility-labs.blogspot.com

### Related Tools

**Production Tools:**
- **Volatility** - Open-source memory forensics
- **Rekall** - Advanced memory analysis
- **WinDbg** - Windows debugger
- **GDB** - GNU debugger (Linux)
- **Redline** - FireEye's triage tool

---

## 🤝 Contributing

### How to Contribute

1. **Report Bugs**: Open issues with details
2. **Suggest Features**: Propose new analysis techniques
3. **Code Improvements**: Optimisation suggestions
4. **Documentation**: Improve explanations

### Areas for Enhancement

- Add Linux memory dump support
- Implement more sophisticated DKOM detection
- Add network artefact extraction
- Improve shellcode detection
- Add timeline reconstruction
- Implement plugin system

---

## ⚖️ License

MIT License

Copyright (c) 2025 Michael Semera

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.**

---

## 🙏 Acknowledgements

### Inspiration
- Volatility Framework
- Windows Internals book
- Memory forensics research community

### Technologies
- C++ Standard Library
- Modern C++17 features
- Forensics research

---

## 📞 Contact & Support

For questions, suggestions, or collaboration opportunities:
- Open an issue on GitHub
- Email: michaelsemera15@gmail.com
- LinkedIn: [Michael Semera](https://www.linkedin.com/in/michael-semera-586737295/)

For issues or questions:
- Review this documentation
- Check troubleshooting section
- Ensure proper privileges and setup
- Verify libpcap installation


**Author**: Michael Semera  
**Project**: MemScope Pro  
**Version**: 1.0  
**Year**: 2025  
**Language**: C++ (UK English)

### Getting Help

1. Read this documentation
2. Check troubleshooting section
3. Review code comments
4. Test with demo mode first

---

## ⚠️ Legal & Ethical Considerations

### Use Responsibly

✅ **Authorised Use Only**:
- Only analyse systems you own
- Get explicit permission
- Follow local laws

❌ **Do Not**:
- Analyse unauthorised systems
- Use for malicious purposes
- Violate privacy laws

### Chain of Custody

For legal forensics:
1. Proper evidence collection
2. Hash verification
3. Write blockers
4. Documentation
5. Professional tools

---

**Thank you for using MemScope Pro!**

*Analyse memory. Detect threats. Secure systems.* 🔍

---

**© 2025 Michael Semera. All Rights Reserved.**

*Built with 🔐 for memory forensics education and malware analysis.*

---

**Last Updated**: 2025  
**Documentation Version**: 1.0  
**C++ Standard**: C++17  
**Status**: Educational Release

---