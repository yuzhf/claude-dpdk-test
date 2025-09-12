# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a DPDK-based C application project that builds a network application called `suna_ai_dpi`. The project uses a pre-compiled DPDK installation with static libraries and includes external libraries like cJSON, libzmq, and Hyperscan for JSON parsing, message queuing, and pattern matching respectively.

## Build System

The project uses a traditional Makefile-based build system:

- **Build command**: `make`
- **Clean command**: `make clean`
- **Target executable**: `bin/suna_ai_dpi`

### Build Configuration
- **Compiler**: gcc with `-g -Wall -march=znver1` flags
- **Include paths**: 
  - `./include` (currently empty)
  - DPDK headers from `dpdk-include/`
  - External library headers from `ext-libs/*/include/`
- **Libraries**: Extensive DPDK static library linking with additional dependencies (pthread, numa, pcap, ssl, crypto, etc.)

## Directory Structure

```
base-dpdk-test/
├── Makefile           # Build configuration with DPDK linking
├── src/               # Source code directory (currently empty)
├── obj/               # Build object files
├── bin/               # Final executable output
├── dpdk-include/      # DPDK header files
├── dpdk-libs/         # DPDK static libraries (.a files)
└── ext-libs/          # External libraries (cJSON, libzmq, libhs, libjson)
    ├── cjson/
    ├── ck/
    ├── libhs/         # Hyperscan pattern matching
    ├── libjson/       # JSON-C library
    └── libzmq/        # ZeroMQ messaging
```

## Key Architecture Notes

1. **DPDK Integration**: This is a DPDK application that requires proper DPDK environment setup and hugepages configuration to run.

2. **Static Linking**: The project uses comprehensive static linking of DPDK libraries, requiring careful management of link order and dependencies.

3. **External Dependencies**: Multiple external libraries are integrated:
   - **cJSON/libjson**: JSON parsing and manipulation
   - **libzmq**: ZeroMQ messaging for inter-process communication
   - **libhs**: Hyperscan for high-performance regular expression matching
   - **ck**: Concurrency Kit for lock-free data structures

4. **Target Architecture**: Optimized for AMD Zen architecture (`-march=znver1`)

## Development Workflow

1. Add source files to `src/` directory
2. Run `make` to build the application  
3. Run `make clean` to remove build artifacts
4. The final executable will be generated as `bin/suna_ai_dpi`

## Important Notes

- No test framework is currently configured
- Source directory is currently empty - this appears to be a template/skeleton project
- DPDK applications typically require root privileges and proper system configuration
- The extensive DPDK library linking suggests this is intended for high-performance network packet processing