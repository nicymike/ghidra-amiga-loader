# ghidra-amiga

Ghidra extension for Amiga programs: loaders for Hunk executables, Kickstart ROMs and USS snapshots, plus an analyzer that
resolves calls into the system libraries.

Based on [ghidra_amiga_ldr](https://github.com/lab313ru/ghidra_amiga_ldr) by Vladimir Kononovich (No license)
and [ghidra-amiga-whdload](https://github.com/apparentlymart/ghidra-amiga-whdload) by Martin Atkins (MIT license).

## Features
- Loads Amiga Hunk executables (the memory type CHIP/FAST from the hunk header is added as a comment on the block), Kickstart ROMs and USS files
- Memory blocks for the Exec base pointer (address 4), the custom chip registers (`Custom`) and both CIAs (`CIAA` at 0xBFE001, `CIAB` at 0xBFD000), typed from the NDK 3.9 headers
- 32-bit relocations are applied and added to the relocation table (8/16-bit relocations are recorded as unsupported)
- Loader option **Prepare analysis for hand-written assembly** (on by default): switches off the analyzers that get in the way of
  assembly code (Call-Fixup Installer, Non-Returning Functions, Unicode string references). They can be switched on again in the
  *Auto Analyze* dialog, and the option can be switched off in the import dialog for programs from C compilers.
- **Amiga Library Calls** analyzer: assigns calls like `jsr -552(a6)` to the called library function.
  The library is determined from A6 by following the control flow backwards (Exec base from address 4, base variables written after
  `OpenLibrary`, including variables relative to A4/A5). Libraries that the program opens with `OpenLibrary("xyz.library")` are enabled
  automatically. Calls whose library cannot be determined unambiguously are left alone.

In headless mode the loader options are set with `-loader-baseAddr <hex address>` (image base of Hunk executables) and
`-loader-assemblyAnalysis <true|false>`.

## Requirements
- Ghidra 12.2 and Java 25 (the extension only loads into the Ghidra version it was built against)
- Maven to build it

## Build and install
```
mvn package -Dghidra.install.dir=/path/to/ghidra
```

The extension zip is created in `target/`. Install it in Ghidra with *File > Install Extensions...* and restart Ghidra.
`ghidra.install.dir` defaults to `/opt/ghidra`. To build against another Ghidra version, also pass `-Dghidra.version=<version>` and
`-Dmaven.compiler.release=<java version of that Ghidra>`.

## Development
- `data/amiga_ndk39.gdt` is created from the NDK 3.9 headers with the `amiga_ndk39.prf` C parser profile (put it into the `parseprofiles` folder
  of your Ghidra user settings). A few headers have been excluded due to parsing problems, and `pack.h` has been added to the start of the parsed
  headers to ensure correct struct alignment.
- Run the unit tests with `mvn test`.
