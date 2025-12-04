# ELF Field Manipulation Tool

A small script for modifying or extracting data from unused fields of ELF file headers.

## Features

- Read/write individual ELF header fields
- Bulk operations on all customizable fields (24 bytes total)
- Hex and binary output formats
- Safe mode (preview changes without modifying files)
- Support for the following ELF header fields:
  - `EI_CLASS` (byte order)
  - `EI_DATA` (data encoding)
  - `EI_VERSION` (ident version)
  - `e_version` (object file version)
  - `EI_PAD` (padding bytes, 7 bytes)
  - `EI_OSABI` (OS/ABI)
  - `EI_ABIVERSION` (ABI version)
  - `e_ehsize` (ELF header size)
  - `e_shentsize` (section header size)
  - `e_shnum` (number of section headers)
  - `e_shstrndx` (section header string table index)

### Requirements
```bash
pip install pyelftools
```

### Usage
```bash
python elfields.py -a file.elf
python elfields.py --data file.elf
python elfields.py -a -w deadbeef0123456789abcdef012345 file.elf
python elfields.py --data -w 01 file.elf
python elfields.py -a -r 16 file.elf
```

### Options

```text
-h, --help            Show help message
-a, --all             Work with all fields (24 bytes total)
-w, --write <data>    Write data (hex string)
-x, --hex             Output in hex format (default)
-b, --binary          Output in binary format
-n, --no-modify       Don't modify file, just show what would be done
```

## Research

Somewhere in future