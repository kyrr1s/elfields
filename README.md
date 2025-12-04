# ELF Field Manipulation Tool

A utility for modifying or extracting data from unused fields of ELF file headers.
Supports both C and Python implementations (I just practiced C and Python).

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

## C Implementation

### Building

```bash
make
```

### Installation

```bash
sudo make install
```

### Usage

```bash
# Read all fields (24 bytes)
elfields -a file.elf

# Read specific field
elfields --data file.elf

# Write to all fields
elfields -a -w deadbeef0123456789abcdef012345 file.elf

# Write to specific field
elfields --data -w 01 file.elf

# Preview changes without modifying file
elfields -n --data -w 02 file.elf

# Binary output
elfields -b --pad file.elf
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

### Individual fields

Use --fieldname for individual field operations:
```text
--class           EI_CLASS (byte order) (1 byte)
--data            EI_DATA (data encoding) (1 byte)
--ident_version   EI_VERSION (ident version) (1 byte)
--version         e_version (object file version) (4 bytes)
--pad             EI_PAD (padding bytes) (7 bytes)
--osabi           EI_OSABI (OS/ABI) (1 byte)
--abiversion      EI_ABIVERSION (ABI version) (1 byte)
--ehsize          e_ehsize (ELF header size) (2 bytes)
--shentsize       e_shentsize (section header size) (2 bytes)
--shnum           e_shnum (number of section headers) (2 bytes)
--shstrndx        e_shstrndx (section header string table index) (2 bytes)
```

## Python Implementation

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

Options are identical to the C version.

## Report

Somewhere in future