# ELF Field Manipulation Tool

## Viewer

A small script for modifying or extracting data from unused fields of ELF file headers.

### Features

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
python elfields.py --hash=md5 file.elf
```

### Options

```text
-h, --help            Show help message
-a, --all             Work with all fields (24 bytes total)
-w, --write <data>    Write data (hex string)
-t, --text            Output in text format (default)
-x, --hex             Output in hex format
-n, --no-modify       Don't modify file, just show what would be done
-H, --hash            Show hash of the unused bytes
```

## Checker

A small library that provides function for verifying the integrity of an ELF file header unused fields by comparing the hash of specific fields with an expected value. Supports MD5, SHA1, SHA256 and SHA512 hashes.

### Main Function

```c
#include "elfields.h"

bool check_elf_fields(const char* hash_hex);
```

**Parameters:**
- `hash_hex` - hash string in hexadecimal format

**Return value:**
- `true` - hash matches
- `false` - hash doesn't match or an error occurred

### Example

```c
#include "elfields.h"

int main() {
    // Check hash of the unused fields in ELF Header of the current executable file
    if (check_elf_fields("d41d8cd98f00b204e9800998ecf8427e")) {
        printf("Hello World\n");
    } else {
        printf("Integrity check failed\n");
        return 1;
    }
    
    return 0;
}
```

## Compilation

OpenSSL 3.0 or higher is required:

```bash
gcc -o program main.c -lssl -lcrypto
```

### Obtaining Hash for Verification

To get the correct hash for your executable file:

1. Compile the program without hash verification
2. Use Viewer tool to compute hash of the specified unused fields
3. Compute the hash and insert it into the `check_elf_fields()` call
4. Recompile the program with the correct hash

## Research

[Abusing ELF Header' forgotten fields](https://kyrr1s.github.io/posts/abusing-elf-header-forgotten-fields/)