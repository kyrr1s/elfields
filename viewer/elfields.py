#!/usr/bin/env python3
import argparse
import sys
from dataclasses import dataclass
from typing import Optional

TOTAL_FIELD_SIZE = 24

@dataclass
class FieldInfo:
    name: str
    offset: int
    size: int
    description: str

FIELDS = [
    FieldInfo("class", 4, 1, "EI_CLASS (byte order)"),
    FieldInfo("data", 5, 1, "EI_DATA (data encoding)"),
    FieldInfo("ident_version", 6, 1, "EI_VERSION (ident version)"),
    FieldInfo("version", 20, 4, "e_version (object file version)"),
    FieldInfo("pad", 7, 7, "EI_PAD (padding bytes)"),
    FieldInfo("osabi", 16, 1, "EI_OSABI (OS/ABI)"),
    FieldInfo("abiversion", 17, 1, "EI_ABIVERSION (ABI version)"),
    FieldInfo("ehsize", 40, 2, "e_ehsize (ELF header size)"),
    FieldInfo("shentsize", 58, 2, "e_shentsize (section header size)"),
    FieldInfo("shnum", 60, 2, "e_shnum (number of section headers)"),
    FieldInfo("shstrndx", 62, 2, "e_shstrndx (section header string table index)"),
]

def find_field(name: str) -> Optional[FieldInfo]:
    for field in FIELDS:
        if field.name == name:
            return field
    return None

def hex_to_bin(hex_str: str) -> bytes:
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return hex_str.encode('utf-8')

def print_field_with_name(field_name: str, data: bytes, hex_output: bool) -> None:
    if hex_output:
        sys.stdout.buffer.write(f"{field_name}: {data.hex()}\n".encode())
    else:
        try:
            text = data.decode('utf-8', errors='strict')
            if all(32 <= c < 127 for c in data):
                sys.stdout.buffer.write(f"{field_name}: {text}\n".encode())
            else:
                sys.stdout.buffer.write(f"{field_name}: {data.hex()}\n".encode())
        except (UnicodeDecodeError, ValueError):
            sys.stdout.buffer.write(f"{field_name}: {data.hex()}\n".encode())

def read_all_fields_without_names(header_data: bytes, size: int, hex_output: bool) -> None:
    if size > TOTAL_FIELD_SIZE:
        raise ValueError(f"Requested size ({size}) exceeds total field size ({TOTAL_FIELD_SIZE})")
    
    result = bytearray()
    offset = 0
    
    for field in FIELDS:
        if offset >= size:
            break
        to_copy = min(field.size, size - offset)
        result.extend(header_data[field.offset:field.offset + to_copy])
        offset += to_copy
    
    if hex_output:
        sys.stdout.buffer.write(result.hex().encode())
        sys.stdout.buffer.write(b'\n')
    else:
        try:
            text = result.decode('utf-8', errors='strict')
            if all(32 <= c < 127 for c in result):
                sys.stdout.buffer.write(text.encode())
                sys.stdout.buffer.write(b'\n')
            else:
                sys.stdout.buffer.write(result.hex().encode())
                sys.stdout.buffer.write(b'\n')
        except (UnicodeDecodeError, ValueError):
            sys.stdout.buffer.write(result.hex().encode())
            sys.stdout.buffer.write(b'\n')

def read_all_fields_with_names(header_data: bytes, size: int, hex_output: bool) -> None:
    if size > TOTAL_FIELD_SIZE:
        raise ValueError(f"Requested size ({size}) exceeds total field size ({TOTAL_FIELD_SIZE})")
    
    offset = 0
    
    for field in FIELDS:
        if offset >= size:
            break
        to_copy = min(field.size, size - offset)
        field_data = header_data[field.offset:field.offset + to_copy]
        print_field_with_name(field.name, field_data, hex_output)
        offset += to_copy

def read_single_field_simple(header_data: bytes, field_name: str, hex_output: bool) -> None:
    field = find_field(field_name)
    if not field:
        raise ValueError(f"Unknown field '{field_name}'")
    
    field_data = header_data[field.offset:field.offset + field.size]
    
    if hex_output:
        sys.stdout.buffer.write(field_data.hex().encode())
        sys.stdout.buffer.write(b'\n')
    else:
        try:
            text = field_data.decode('utf-8', errors='strict')
            if all(32 <= c < 127 for c in field_data):
                sys.stdout.buffer.write(text.encode())
                sys.stdout.buffer.write(b'\n')
            else:
                sys.stdout.buffer.write(field_data.hex().encode())
                sys.stdout.buffer.write(b'\n')
        except (UnicodeDecodeError, ValueError):
            sys.stdout.buffer.write(field_data.hex().encode())
            sys.stdout.buffer.write(b'\n')

def read_single_field_with_name(header_data: bytes, field_name: str, hex_output: bool) -> None:
    field = find_field(field_name)
    if not field:
        raise ValueError(f"Unknown field '{field_name}'")
    
    field_data = header_data[field.offset:field.offset + field.size]
    print_field_with_name(field_name, field_data, hex_output)

def write_all_fields(header_data: bytes, write_data: bytes) -> bytes:
    if len(write_data) > TOTAL_FIELD_SIZE:
        raise ValueError(f"Data size ({len(write_data)}) exceeds total field size ({TOTAL_FIELD_SIZE})")
    
    data = bytearray(header_data)
    offset = 0
    
    for field in FIELDS:
        if offset >= len(write_data):
            break
        to_copy = min(field.size, len(write_data) - offset)
        data[field.offset:field.offset + to_copy] = write_data[offset:offset + to_copy]
        offset += to_copy
    
    return bytes(data)

def write_single_field(header_data: bytes, field_name: str, write_data: bytes) -> bytes:
    field = find_field(field_name)
    if not field:
        raise ValueError(f"Unknown field '{field_name}'")
    
    if len(write_data) != field.size:
        raise ValueError(f"Data size ({len(write_data)}) doesn't match field size ({field.size})")
    
    data = bytearray(header_data)
    data[field.offset:field.offset + field.size] = write_data
    
    return bytes(data)

def read_elf_header(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        header_data = f.read(64)
        if len(header_data) >= 4 and header_data[:4] != b'\x7fELF':
            raise ValueError("Not a valid ELF file")
        return header_data

def write_elf_header(filename: str, header_data: bytes, modify: bool) -> None:
    if modify:
        with open(filename, 'r+b') as f:
            f.seek(0)
            f.write(header_data)
    else:
        sys.stdout.buffer.write(f"Modified header: {header_data.hex()}\n".encode())

def main() -> None:
    parser = argparse.ArgumentParser(description='ELF field manipulation tool')
    parser.add_argument('file', help='ELF file')
    parser.add_argument('-a', '--all', action='store_true', help='Work with all fields (24 bytes total)')
    parser.add_argument('-w', '--write', metavar='DATA', help='Write data (hex string or text, e.g., deadbeef or "some text")')
    parser.add_argument('-r', '--read', metavar='SIZE', type=int, help='Read data of specified size (for --all)')
    parser.add_argument('-x', '--hex', action='store_true', help='Output in hex format')
    parser.add_argument('-n', '--no-modify', action='store_true', help="Don't modify file, just show what would be done")
    parser.add_argument('-s', '--simple', action='store_true', help='Simple output (just data without field names)')
    
    field_group = parser.add_argument_group('Individual field operations')
    for field in FIELDS:
        field_group.add_argument(f'--{field.name}', action='store_true', help=field.description)
    
    args = parser.parse_args()
    
    try:
        header_data = read_elf_header(args.file)
        
        field_name = None
        for field in FIELDS:
            if getattr(args, field.name):
                field_name = field.name
                break
        
        if args.all and field_name:
            raise ValueError("Cannot specify both --all and individual field")
        
        modify_file = not args.no_modify
        hex_output = args.hex
        
        if args.all:
            if args.write:
                write_data = hex_to_bin(args.write)
                new_header = write_all_fields(header_data, write_data)
                write_elf_header(args.file, new_header, modify_file)
            else:
                size = args.read if args.read else TOTAL_FIELD_SIZE
                if args.simple:
                    read_all_fields_without_names(header_data, size, hex_output)
                else:
                    read_all_fields_with_names(header_data, size, hex_output)
        elif field_name:
            if args.write:
                write_data = hex_to_bin(args.write)
                new_header = write_single_field(header_data, field_name, write_data)
                write_elf_header(args.file, new_header, modify_file)
            else:
                if args.simple:
                    read_single_field_simple(header_data, field_name, hex_output)
                else:
                    read_single_field_with_name(header_data, field_name, hex_output)
        else:
            if args.write or args.read:
                raise ValueError("Specify either --all or individual field")
            size = args.read if args.read else TOTAL_FIELD_SIZE
            if args.simple:
                read_all_fields_without_names(header_data, size, hex_output)
            else:
                read_all_fields_with_names(header_data, size, hex_output)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()