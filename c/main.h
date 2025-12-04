#pragma once

#ifndef ELFIELDS
#define ELFIELDS

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdint.h>

#define TOTAL_FIELD_SIZE 24

typedef struct {
    const char *name;
    size_t offset;
    size_t size;
    const char *description;
} FieldInfo;

extern const FieldInfo fields[];

bool is_elf_file(const Elf64_Ehdr *ehdr);
const FieldInfo* find_field(const char *name);
int write_all_fields(int fd, const unsigned char *data, size_t data_size, 
                    Elf64_Ehdr *ehdr, bool modify_file);
int read_all_fields(const Elf64_Ehdr *ehdr, size_t size, bool hex_output);
int write_single_field(int fd, const char *field_name, 
                      const unsigned char *data, size_t data_size,
                      Elf64_Ehdr *ehdr, bool modify_file);
int read_single_field(const Elf64_Ehdr *ehdr, const char *field_name, bool hex_output);
void print_usage(const char *prog_name);
int hex_to_bin(const char *hex, unsigned char *bin, size_t max_len);
void print_hex(const unsigned char *data, size_t size);
void print_binary(const unsigned char *data, size_t size);

#endif