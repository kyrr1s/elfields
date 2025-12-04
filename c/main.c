#include "main.h"

const FieldInfo fields[] = {
    {"class", offsetof(Elf64_Ehdr, e_ident[EI_CLASS]), 1, "EI_CLASS (byte order)"},
    {"data", offsetof(Elf64_Ehdr, e_ident[EI_DATA]), 1, "EI_DATA (data encoding)"},
    {"ident_version", offsetof(Elf64_Ehdr, e_ident[EI_VERSION]), 1, "EI_VERSION (ident version)"},
    {"version", offsetof(Elf64_Ehdr, e_version), 4, "e_version (object file version)"},
    {"pad", offsetof(Elf64_Ehdr, e_ident[EI_PAD]), 7, "EI_PAD (padding bytes)"},
    {"osabi", offsetof(Elf64_Ehdr, e_ident[EI_OSABI]), 1, "EI_OSABI (OS/ABI)"},
    {"abiversion", offsetof(Elf64_Ehdr, e_ident[EI_ABIVERSION]), 1, "EI_ABIVERSION (ABI version)"},
    {"ehsize", offsetof(Elf64_Ehdr, e_ehsize), 2, "e_ehsize (ELF header size)"},
    {"shentsize", offsetof(Elf64_Ehdr, e_shentsize), 2, "e_shentsize (section header size)"},
    {"shnum", offsetof(Elf64_Ehdr, e_shnum), 2, "e_shnum (number of section headers)"},
    {"shstrndx", offsetof(Elf64_Ehdr, e_shstrndx), 2, "e_shstrndx (section header string table index)"},
    {NULL, 0, 0, NULL}
};

void print_hex(const unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
}

void print_binary(const unsigned char *data, size_t size) {
    fwrite(data, 1, size, stdout);
}

bool is_elf_file(const Elf64_Ehdr *ehdr) {
    return (ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
            ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
            ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
            ehdr->e_ident[EI_MAG3] == ELFMAG3);
}

const FieldInfo* find_field(const char *name) {
    for (int i = 0; fields[i].name != NULL; i++) {
        if (strcmp(fields[i].name, name) == 0) {
            return &fields[i];
        }
    }
    return NULL;
}

int write_all_fields(int fd, const unsigned char *data, size_t data_size, 
                    Elf64_Ehdr *ehdr, bool modify_file) {
    if (data_size > TOTAL_FIELD_SIZE) {
        fprintf(stderr, "Error: Data size (%zu) exceeds total field size (%d)\n", 
                data_size, TOTAL_FIELD_SIZE);
        return -1;
    }
    
    size_t offset = 0;
    for (int i = 0; fields[i].name != NULL && offset < data_size; i++) {
        size_t to_copy = fields[i].size;
        if (offset + to_copy > data_size) {
            to_copy = data_size - offset;
        }
        memcpy((char*)ehdr + fields[i].offset, data + offset, to_copy);
        offset += to_copy;
    }
    
    if (modify_file) {
        if (lseek(fd, 0, SEEK_SET) == -1) {
            perror("lseek");
            return -1;
        }
        if (write(fd, ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
            perror("write");
            return -1;
        }
    }
    
    return 0;
}

int read_all_fields(const Elf64_Ehdr *ehdr, size_t size, bool hex_output) {
    if (size > TOTAL_FIELD_SIZE) {
        fprintf(stderr, "Error: Requested size (%zu) exceeds total field size (%d)\n", 
                size, TOTAL_FIELD_SIZE);
        return -1;
    }
    
    unsigned char buffer[TOTAL_FIELD_SIZE];
    size_t offset = 0;
    
    for (int i = 0; fields[i].name != NULL && offset < size; i++) {
        size_t to_copy = fields[i].size;
        if (offset + to_copy > size) {
            to_copy = size - offset;
        }
        memcpy(buffer + offset, (const char*)ehdr + fields[i].offset, to_copy);
        offset += to_copy;
    }
    
    if (hex_output) {
        print_hex(buffer, size);
        printf("\n");
    } else {
        print_binary(buffer, size);
    }
    
    return 0;
}

int write_single_field(int fd, const char *field_name, 
                      const unsigned char *data, size_t data_size,
                      Elf64_Ehdr *ehdr, bool modify_file) {
    const FieldInfo *field = find_field(field_name);
    if (!field) {
        fprintf(stderr, "Error: Unknown field '%s'\n", field_name);
        return -1;
    }
    
    if (data_size != field->size) {
        fprintf(stderr, "Error: Data size (%zu) doesn't match field size (%zu)\n", 
                data_size, field->size);
        return -1;
    }
    
    memcpy((char*)ehdr + field->offset, data, field->size);
    
    if (modify_file) {
        if (lseek(fd, 0, SEEK_SET) == -1) {
            perror("lseek");
            return -1;
        }
        if (write(fd, ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
            perror("write");
            return -1;
        }
    }
    
    return 0;
}

int read_single_field(const Elf64_Ehdr *ehdr, const char *field_name, bool hex_output) {
    const FieldInfo *field = find_field(field_name);
    if (!field) {
        fprintf(stderr, "Error: Unknown field '%s'\n", field_name);
        return -1;
    }
    
    if (hex_output) {
        print_hex((const unsigned char*)ehdr + field->offset, field->size);
        printf("\n");
    } else {
        print_binary((const unsigned char*)ehdr + field->offset, field->size);
    }
    
    return 0;
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] <elf_file>\n", prog_name);
    printf("\nOptions:\n");
    printf("  -h, --help            Show this help message\n");
    printf("  -a, --all             Work with all fields (24 bytes total)\n");
    printf("  -w, --write <data>    Write data (hex string, e.g., deadbeef)\n");
    printf("  -r, --read <size>     Read data of specified size (for --all)\n");
    printf("  -x, --hex             Output in hex format (default for reading)\n");
    printf("  -b, --binary          Output in binary format\n");
    printf("  -n, --no-modify       Don't modify file, just show what would be done\n");
    printf("\nIndividual field operations (use with -w or without for read):\n");
    for (int i = 0; fields[i].name != NULL; i++) {
        printf("  --%-12s        %s (%zu byte%s)\n", 
               fields[i].name, fields[i].description, 
               fields[i].size, fields[i].size == 1 ? "" : "s");
    }
    printf("\nExamples:\n");
    printf("  %s -a -w deadbeef0123456789abcdef012345 file.elf\n", prog_name);
    printf("  %s -r file.elf\n", prog_name);
    printf("  %s --data -w 01 file.elf\n", prog_name);
    printf("  %s --pad file.elf\n", prog_name);
}

int hex_to_bin(const char *hex, unsigned char *bin, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string must have even length\n");
        return -1;
    }
    
    size_t bin_len = hex_len / 2;
    if (bin_len > max_len) {
        fprintf(stderr, "Error: Hex data too long\n");
        return -1;
    }
    
    for (size_t i = 0; i < bin_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bin[i]) != 1) {
            fprintf(stderr, "Error: Invalid hex character\n");
            return -1;
        }
    }
    
    return bin_len;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    bool all_fields = false;
    bool write_mode = false;
    bool read_mode = false;
    bool modify_file = true;
    bool hex_output = true;
    bool binary_output = false;
    const char *field_name = NULL;
    const char *write_data = NULL;
    const char *filename = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            all_fields = true;
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--write") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing data for -w option\n");
                return 1;
            }
            write_mode = true;
            write_data = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--read") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing size for -r option\n");
                return 1;
            }
            read_mode = true;
        } else if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--hex") == 0) {
            hex_output = true;
            binary_output = false;
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--binary") == 0) {
            hex_output = false;
            binary_output = true;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-modify") == 0) {
            modify_file = false;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            field_name = argv[i] + 2;
        } else {
            if (filename) {
                fprintf(stderr, "Error: Multiple filenames specified\n");
                return 1;
            }
            filename = argv[i];
        }
    }
    
    if (!filename) {
        fprintf(stderr, "Error: No filename specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (write_mode && read_mode) {
        fprintf(stderr, "Error: Cannot specify both -w and -r\n");
        return 1;
    }
    
    if (all_fields && field_name) {
        fprintf(stderr, "Error: Cannot specify both --all and individual field\n");
        return 1;
    }
    
    if (hex_output && binary_output) {
        fprintf(stderr, "Error: Cannot specify both --hex and --binary\n");
        return 1;
    }
    
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read");
        close(fd);
        return 1;
    }
    
    if (!is_elf_file(&ehdr)) {
        fprintf(stderr, "Error: Not an ELF file\n");
        close(fd);
        return 1;
    }
    
    int result = 0;
    
    if (all_fields) {
        if (write_mode) {
            unsigned char data[TOTAL_FIELD_SIZE];
            int data_size = hex_to_bin(write_data, data, sizeof(data));
            if (data_size < 0) {
                result = 1;
            } else {
                result = write_all_fields(fd, data, data_size, &ehdr, modify_file);
            }
        } else {
            result = read_all_fields(&ehdr, TOTAL_FIELD_SIZE, hex_output);
        }
    } else if (field_name) {
        if (write_mode) {
            unsigned char data[16];
            int data_size = hex_to_bin(write_data, data, sizeof(data));
            if (data_size < 0) {
                result = 1;
            } else {
                result = write_single_field(fd, field_name, data, data_size, &ehdr, modify_file);
            }
        } else {
            result = read_single_field(&ehdr, field_name, hex_output);
        }
    } else {
        if (!write_mode && !read_mode) {
            result = read_all_fields(&ehdr, TOTAL_FIELD_SIZE, hex_output);
        } else {
            fprintf(stderr, "Error: Specify either --all or individual field\n");
            result = 1;
        }
    }
    
    close(fd);
    return result;
}