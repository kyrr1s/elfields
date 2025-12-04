#ifndef ELFIELDS_H
#define ELFIELDS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/evp.h>

typedef struct {
    uint32_t offset;
    uint32_t size;
} ElfField;

static const ElfField FIELDS[] = {
    {4, 1},
    {5, 1},
    {6, 1},
    {20, 4},
    {7, 7},
    {16, 1},
    {17, 1},
    {40, 2},
    {58, 2},
    {60, 2},
    {62, 2}
};

#define NUM_FIELDS (sizeof(FIELDS) / sizeof(FIELDS[0]))

static bool hex_to_binary(const char* hex_str, uint8_t* output, size_t output_len) {
    if (!hex_str || !output) return false;
    size_t hex_len = strlen(hex_str);
    if (hex_len != output_len * 2) return false;
    for (size_t i = 0; i < output_len; i++) {
        if (sscanf(hex_str + 2*i, "%2hhx", &output[i]) != 1) return false;
    }
    return true;
}

static bool compute_hash(const char* algorithm, const uint8_t* data, 
                        size_t data_len, uint8_t* hash, unsigned int* hash_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    
    const EVP_MD* md = EVP_get_digestbyname(algorithm);
    if (!md) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DigestFinal_ex(ctx, hash, hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    EVP_MD_CTX_free(ctx);
    return true;
}

bool check_elf_fields(const char* hash_hex) {
    if (!hash_hex) return false;
    
    size_t hex_len = strlen(hash_hex);
    const char* algorithm;
    size_t expected_hash_len;
    
    switch (hex_len) {
        case 32: algorithm = "md5"; expected_hash_len = 16; break;
        case 40: algorithm = "sha1"; expected_hash_len = 20; break;
        case 64: algorithm = "sha256"; expected_hash_len = 32; break;
        case 128: algorithm = "sha512"; expected_hash_len = 64; break;
        default: return false;
    }
    
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return false;
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }
    
    uint8_t* elf_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_data == MAP_FAILED) {
        close(fd);
        return false;
    }
    
    if (st.st_size < 64 || 
        elf_data[0] != 0x7F || elf_data[1] != 'E' || 
        elf_data[2] != 'L' || elf_data[3] != 'F') {
        munmap(elf_data, st.st_size);
        close(fd);
        return false;
    }
    
    size_t total_data_size = 0;
    for (size_t i = 0; i < NUM_FIELDS; i++) {
        const ElfField* field = &FIELDS[i];
        if (field->offset + field->size > (uint32_t)st.st_size) {
            munmap(elf_data, st.st_size);
            close(fd);
            return false;
        }
        total_data_size += field->size;
    }
    
    uint8_t* field_data = (uint8_t*)malloc(total_data_size);
    if (!field_data) {
        munmap(elf_data, st.st_size);
        close(fd);
        return false;
    }
    
    uint8_t* current_ptr = field_data;
    for (size_t i = 0; i < NUM_FIELDS; i++) {
        const ElfField* field = &FIELDS[i];
        memcpy(current_ptr, elf_data + field->offset, field->size);
        current_ptr += field->size;
    }
    
    uint8_t computed_hash[64];
    unsigned int computed_hash_len = 0;
    bool hash_success = compute_hash(algorithm, field_data, total_data_size, 
                                     computed_hash, &computed_hash_len);
    
    free(field_data);
    munmap(elf_data, st.st_size);
    close(fd);
    
    if (!hash_success || computed_hash_len != expected_hash_len) return false;
    
    uint8_t expected_hash[64];
    if (!hex_to_binary(hash_hex, expected_hash, expected_hash_len)) return false;
    
    return memcmp(expected_hash, computed_hash, expected_hash_len) == 0;
}

#endif