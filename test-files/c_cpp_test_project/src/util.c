/**
 * util.c — Utility functions (mirrors source_code/utils.c)
 *
 * Expected scanner findings:
 *   Line 24: MEM-UNSAFE-COPY — memcpy with variable 'n' as size
 *   Line 45: MEM-RETURN-LOCAL — return with &local inside expression
 *   Line 54: INT-NARROW — uint32_t -> uint16_t narrowing cast
 *   Line 55: INT-NARROW — size_t -> int narrowing assignment
 */

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_DUP_SIZE (8 * 1024 * 1024)

void* safedup(const void* src, size_t n) {
    if (src == NULL || n == 0)
        return NULL;
    if (n > MAX_DUP_SIZE)
        return NULL;
    void* dst = malloc(n);
    if (dst != NULL)
        memcpy(dst, src, n);                /* MATCH: MEM-UNSAFE-COPY (variable size) */
    return dst;
}

uint32_t readU32BE(const char* p) {
    unsigned char* b = (unsigned char*)p;
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

uint16_t readU16BE(const char* p) {
    unsigned char* b = (unsigned char*)p;
    return (b[0] << 8) | b[1];
}

void die(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int fileExists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;            /* MATCH: MEM-RETURN-LOCAL (FP — &st passed as arg) */
}

/* narrowing helpers for legacy compatibility */
uint16_t truncateToU16(uint32_t val) {
    return (uint16_t)val;                    /* MATCH: INT-NARROW — 32-bit to 16-bit cast */
}

void printCount(size_t total) {
    int count = total;                       /* MATCH: INT-NARROW — size_t to int */
    printf("Count: %d\n", count);
}
