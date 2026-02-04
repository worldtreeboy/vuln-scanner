/**
 * config.c — Binary configuration file parser
 *
 * Demonstrates another realistic protocol parsing scenario, similar to
 * handler.c but for a config format instead of network commands.
 *
 * Wire format:
 *   [2 bytes name_len][name_len bytes name]
 *   [2 bytes host_len][host_len bytes host]
 *   [4 bytes port][4 bytes max_conns]
 *
 * Expected scanner findings:
 *   Line 34:  MEM-UNVALIDATED-SIZE — safedup with name_len from readU16BE
 *   Line 46:  MEM-UNVALIDATED-SIZE — safedup with host_len from readU16BE
 *   Line 58:  MEM-DANGLING-PTR     — returning &cfg (stack local) via result
 *   Line 73:  MEM-NULL-DEREF       — (char*)calloc without NULL check, alias used in read()
 *   Line 69:  INT-UNDERFLOW        — size_t fileSize = statResult - headerSize
 *   Line 85:  INT-SIGN-COMPARE     — int vs size_t comparison
 *   Line 96:  PTR-OOB-INDEX        — arr[-1] negative index
 *   Line 97:  PTR-OOB-INDEX        — arr[idx - 1] subtraction in index
 *   Line 103: PTR-ARITH            — *(base + offset) with variable offset
 */

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

config_t* parseConfigBuf(char* raw, size_t len) {
    config_t cfg;                                     /* stack local                    */
    config_t* result = &cfg;                          /* ptr to stack local             */

    /* --- name field: 2-byte BE length + data --- */
    uint16_t name_len = readU16BE(raw);
    raw += WORD_SIZE;
    result->name = (char*)safedup(raw, name_len + 1); /* MATCH: MEM-UNVALIDATED-SIZE   */
    if (!result->name)
        return NULL;
    result->name[name_len] = '\0';

    /* --- host field: 2-byte BE length + data --- */
    raw += name_len;
    uint16_t host_len = readU16BE(raw);
    raw += WORD_SIZE;
    result->host = (char*)safedup(raw, host_len + 1); /* MATCH: MEM-UNVALIDATED-SIZE   */
    if (!result->host)
        return NULL;                                   /* Note: leaks result->name      */
    result->host[host_len] = '\0';

    /* --- port (4 bytes) + max_conns (4 bytes) --- */
    raw += host_len;
    result->port      = (int)readU32BE(raw);
    raw += DWORD_SIZE;
    result->max_conns = (size_t)readU32BE(raw);

    return result;                                     /* MATCH: MEM-DANGLING-PTR       */
}

config_t* loadConfig(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0)
        return NULL;

    size_t headerSize = 32;
    size_t fileSize = st.st_size - headerSize;        /* MATCH: INT-UNDERFLOW          */
    /* if file < 32 bytes, fileSize wraps to huge value */

    char* raw = (char*)calloc(1, fileSize);            /* may fail after underflow      */
    char* cursor = raw;                                /* alias                         */

    FILE* fp = fopen(path, "rb");
    if (!fp) return NULL;

    fseek(fp, headerSize, SEEK_SET);
    fread(cursor, 1, fileSize, fp);                    /* MATCH: MEM-NULL-DEREF (alias) */
    fclose(fp);

    config_t* cfg = parseConfigBuf(raw, fileSize);
    free(raw);
    return cfg;
}

/* --- Additional pattern tests below --- */

/* INT-SIGN-COMPARE: signed int compared against unsigned size_t */
int validateIndex(int idx, size_t array_len) {
    if (idx < array_len)                               /* MATCH: INT-SIGN-COMPARE       */
        return 1;
    return 0;
}

/* PTR-OOB-INDEX: negative constant index and subtraction in index */
void dangerousIndexing(int* arr, int idx) {
    /* These patterns are common in off-by-one bugs and ring buffer code */
    arr[-1] = 0;                                       /* MATCH: PTR-OOB-INDEX (neg)    */
    arr[idx - 1] = 0;                                  /* MATCH: PTR-OOB-INDEX (sub)    */
}

/* PTR-ARITH: pointer dereference with computed offset */
char readAtOffset(char* base, int offset) {
    return *(base + offset);                           /* MATCH: PTR-ARITH              */
}
