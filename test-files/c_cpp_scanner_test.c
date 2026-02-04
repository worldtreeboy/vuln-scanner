/**
 * c_cpp_scanner_test.c — Test cases for c_cpp_treesitter_scanner.py
 *
 * This file mimics the vulnerability patterns found in the source_code/
 * project (a network command server). Each function targets a specific
 * scanner rule. Run with:
 *
 *   python3 c_cpp_treesitter_scanner.py test-files/c_cpp_scanner_test.c --all
 *   python3 c_cpp_treesitter_scanner.py test-files/c_cpp_scanner_test.c        # default: CRITICAL+HIGH only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------- helpers (stubs) ---------- */
typedef struct {
    char*   outputFileName;
    uint8_t outputFlags;
    uint8_t operationIndex;
    char*   argument;
} command_t;

typedef struct {
    int socket_fd;
} client_t;

extern uint32_t dwordToIntBe(char* bytes);
extern void*    memdup(const void* mem, size_t size);
extern ssize_t  recv(int fd, void* buf, size_t len, int flags);

/* ============================================================
 * CRITICAL findings — these MUST fire with default settings
 * ============================================================ */

/*
 * Finding 1 — MEM-DANGLING-PTR
 * Returning pointer to stack-local struct via intermediate variable.
 * Real-world: handler.c parseCommand() returning &command.
 * Expected: CRITICAL / HIGH confidence
 */
command_t* test_dangling_ptr_return(char* data) {
    command_t local_cmd;                    /* stack-local struct         */
    command_t* ptr = &local_cmd;            /* ptr = &stack_local         */

    ptr->outputFileName = data;
    ptr->operationIndex = 1;

    return ptr;                             /* MATCH: dangling pointer    */
}

/*
 * Finding 2 — INT-UNDERFLOW
 * Unsigned subtraction that wraps if minuend < subtrahend.
 * Real-world: handler.c handleFrag() with commandLength < DWORD.
 * Expected: CRITICAL / HIGH confidence
 */
void test_unsigned_underflow(size_t commandLength) {
    size_t remaining = commandLength - 4;   /* MATCH: unsigned underflow  */
    char* buf = (char*)malloc(remaining);
    /* ... use buf ... */
    free(buf);
}

/*
 * Finding 3 — MEM-NULL-DEREF (with cast around malloc)
 * malloc returns NULL under memory pressure or after underflow;
 * result used without NULL check, including through aliases.
 * Real-world: handler.c handleFrag() — cmd/cmdPtr used in recv().
 * Expected: CRITICAL / HIGH confidence
 */
void test_null_deref_cast_alias(size_t n) {
    char* p = (char*)malloc(n);             /* may return NULL            */
    char* q = p;                            /* alias                      */
    recv(0, q, n, 0);                       /* MATCH: deref via alias q   */
}

/*
 * Finding 4 — MEM-UNVALIDATED-SIZE
 * Size for memcpy/memdup derived from a network byte-order conversion
 * function without bounds check.
 * Real-world: handler.c parseCommand() using dwordToIntBe length in memdup.
 * Expected: CRITICAL / HIGH confidence
 */
void test_unvalidated_size(char* cmd) {
    char len_buf[4];
    memcpy(len_buf, cmd, 4);
    uint32_t data_len = dwordToIntBe(len_buf);  /* length from wire data */

    cmd += 4;
    char* out = memdup(cmd, data_len + 1);  /* MATCH: no bounds check     */
    /* attacker can set data_len = 0xFFFF causing heap over-read */
    if (out)
        free(out);
}

/* ============================================================
 * Additional CRITICAL findings — variations
 * ============================================================ */

/* MEM-DANGLING-PTR: via assignment (not init) */
command_t* test_dangling_ptr_assign(char* data) {
    command_t stack_obj;
    command_t* result;
    result = &stack_obj;                    /* assignment variant          */
    result->argument = data;
    return result;                          /* MATCH: dangling pointer    */
}

/* INT-UNDERFLOW: -= operator variant */
void test_underflow_minus_equals(size_t total) {
    size_t remaining = total;
    size_t chunk = 100;
    remaining -= chunk;                     /* MATCH: unsigned -=         */
}

/* MEM-NULL-DEREF: direct (no alias, no cast) */
void test_null_deref_direct() {
    int* p = malloc(sizeof(int));
    *p = 42;                                /* MATCH: NULL deref          */
}

/* MEM-UNVALIDATED-SIZE: ntohl variant */
void test_ntohl_memcpy(char* packet) {
    uint32_t payload_len = ntohl(*(uint32_t*)packet);
    packet += 4;
    char dst[256];
    memcpy(dst, packet, payload_len);       /* MATCH: unvalidated size    */
}

/* MEM-DOUBLE-FREE */
void test_double_free() {
    char* buf = malloc(128);
    free(buf);
    free(buf);                              /* MATCH: double free         */
}

/* MEM-USE-AFTER-FREE */
void test_use_after_free() {
    int* p = malloc(sizeof(int));
    *p = 10;
    free(p);
    int x = *p;                             /* MATCH: use after free      */
}

/* ============================================================
 * HIGH severity findings (shown with --all or --min-severity HIGH)
 * ============================================================ */

/* MEM-UNSAFE-COPY: strcpy, gets, sprintf */
void test_unsafe_copy(char* input) {
    char buf[64];
    strcpy(buf, input);                     /* MATCH: strcpy              */
    strcat(buf, input);                     /* MATCH: strcat              */
    sprintf(buf, "%s", input);              /* MATCH: sprintf             */
    gets(buf);                              /* MATCH: gets                */
}

/* MEM-RETURN-LOCAL: direct return &local */
int* test_return_local_addr() {
    int val = 42;
    return &val;                            /* MATCH: return &local       */
}

/* DANGER-EXEC */
void test_dangerous_exec(char* cmd) {
    system(cmd);                            /* MATCH: system()            */
    popen(cmd, "r");                        /* MATCH: popen()             */
}

/* DANGER-FORMAT */
void test_format_string(char* user_fmt) {
    printf(user_fmt);                       /* MATCH: non-literal format  */
    fprintf(stderr, user_fmt);              /* MATCH                      */
}

/* INT-OVERFLOW-ALLOC */
void test_alloc_overflow(size_t n) {
    void* p = malloc(n * sizeof(int));      /* MATCH: overflow risk       */
    free(p);
}

/* ============================================================
 * MEDIUM severity findings (shown with --all)
 * ============================================================ */

/* MEM-BUFFER-OOB: write with variable index */
void test_buffer_oob(int idx) {
    int arr[10];
    arr[idx] = 1;                           /* MATCH: variable index      */
}

/* MEM-UNSAFE-COPY: memcpy with variable size */
void test_memcpy_var_size(void* dst, void* src, size_t len) {
    memcpy(dst, src, len);                  /* MATCH: variable size       */
}

/* PTR-OOB-INDEX: negative and large constant */
void test_oob_index() {
    int arr[10];
    arr[-1] = 0;                            /* MATCH: negative index      */
    arr[99999] = 0;                         /* MATCH: large index         */
}

/* PTR-ARITH: *(ptr + variable) */
void test_ptr_arith(char* buf, int offset) {
    char c = *(buf + offset);               /* MATCH: ptr arith           */
}

/* INT-SIGN-COMPARE: signed vs unsigned */
void test_sign_compare(int len, size_t size) {
    if (len < size)                         /* MATCH: signed/unsigned     */
        return;
}

/* INT-NARROW: narrowing conversion */
void test_narrowing() {
    size_t big = 999999;
    int small = big;                        /* MATCH: narrowing           */
    int cast = (int)big;                    /* MATCH: narrowing cast      */
}

/* ============================================================
 * Negative tests — these should NOT fire
 * ============================================================ */

/* Safe: malloc with proper NULL check */
void test_safe_malloc() {
    int* p = malloc(sizeof(int));
    if (p == NULL)
        return;
    *p = 42;                                /* NO MATCH: NULL checked     */
    free(p);
}

/* Safe: bounded memcpy with sizeof */
void test_safe_memcpy() {
    char dst[64];
    char src[64];
    memcpy(dst, src, sizeof(dst));          /* NO MATCH: sizeof is safe   */
}

/* Safe: system with string literal */
void test_safe_system() {
    system("ls -la");                       /* lower severity (literal)   */
}

/* Safe: printf with literal format */
void test_safe_printf() {
    printf("Hello %s\n", "world");          /* NO MATCH: literal format   */
}

/* Safe: heap-allocated struct returned (not dangling) */
command_t* test_safe_heap_return(char* data) {
    command_t* cmd = malloc(sizeof(command_t));
    if (!cmd) return NULL;
    cmd->argument = data;
    return cmd;                             /* NO MATCH: heap allocated   */
}
