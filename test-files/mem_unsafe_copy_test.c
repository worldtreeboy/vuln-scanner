/**
 * mem_unsafe_copy_test.c — Comprehensive TP / TN / FP / FN test suite
 *                          for rule MEM-UNSAFE-COPY
 *
 * Tests the scanner's ability to detect unsafe string/memory copy operations
 * and to suppress findings on safe patterns.
 *
 *   TP  = True Positive   — vulnerable code, scanner SHOULD flag it     (good)
 *   TN  = True Negative   — safe code, scanner should NOT flag it       (good)
 *   FP  = False Positive  — safe code, scanner INCORRECTLY flags        (known weakness)
 *   FN  = False Negative  — vulnerable code, scanner MISSES             (known limitation)
 *
 * Every test function is named:  ucopy_<tp|tn|fp|fn><N>_<short_desc>
 * Every flaggable line is annotated with the expected outcome.
 *
 * Run:
 *   python3 c_cpp_treesitter_scanner.py test-files/mem_unsafe_copy_test.c --all
 *
 * Expected totals are listed at the bottom of this file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>

/* Stubs */
extern char* get_user_input(void);
extern size_t get_untrusted_len(void);
extern void process(const char*);
extern int validate_size(size_t sz, size_t max);
extern size_t bounded_len(const char* s, size_t max);

typedef void (*copy_fn)(char*, const char*);
typedef struct { char name[64]; char addr[128]; } record_t;
typedef struct { char buf[256]; size_t len; } strbuf_t;

#define MY_STRCPY(d,s) strcpy(d,s)
#define SAFE_COPY(d,s,n) strncpy(d,s,n)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

/* ============================================================================
 *  TRUE POSITIVES — Vulnerable code the scanner SHOULD detect
 * ============================================================================*/

/* TP-01: Classic strcpy from untrusted source */
void ucopy_tp01_strcpy_basic(char* dst, const char* src) {
    strcpy(dst, src);                                 /* TP: MEM-UNSAFE-COPY */
}

/* TP-02: strcat — unbounded append */
void ucopy_tp02_strcat_basic(char* dst, const char* src) {
    strcat(dst, src);                                 /* TP: MEM-UNSAFE-COPY */
}

/* TP-03: sprintf with %s — unbounded write */
void ucopy_tp03_sprintf_string(char* dst, const char* name) {
    sprintf(dst, "Hello, %s!", name);                 /* TP: MEM-UNSAFE-COPY */
}

/* TP-04: gets — always unsafe, removed in C11 */
void ucopy_tp04_gets(char* buf) {
    gets(buf);                                        /* TP: MEM-UNSAFE-COPY */
}

/* TP-05: vsprintf — unbounded va_list write */
void ucopy_tp05_vsprintf(char* dst, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsprintf(dst, fmt, ap);                           /* TP: MEM-UNSAFE-COPY */
    va_end(ap);
}

/* TP-06: wcscpy — wide-char variant */
void ucopy_tp06_wcscpy(wchar_t* dst, const wchar_t* src) {
    wcscpy(dst, src);                                 /* TP: MEM-UNSAFE-COPY */
}

/* TP-07: wcscat — wide-char concat */
void ucopy_tp07_wcscat(wchar_t* dst, const wchar_t* src) {
    wcscat(dst, src);                                 /* TP: MEM-UNSAFE-COPY */
}

/* TP-08: lstrcpy — Windows API unsafe copy */
void ucopy_tp08_lstrcpy(char* dst, const char* src) {
    lstrcpy(dst, src);                                /* TP: MEM-UNSAFE-COPY */
}

/* TP-09: lstrcpyW — Windows wide variant */
void ucopy_tp09_lstrcpyW(wchar_t* dst, const wchar_t* src) {
    lstrcpyW(dst, src);                               /* TP: MEM-UNSAFE-COPY */
}

/* TP-10: _tcscpy — TCHAR variant */
void ucopy_tp10_tcscpy(char* dst, const char* src) {
    _tcscpy(dst, src);                                /* TP: MEM-UNSAFE-COPY */
}

/* TP-11: strcpy into stack buffer from function argument */
void ucopy_tp11_stack_strcpy(const char* input) {
    char local[64];
    strcpy(local, input);                             /* TP: MEM-UNSAFE-COPY */
}

/* TP-12: sprintf with multiple %s — amplified overflow */
void ucopy_tp12_sprintf_multi(char* buf, const char* a, const char* b) {
    sprintf(buf, "%s:%s:%s", a, b, a);                /* TP: MEM-UNSAFE-COPY */
}

/* TP-13: strcat in a loop — progressively fills buffer */
void ucopy_tp13_strcat_loop(char* buf, char** items, int count) {
    buf[0] = '\0';
    for (int i = 0; i < count; i++) {
        strcat(buf, items[i]);                        /* TP: MEM-UNSAFE-COPY */
        strcat(buf, ",");                             /* TP: MEM-UNSAFE-COPY */
    }
}

/* TP-14: strcpy from argv — classic command-line overflow */
int ucopy_tp14_argv_strcpy(int argc, char** argv) {
    char buf[256];
    if (argc > 1)
        strcpy(buf, argv[1]);                         /* TP: MEM-UNSAFE-COPY */
    return 0;
}

/* TP-15: sprintf with %s and no width limit */
void ucopy_tp15_sprintf_no_width(char* buf, const char* s) {
    sprintf(buf, "[%s]", s);                          /* TP: MEM-UNSAFE-COPY */
}

/* TP-16: memcpy with untrusted size from function */
void ucopy_tp16_memcpy_untrusted_sz(char* dst, const char* src) {
    size_t n = get_untrusted_len();
    memcpy(dst, src, n);                              /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* TP-17: strncpy with strlen(src) — defeats bounds checking purpose */
void ucopy_tp17_strncpy_strlen(char* dst, const char* src) {
    strncpy(dst, src, strlen(src));                   /* TP: MEM-UNSAFE-COPY (size = strlen(src)) */
}

/* TP-18: memcpy with size from arithmetic expression (no sizeof) */
void ucopy_tp18_memcpy_arith_size(char* dst, const char* src, int count) {
    memcpy(dst, src, count * 4);                      /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* TP-19: memmove with raw variable size */
void ucopy_tp19_memmove_var_size(char* dst, const char* src, size_t len) {
    memmove(dst, src, len);                           /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* TP-20: strncat with variable size not validated */
void ucopy_tp20_strncat_var_size(char* dst, const char* src, size_t n) {
    strncat(dst, src, n);                             /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* TP-21: wsprintf — Windows unsafe wide sprintf */
void ucopy_tp21_wsprintf(wchar_t* dst, const wchar_t* name) {
    wsprintf(dst, L"Name: %s", name);                 /* TP: MEM-UNSAFE-COPY */
}

/* TP-22: strcpy result assigned — still unsafe */
char* ucopy_tp22_strcpy_retval(char* dst, const char* src) {
    return strcpy(dst, src);                          /* TP: MEM-UNSAFE-COPY */
}

/* TP-23: lstrcatA — Windows ANSI concat */
void ucopy_tp23_lstrcatA(char* dst, const char* src) {
    lstrcatA(dst, src);                               /* TP: MEM-UNSAFE-COPY */
}

/* TP-24: lstrcatW — Windows wide concat */
void ucopy_tp24_lstrcatW(wchar_t* dst, const wchar_t* src) {
    lstrcatW(dst, src);                               /* TP: MEM-UNSAFE-COPY */
}

/* TP-25: _tcscat — TCHAR concat */
void ucopy_tp25_tcscat(char* dst, const char* src) {
    _tcscat(dst, src);                                /* TP: MEM-UNSAFE-COPY */
}

/* TP-26: strcpy inside conditional — still vulnerable on that path */
void ucopy_tp26_strcpy_in_if(char* dst, const char* src, int flag) {
    if (flag)
        strcpy(dst, src);                             /* TP: MEM-UNSAFE-COPY */
}

/* TP-27: sprintf with mixed format — %d is bounded but %s is not */
void ucopy_tp27_sprintf_mixed(char* buf, int id, const char* name) {
    sprintf(buf, "id=%d name=%s", id, name);          /* TP: MEM-UNSAFE-COPY */
}

/* TP-28: lstrcpyA — Windows ANSI copy */
void ucopy_tp28_lstrcpyA(char* dst, const char* src) {
    lstrcpyA(dst, src);                               /* TP: MEM-UNSAFE-COPY */
}

/* TP-29: strcpy after malloc — buffer may be too small if logic is wrong */
void ucopy_tp29_strcpy_after_malloc(const char* src) {
    char* buf = malloc(16);
    strcpy(buf, src);                                 /* TP: MEM-UNSAFE-COPY — 16 bytes may be too small */
}

/* TP-30: wmemcpy with variable size */
void ucopy_tp30_wmemcpy_var(wchar_t* dst, const wchar_t* src, size_t n) {
    wmemcpy(dst, src, n);                             /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* TP-31: CopyMemory (Windows) with variable size */
void ucopy_tp31_copymemory(void* dst, const void* src, size_t n) {
    CopyMemory(dst, src, n);                          /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* TP-32: RtlCopyMemory (Windows kernel) with variable size */
void ucopy_tp32_rtlcopymemory(void* dst, const void* src, size_t n) {
    RtlCopyMemory(dst, src, n);                       /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* TP-33: wmemmove with variable size */
void ucopy_tp33_wmemmove_var(wchar_t* dst, const wchar_t* src, size_t n) {
    wmemmove(dst, src, n);                            /* TP: MEM-UNSAFE-COPY (variable size) */
}


/* ============================================================================
 *  TRUE NEGATIVES — Safe code the scanner should NOT flag
 * ============================================================================*/

/* TN-01: strncpy with sizeof(dst) — properly bounded */
void ucopy_tn01_strncpy_sizeof(const char* src) {
    char buf[64];
    strncpy(buf, src, sizeof(buf));                   /* TN: safe — sizeof bounds */
}

/* TN-02: snprintf — always bounded */
void ucopy_tn02_snprintf(const char* name) {
    char buf[128];
    snprintf(buf, sizeof(buf), "Hi %s", name);        /* TN: snprintf not in unsafe list */
}

/* TN-03: memcpy with sizeof(struct) — compile-time constant */
void ucopy_tn03_memcpy_sizeof_struct(record_t* dst, const record_t* src) {
    memcpy(dst, src, sizeof(record_t));               /* TN: sizeof is safe */
}

/* TN-04: memcpy with numeric literal size */
void ucopy_tn04_memcpy_literal(char* dst, const char* src) {
    memcpy(dst, src, 16);                             /* TN: literal size */
}

/* TN-05: strncpy with numeric literal */
void ucopy_tn05_strncpy_literal(char* dst, const char* src) {
    strncpy(dst, src, 63);                            /* TN: literal size */
}

/* TN-06: memmove with sizeof — safe */
void ucopy_tn06_memmove_sizeof(int* dst, const int* src) {
    memmove(dst, src, sizeof(int) * 4);               /* TN: sizeof expression */
}

/* TN-07: memcpy with sizeof(*ptr) */
void ucopy_tn07_memcpy_sizeof_deref(record_t* dst, const record_t* src) {
    memcpy(dst, src, sizeof(*dst));                   /* TN: sizeof deref */
}

/* TN-08: strncat with constant */
void ucopy_tn08_strncat_const(char* dst, const char* src) {
    strncat(dst, src, 32);                            /* TN: literal size */
}

/* TN-09: strncpy inside safe macro wrapper */
void ucopy_tn09_macro_wrapper(char* dst, const char* src) {
    SAFE_COPY(dst, src, 64);                          /* TN: macro with literal */
}

/* TN-10: memcpy with sizeof(variable) */
void ucopy_tn10_memcpy_sizeof_var(void) {
    int a, b = 42;
    memcpy(&a, &b, sizeof(a));                        /* TN: sizeof(a) */
}

/* TN-11: wmemcpy with sizeof */
void ucopy_tn11_wmemcpy_sizeof(wchar_t* dst, const wchar_t* src) {
    wmemcpy(dst, src, sizeof(wchar_t) * 10);          /* TN: sizeof expression */
}

/* TN-12: CopyMemory with literal */
void ucopy_tn12_copymemory_literal(void* dst, const void* src) {
    CopyMemory(dst, src, 128);                        /* TN: literal size */
}

/* TN-13: memcpy(dst, src, 0) — zero-length copy is safe (noop) */
void ucopy_tn13_memcpy_zero(char* dst, const char* src) {
    memcpy(dst, src, 0);                              /* TN: zero literal */
}

/* TN-14: strncpy with sizeof buf - 1 */
void ucopy_tn14_strncpy_sizeof_minus_1(const char* src) {
    char buf[128];
    strncpy(buf, src, sizeof(buf) - 1);               /* TN: sizeof expression */
    buf[sizeof(buf) - 1] = '\0';
}


/* ============================================================================
 *  FALSE POSITIVES — Safe code the scanner INCORRECTLY flags
 *  (These represent known weaknesses / things hard to fix)
 * ============================================================================*/

/* FP-01: strcpy after malloc(strlen+1) — perfectly sized buffer */
void ucopy_fp01_strcpy_strlen_malloc(const char* src) {
    char* dst = malloc(strlen(src) + 1);
    if (!dst) return;
    strcpy(dst, src);                                 /* FP: MEM-UNSAFE-COPY — buffer is exactly right size */
}

/* FP-02: strcpy of a short string literal */
void ucopy_fp02_strcpy_literal(void) {
    char buf[256];
    strcpy(buf, "hello");                             /* FP: MEM-UNSAFE-COPY — 5+1 bytes into 256 */
}

/* FP-03: sprintf with only %d — output is bounded (~11 chars max) */
void ucopy_fp03_sprintf_int_only(char* buf, int x) {
    sprintf(buf, "%d", x);                            /* FP: MEM-UNSAFE-COPY — bounded output */
}

/* FP-04: sprintf with width-limited %s — e.g., %.10s */
void ucopy_fp04_sprintf_width_limited(void) {
    char buf[32];
    const char* s = get_user_input();
    sprintf(buf, "%.10s", s);                         /* FP: MEM-UNSAFE-COPY — precision limits to 10 chars */
}

/* FP-05: strcpy from a constant known string */
void ucopy_fp05_strcpy_known_constant(void) {
    char buf[64];
    const char* greeting = "hi";
    strcpy(buf, greeting);                            /* FP: MEM-UNSAFE-COPY — source is constant "hi" */
}

/* TN-15: strcat with empty string — noop (was FP-06, now suppressed) */
void ucopy_fp06_strcat_empty(char* buf) {
    strcat(buf, "");                                  /* TN: strcat("") is a noop, now suppressed */
}

/* FP-07: strcpy within static_assert-like dead code (ifdef'd out) */
void ucopy_fp07_dead_strcpy(char* dst, const char* src) {
    #if 0
    strcpy(dst, src);                                 /* FP: MEM-UNSAFE-COPY — dead code, never executes */
    #endif
    /* Note: tree-sitter still parses #if 0 blocks */
}

/* FP-08: sprintf with %c — single char, always 1 byte output */
void ucopy_fp08_sprintf_char(char* buf, char c) {
    sprintf(buf, "%c", c);                            /* FP: MEM-UNSAFE-COPY — max 1 char + null */
}

/* TN-16: memcpy with pre-validated size (was FP-09, now suppressed) */
void ucopy_fp09_memcpy_prevalidated(char* dst, size_t dstsz,
                                     const char* src, size_t n) {
    if (n > dstsz) return;
    memcpy(dst, src, n);                              /* TN: n is validated above, now suppressed */
}

/* FP-10: strncpy with computed but safe size: min(n, sizeof) */
void ucopy_fp10_strncpy_min_size(const char* src, size_t n) {
    char buf[256];
    size_t safe_n = n < sizeof(buf) ? n : sizeof(buf);
    strncpy(buf, src, safe_n);                        /* FP: MEM-UNSAFE-COPY — safe_n <= sizeof(buf) */
}

/* TN-17: memcpy inside assert / error-checked block (was FP-11, now suppressed) */
void ucopy_fp11_memcpy_asserted(char* dst, const char* src, size_t n) {
    if (n > 1024) abort();
    memcpy(dst, src, n);                              /* TN: n is bounded by abort, now suppressed */
}

/* FP-12: memmove with parameter validated by caller contract (inter-proc) */
void ucopy_fp12_memmove_contracted(char* dst, const char* src, size_t n) {
    /* REQUIRES: n <= allocated_size(dst) */
    memmove(dst, src, n);                             /* FP: MEM-UNSAFE-COPY — caller contract */
}

/* FP-13: strcpy into a dynamically-allocated exact-fit buffer using strdup logic */
char* ucopy_fp13_strcpy_strdup_manual(const char* src) {
    size_t len = strlen(src);
    char* p = malloc(len + 1);
    if (!p) return NULL;
    strcpy(p, src);                                   /* FP: MEM-UNSAFE-COPY — buffer sized for src */
    return p;
}

/* FP-14: memcpy with size from sizeof array */
void ucopy_fp14_memcpy_sizeof_array(void) {
    int src[10] = {0};
    int dst[10];
    memcpy(dst, src, sizeof(src));                    /* TN actually — sizeof, but scanner might flag? */
}

/* FP-15: sprintf with only %p — pointer output is bounded */
void ucopy_fp15_sprintf_ptr(char* buf, void* p) {
    sprintf(buf, "%p", p);                            /* FP: MEM-UNSAFE-COPY — %p is bounded */
}

/* TN-19: memcpy where size is a compile-time enum constant (was FP-16, now suppressed) */
enum { BLOCK_SIZE = 512 };
void ucopy_fp16_memcpy_enum_size(char* dst, const char* src) {
    memcpy(dst, src, BLOCK_SIZE);                     /* TN: BLOCK_SIZE is ALL_CAPS constant, now suppressed */
}

/* TN-20: strncpy with validated variable (was FP-17, now suppressed) */
void ucopy_fp17_strncpy_validated(char* dst, const char* src, size_t n) {
    if (n == 0 || n > 64) return;
    strncpy(dst, src, n);                             /* TN: n validated by guard, now suppressed */
}

/* FP-18: memcpy inside macro that expands sizeof */
void ucopy_fp18_memcpy_in_sizeof_macro(record_t* dst, const record_t* src) {
    memcpy(dst, src, sizeof *src);                    /* TN: sizeof expression */
}


/* ============================================================================
 *  FALSE NEGATIVES — Vulnerable code the scanner MISSES
 *  (These represent known limitations)
 * ============================================================================*/

/* TP-34: stpcpy — POSIX variant, now detected (was FN-01) */
void ucopy_fn01_stpcpy(char* dst, const char* src) {
    stpcpy(dst, src);                                 /* TP: MEM-UNSAFE-COPY — stpcpy is unsafe like strcpy */
}

/* TP-35: bcopy — BSD legacy, reversed arg order, now detected (was FN-02) */
void ucopy_fn02_bcopy(const char* src, char* dst, size_t n) {
    bcopy(src, dst, n);                               /* TP: MEM-UNSAFE-COPY — bcopy with variable size */
}

/* FN-03: strcpy via function pointer */
void ucopy_fn03_funcptr_strcpy(char* dst, const char* src) {
    char* (*copier)(char*, const char*) = strcpy;
    copier(dst, src);                                 /* FN: indirect call via function pointer */
}

/* FN-04: strcpy hidden inside macro expansion */
void ucopy_fn04_macro_strcpy(char* dst, const char* src) {
    MY_STRCPY(dst, src);                              /* FN: macro hides strcpy — scanner may see expanded */
}

/* FN-05: swprintf — wide sprintf, not in unsafe list */
void ucopy_fn05_swprintf(wchar_t* dst, const wchar_t* name) {
    swprintf(dst, 256, L"Name: %s", name);            /* FN: swprintf without proper size check */
}

/* FN-06: snprintf into too-small buffer (size arg is wrong) */
void ucopy_fn06_snprintf_wrong_size(const char* src) {
    char buf[8];
    snprintf(buf, 256, "%s", src);                    /* FN: size arg 256 >> sizeof(buf)=8, truncation won't help */
}

/* FN-07: strncpy with sizeof(pointer) instead of sizeof(buffer) */
void ucopy_fn07_strncpy_sizeof_ptr(const char* src) {
    char* dst = malloc(256);
    strncpy(dst, src, sizeof(dst));                   /* FN: sizeof(dst)=8 on 64-bit, not 256 */
}

/* TP-36: memcpy with strlen(src) — no +1 for null terminator (was FN-08) */
void ucopy_fn08_memcpy_strlen_no_null(char* dst, const char* src) {
    memcpy(dst, src, strlen(src));                    /* TP: MEM-UNSAFE-COPY — strlen is variable, no +1 for null */
}

/* TP-37: _mbscpy — multibyte string copy, now detected (was FN-09) */
void ucopy_fn09_mbscpy(unsigned char* dst, const unsigned char* src) {
    _mbscpy(dst, src);                                /* TP: MEM-UNSAFE-COPY — _mbscpy is unsafe like strcpy */
}

/* TP-38: _mbscat — multibyte string concat, now detected (was FN-10) */
void ucopy_fn10_mbscat(unsigned char* dst, const unsigned char* src) {
    _mbscat(dst, src);                                /* TP: MEM-UNSAFE-COPY — _mbscat is unsafe like strcat */
}

/* FN-11: strcpy via inline wrapper function (inter-procedural) */
static inline void my_copy(char* d, const char* s) {
    strcpy(d, s);  /* This is flagged, but the CALLER is where the real vuln is */
}
void ucopy_fn11_wrapper_call(const char* input) {
    char buf[32];
    my_copy(buf, input);                              /* FN: wrapper hides the unsafe copy from the call site */
}

/* FN-12: sprintf result used for return — still overflows */
int ucopy_fn12_sprintf_retval(char* buf, const char* s) {
    return sprintf(buf, "%s:%s", s, s);               /* scanner catches sprintf — actually TP, not FN */
}

/* TP-39: strncpy where size = strlen(src) + 1 — could exceed dst[16] (was FN-13) */
void ucopy_fn13_strncpy_strlen_plus1(char dst[16], const char* src) {
    strncpy(dst, src, strlen(src) + 1);               /* TP: MEM-UNSAFE-COPY — strlen(src)+1 is variable, could exceed dst */
}

/* TP-40: memcpy with size from untrusted field in struct (was FN-14) */
typedef struct { size_t len; char data[]; } msg_t;
void ucopy_fn14_memcpy_struct_field(char* dst, msg_t* msg) {
    memcpy(dst, msg->data, msg->len);                 /* TP: MEM-UNSAFE-COPY — msg->len is untrusted variable */
}

/* FN-15: sprintf into stack buffer with %lu — bounded but barely fits? */
void ucopy_fn15_sprintf_format_lu(void) {
    char tiny[4];
    sprintf(tiny, "%lu", (unsigned long)99999999UL);  /* scanner catches sprintf — actually TP */
}

/* FN-16: reallocated buffer + strcpy — size mismatch possible */
void ucopy_fn16_realloc_strcpy(char* buf, const char* src) {
    buf = realloc(buf, 32);
    strcpy(buf, src);                                 /* scanner catches strcpy — actually TP */
}

/* FN-17: wcsncpy with wrong size */
void ucopy_fn17_wcsncpy_wrong(wchar_t dst[8], const wchar_t* src) {
    wcsncpy(dst, src, 256);                           /* FN: wcsncpy not in bounded list, 256 >> 8 */
}

/* FN-18: std::copy with raw pointers in C++ style (but .c file) */
/* Skipped — only relevant in .cpp context */

/* TP-41: memcpy where size is from a cast of user input (was FN-19) */
void ucopy_fn19_memcpy_cast_size(char* dst, const char* src, const char* sz_str) {
    size_t n = (size_t)atoi(sz_str);
    memcpy(dst, src, n);                              /* TP: MEM-UNSAFE-COPY — n from atoi is untrusted variable */
}

/* FN-20: strncpy with size from sizeof but wrong buffer */
void ucopy_fn20_strncpy_wrong_sizeof(const char* src) {
    char small[8];
    char big[512];
    strncpy(small, src, sizeof(big));                 /* FN: sizeof(big) is 512, small is only 8 — sizeof makes it look safe */
}

/* FN-21: memcpy with sizeof expression that's actually wrong type */
void ucopy_fn21_memcpy_sizeof_wrong_type(void) {
    short dst[4];
    int src[4] = {1,2,3,4};
    memcpy(dst, src, sizeof(src));                    /* FN: sizeof(src)=16, sizeof(dst)=8, overflow — sizeof makes it look safe */
}

/* FN-22: strcpy through array of function pointers */
typedef char* (*str_op)(char*, const char*);
void ucopy_fn22_funcptr_array(char* dst, const char* src) {
    str_op ops[] = { strcpy, strcat };
    ops[0](dst, src);                                 /* FN: indirect call through array */
}

/* FN-23: sprintf to global buffer — size unknown */
char g_buf[32];
void ucopy_fn23_sprintf_global(const char* s) {
    sprintf(g_buf, "%s", s);                          /* scanner catches sprintf — actually TP */
}

/* TP-42: strlcpy — BSD, now tracked as bounded copy (was FN-24) */
void ucopy_fn24_strlcpy(char* dst, const char* src, size_t sz) {
    strlcpy(dst, src, sz);                            /* TP: MEM-UNSAFE-COPY — strlcpy with variable size */
}

/* TP-43: strlcat — BSD, now tracked as bounded copy (was FN-25) */
void ucopy_fn25_strlcat(char* dst, const char* src, size_t sz) {
    strlcat(dst, src, sz);                            /* TP: MEM-UNSAFE-COPY — strlcat with variable size */
}


/* ============================================================================
 *  MIXED / TRICKY PATTERNS — Combinations that test edge cases
 * ============================================================================*/

/* MIX-01: Multiple unsafe ops in one function */
void ucopy_mix01_multi_unsafe(char* dst, const char* a, const char* b) {
    strcpy(dst, a);                                   /* TP: MEM-UNSAFE-COPY */
    strcat(dst, ":");                                 /* FP: MEM-UNSAFE-COPY — known literal, fits if dst big enough */
    strcat(dst, b);                                   /* TP: MEM-UNSAFE-COPY */
}

/* MIX-02: Safe memcpy followed by unsafe strcpy */
void ucopy_mix02_safe_then_unsafe(record_t* dst, const record_t* src, const char* tag) {
    memcpy(dst, src, sizeof(*dst));                   /* TN: sizeof */
    strcpy(dst->name, tag);                           /* TP: MEM-UNSAFE-COPY — tag could overflow name[64] */
}

/* MIX-03: strncpy then manual null-term — safe pattern */
void ucopy_mix03_strncpy_nullterm(const char* src) {
    char buf[64];
    strncpy(buf, src, sizeof(buf) - 1);               /* TN: sizeof expression */
    buf[sizeof(buf) - 1] = '\0';
}

/* MIX-04: Nested function calls — sprintf inside strlen (weird but valid) */
void ucopy_mix04_nested_sprintf(char* out, const char* in) {
    sprintf(out, "%zu", strlen(in));                  /* TP: MEM-UNSAFE-COPY — sprintf, even though output is bounded */
}

/* MIX-05: Conditional safe/unsafe paths */
void ucopy_mix05_conditional_paths(char* dst, const char* src, int safe_mode) {
    if (safe_mode) {
        strncpy(dst, src, 64);                        /* TN/FP: literal size */
    } else {
        strcpy(dst, src);                             /* TP: MEM-UNSAFE-COPY */
    }
}

/* MIX-06: strcpy in ternary expression */
void ucopy_mix06_ternary_strcpy(char* a, char* b, const char* src, int flag) {
    flag ? strcpy(a, src) : strcpy(b, src);           /* TP: MEM-UNSAFE-COPY x2 */
}

/* MIX-07: memcpy with sizeof in one arg and variable in another call */
void ucopy_mix07_mixed_memcpy(char* dst, const char* src, size_t n) {
    memcpy(dst, src, sizeof(int));                    /* TN: sizeof */
    memcpy(dst + sizeof(int), src, n);                /* TP: MEM-UNSAFE-COPY (variable size) */
}

/* MIX-08: Chain of copies building a path */
void ucopy_mix08_path_build(const char* dir, const char* file) {
    char path[256];
    strcpy(path, dir);                                /* TP: MEM-UNSAFE-COPY */
    strcat(path, "/");                                /* FP: MEM-UNSAFE-COPY — literal "/" */
    strcat(path, file);                               /* TP: MEM-UNSAFE-COPY */
}

/* MIX-09: strcpy guarded by strlen check — technically safe but scanner can't see it */
void ucopy_mix09_strlen_guarded(char* dst, const char* src) {
    if (strlen(src) < 64) {
        strcpy(dst, src);                             /* FP: MEM-UNSAFE-COPY — strlen-guarded */
    }
}

/* MIX-10: memcpy with ternary size — clamped (was FP, now TN) */
void ucopy_mix10_ternary_size(char* dst, const char* src, size_t n) {
    memcpy(dst, src, n < 64 ? n : 64);               /* TN: ternary clamps to 64, now suppressed */
}

/* MIX-11: sprintf with %.*s (precision from variable) — bounded by precision */
void ucopy_mix11_sprintf_precision(char* buf, int maxlen, const char* s) {
    sprintf(buf, "%.*s", maxlen, s);                  /* TP: MEM-UNSAFE-COPY — sprintf, though precision limits it */
}

/* MIX-12: Back-to-back strncpy + strncat both with sizeof */
void ucopy_mix12_bounded_chain(const char* a, const char* b) {
    char buf[128];
    strncpy(buf, a, sizeof(buf) - 1);                 /* TN: sizeof */
    buf[sizeof(buf) - 1] = '\0';
    strncat(buf, b, sizeof(buf) - strlen(buf) - 1);   /* TN: sizeof in expression */
}

/* MIX-13: memcpy in a loop with constant size per iteration */
void ucopy_mix13_loop_memcpy(char* dst, const char** blocks, int n) {
    for (int i = 0; i < n; i++) {
        memcpy(dst + i * 64, blocks[i], 64);          /* TN: literal size */
    }
}

/* MIX-14: strcpy with source from strdup (known safe but scanner can't tell) */
void ucopy_mix14_strdup_source(void) {
    char buf[256];
    char* src = strdup("short string");
    if (src) {
        strcpy(buf, src);                             /* FP: MEM-UNSAFE-COPY — src is a known short string */
        free(src);
    }
}


/* ============================================================================
 *  Expected results summary  (after scanner fixes)
 *
 *  Category    Count  Description
 *  --------    -----  -----------
 *  TP           54    Unsafe copy/concat/sprintf/gets/memcpy calls correctly flagged
 *                     (44 original + 10 former FN now caught)
 *                     - 38 at HIGH/HIGH, 12 at MEDIUM/MEDIUM, 4 at LOW/LOW
 *  TN           30    Safe bounded operations correctly NOT flagged
 *                     (24 original + 6 former FP now suppressed)
 *  FP           15    Safe code still flagged (known scanner limitation)
 *                     - 3 at HIGH/HIGH, 3 at MEDIUM/MEDIUM, 9 at LOW/LOW
 *  FN           10    Unsafe code still missed (known scanner limitation)
 *
 *  Remaining FP (still flagged):
 *   - FP-01 (LOW):  strcpy after malloc(strlen+1) — detected, severity lowered
 *   - FP-02 (LOW):  strcpy of literal "hello" — detected, severity lowered
 *   - FP-03 (LOW):  sprintf with %d only — detected, severity lowered
 *   - FP-04 (LOW):  sprintf with %.10s — detected, severity lowered
 *   - FP-05 (HIGH): strcpy from const variable (needs dataflow to resolve)
 *   - FP-07 (HIGH): #if 0 dead code (tree-sitter parses it regardless)
 *   - FP-08 (LOW):  sprintf with %c — detected, severity lowered
 *   - FP-10 (MED):  strncpy with computed min(n, sizeof) — needs ternary assignment tracking
 *   - FP-12 (MED):  memmove with caller contract — inter-procedural, cannot fix
 *   - FP-13 (LOW):  strcpy into exact-fit malloc — detected, severity lowered
 *   - FP-15 (LOW):  sprintf with %p — detected, severity lowered
 *   - MIX strcat(dst, ":") and strcat(dst, "/") — literal source, severity lowered
 *   - MIX-09 (LOW): strlen-guarded strcpy — detected, severity lowered
 *   - MIX-14 (HIGH): strcpy from strdup source — needs strdup tracking
 *
 *  Remaining FN (still missed):
 *   - FN-03: strcpy via function pointer (indirect call)
 *   - FN-04: strcpy hidden in macro (depends on preprocessing)
 *   - FN-05: swprintf not in tracked function list
 *   - FN-06: snprintf with wrong size arg (needs buffer-size tracking)
 *   - FN-07: strncpy with sizeof(pointer) — sizeof suppresses the finding
 *   - FN-11: Wrapper function hides unsafe call site (inter-procedural)
 *   - FN-17: wcsncpy with wrong size (not enough context)
 *   - FN-20: strncpy with sizeof(wrong_buffer) — sizeof suppresses
 *   - FN-21: memcpy with sizeof(wrong_type) — sizeof suppresses
 *   - FN-22: strcpy through function pointer array
 *
 *  Scanner improvements made:
 *   1. Added stpcpy, _mbscpy, _mbscat to UNSAFE_COPY_FUNCS
 *   2. Added wcsncpy, wcsncat, strlcpy, strlcat, bcopy to BOUNDED_COPY_FUNCS
 *   3. FP reduction: string literal source → LOW severity (strcpy/strcat "literal")
 *   4. FP reduction: strcat("") → suppressed entirely
 *   5. FP reduction: sprintf with bounded-only format (%d/%c/%p) → LOW severity
 *   6. FP reduction: strcpy dst = malloc(strlen(src)+1) → LOW severity
 *   7. FP reduction: strlen-guarded strcpy/strcat → LOW severity
 *   8. FP reduction: size variable with if-guard/abort before call → suppressed
 *   9. FP reduction: ALL_CAPS identifier as size → treated as constant
 *  10. FP reduction: ternary-clamped size (n < 64 ? n : 64) → suppressed
 * ============================================================================*/
