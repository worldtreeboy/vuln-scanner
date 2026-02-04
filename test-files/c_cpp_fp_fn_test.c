/**
 * c_cpp_fp_fn_test.c — Comprehensive TP / TN / FP / FN test suite
 *
 * Tests all 16 scanner rules for:
 *   TP  = True Positive   — vulnerable code, scanner SHOULD flag it     (good)
 *   TN  = True Negative   — safe code, scanner should NOT flag it       (good)
 *   FP  = False Positive  — safe code, scanner INCORRECTLY flags        (known weakness)
 *   FN  = False Negative  — vulnerable code, scanner MISSES             (known limitation)
 *
 * Every test function is named:  <rule_short>_<tp|tn|fp|fn><N>
 * Every flaggable line is annotated with the expected outcome.
 *
 * Run:
 *   python3 c_cpp_treesitter_scanner.py test-files/c_cpp_fp_fn_test.c --all
 *   python3 c_cpp_treesitter_scanner.py test-files/c_cpp_fp_fn_test.c --all --jsonl 2>/dev/null
 *
 * Expected totals are listed at the bottom of this file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <sys/types.h>

/* Stubs — declarations so the file parses, never linked */
extern int       fileExists(const char*);
extern void      die(const char*);
extern void*     safedup(const void*, size_t);
extern uint16_t  readU16BE(const char*);
extern uint32_t  readU32BE(const char*);
extern void      process(const char*);
extern void      log_msg(const char*);
extern int       compute_index(void);
extern long      get_big_val(void);
extern void      takes_short(short);
extern size_t    safe_subtract(size_t, size_t);
extern const char* get_format(int);

typedef struct { int x; int y; } point_t;
typedef struct { char* name; int port; } myconfig_t;
typedef struct { int* data; } wrapper_t;
typedef unsigned long my_size;


/* ============================================================================
 *  RULE 1 — MEM-UNSAFE-COPY
 * ============================================================================*/

/* TP-1a: strcpy — unconditionally unsafe */
void ucopy_tp1(char* dst, char* src) {
    strcpy(dst, src);                           /* TP: MEM-UNSAFE-COPY */
}

/* TP-1b: strcat — unconditionally unsafe */
void ucopy_tp2(char* dst, char* src) {
    strcat(dst, src);                           /* TP: MEM-UNSAFE-COPY */
}

/* TP-1c: sprintf — unconditionally unsafe */
void ucopy_tp3(char* dst, const char* name) {
    sprintf(dst, "hello %s", name);             /* TP: MEM-UNSAFE-COPY */
}

/* TP-1d: gets — unconditionally unsafe */
void ucopy_tp4(char* buf) {
    gets(buf);                                  /* TP: MEM-UNSAFE-COPY */
}

/* TP-1e: vsprintf — unconditionally unsafe */
void ucopy_tp5(char* dst, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsprintf(dst, fmt, ap);                     /* TP: MEM-UNSAFE-COPY + DANGER-FORMAT (fmt is non-literal) */
    va_end(ap);
}

/* TP-1f: memcpy with variable size (not sizeof, not constant) */
void ucopy_tp6(char* dst, char* src, size_t n) {
    memcpy(dst, src, n);                        /* TP: MEM-UNSAFE-COPY (MEDIUM — variable size) */
}

/* TP-1g: strncpy with variable size */
void ucopy_tp7(char* dst, char* src, int len) {
    strncpy(dst, src, len);                     /* TP: MEM-UNSAFE-COPY (MEDIUM — variable size) */
}

/* TN-1a: strncpy with sizeof — safe */
void ucopy_tn1(char* src) {
    char dst[64];
    strncpy(dst, src, sizeof(dst));             /* TN: sizeof makes it safe */
}

/* TN-1b: memcpy with sizeof — safe */
void ucopy_tn2(void) {
    int a, b;
    memcpy(&a, &b, sizeof(int));                /* TN: sizeof */
}

/* TN-1c: memcpy with constant — safe */
void ucopy_tn3(char* dst, char* src) {
    memcpy(dst, src, 16);                       /* TN: constant */
}

/* TN-1d: snprintf with sizeof — safe */
void ucopy_tn4(const char* name) {
    char buf[128];
    snprintf(buf, sizeof(buf), "hi %s", name);  /* TN: not in UNSAFE list, sizeof size */
}

/* TN-1e: printf is NOT a copy function */
void ucopy_tn5(const char* msg) {
    printf("%s\n", msg);                        /* TN: not a copy function */
}

/* FP-1a: memcpy after bounds-check — scanner can't see the validation */
void ucopy_fp1(char* dst, char* src, size_t n) {
    if (n > 1024) return;                       /* bounds check */
    memcpy(dst, src, n);                        /* FP: MEM-UNSAFE-COPY — n is bounded but scanner can't tell */
}

/* FN-1a: custom unsafe wrapper — scanner doesn't track custom function names */
static void my_strcpy(char* d, const char* s) { while ((*d++ = *s++)); }
void ucopy_fn1(char* dst, char* src) {
    my_strcpy(dst, src);                        /* FN: custom wrapper not tracked */
}


/* ============================================================================
 *  RULE 2 — MEM-BUFFER-OOB
 * ============================================================================*/

/* TP-2a: array write with variable index */
void oob_tp1(int* arr, int idx) {
    arr[idx] = 42;                              /* TP: MEM-BUFFER-OOB */
}

/* TP-2b: array write with expression index */
void oob_tp2(int* arr, int a, int b) {
    arr[a + b] = 99;                            /* TP: MEM-BUFFER-OOB */
}

/* TP-2c: array write with function call index */
void oob_tp3(int* arr) {
    arr[compute_index()] = 1;                   /* TP: MEM-BUFFER-OOB */
}

/* TN-2a: array write with small constant indices */
void oob_tn1(int* arr) {
    arr[0] = 1;                                 /* TN: constant 0 */
    arr[5] = 2;                                 /* TN: constant 5 */
    arr[4095] = 3;                              /* TN: constant < 4096 */
}

/* TN-2b: array READ with variable index — reads aren't flagged */
int oob_tn2(int* arr, int idx) {
    return arr[idx];                            /* TN: read, not write */
}

/* TN-2c: pointer increment (not subscript write) */
void oob_tn3(char* p) {
    *p = 'a';                                   /* TN: not subscript */
    p++;
}

/* FP-2a: bounded loop write — scanner can't track loop bounds */
void oob_fp1(int arr[100]) {
    for (int i = 0; i < 100; i++) {
        arr[i] = i;                             /* FP: MEM-BUFFER-OOB — i is bounded by loop */
    }
}

/* FP-2b: index validated before write — scanner can't see the guard */
void oob_fp2(int* arr, int idx, int len) {
    if (idx >= 0 && idx < len) {
        arr[idx] = 0;                           /* FP: MEM-BUFFER-OOB — idx is validated */
    }
}

/* FN-2a: write through pointer arithmetic (not subscript syntax) */
void oob_fn1(int* arr, int idx) {
    *(arr + idx) = 42;                          /* FN for OOB, but TP for PTR-ARITH instead */
}


/* ============================================================================
 *  RULE 3 — MEM-USE-AFTER-FREE
 *
 *  Note: all test functions use if(!p) return after malloc to avoid
 *  unrelated MEM-NULL-DEREF findings.
 * ============================================================================*/

/* TP-3a: classic UAF — free then read */
void uaf_tp1(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    printf("%s\n", p);                          /* TP: MEM-USE-AFTER-FREE */
}

/* TP-3b: free then write */
void uaf_tp2(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return;
    *p = 10;
    free(p);
    *p = 20;                                    /* TP: MEM-USE-AFTER-FREE */
}

/* TN-3a: free at end of function — no use after */
void uaf_tn1(void) {
    char* buf = malloc(256);
    if (!buf) return;
    memset(buf, 0, 256);
    printf("%p\n", (void*)buf);
    free(buf);
    /* nothing after free */                    /* TN: nothing after free */
}

/* TN-3b: free different variables — only b used after a is freed.
   Note: free(a) in error branch + free(a) after creates collateral MEM-DOUBLE-FREE FP. */
void uaf_tn2(void) {
    char* a = malloc(10);
    if (!a) return;
    char* b = malloc(10);
    if (!b) { free(a); return; }
    free(a);                                    /* Collateral FP: MEM-DOUBLE-FREE (exclusive branch) */
    printf("%s\n", b);                          /* TN for UAF: b is alive, only a freed */
    free(b);
}

/* FP-3a: free then reassign then use — scanner doesn't check intervening reassignment.
   Scanner also flags the if(!p) null-check as a "use" of p after free. */
void uaf_fp1(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p = malloc(128);                            /* reassignment */
    if (!p) return;                             /* FP: MEM-USE-AFTER-FREE — scanner sees if(!p) as "use" */
    printf("%s\n", p);                          /* FP: MEM-USE-AFTER-FREE — scanner misses reassignment */
    free(p);
}

/* FP-3b: free in if branch, use in else — exclusive branches.
   Also creates collateral MEM-DOUBLE-FREE FP (free in both branches). */
void uaf_fp2(int cond) {
    char* p = malloc(64);
    if (!p) return;
    if (cond) {
        free(p);
    } else {
        printf("%s\n", p);                      /* FP: MEM-USE-AFTER-FREE — branches exclusive */
        free(p);                                /* Collateral FP: MEM-DOUBLE-FREE (exclusive branches) */
    }
}

/* FP-3c: free in guarded early-return, use after — scanner sees them in same compound.
   Also creates collateral MEM-DOUBLE-FREE FP. */
void uaf_fp3(int err) {
    char* p = malloc(64);
    if (!p) return;
    if (err) {
        free(p);
        return;                                 /* early return! */
    }
    printf("%s\n", p);                          /* FP: MEM-USE-AFTER-FREE — free is in a returning branch */
    free(p);                                    /* Collateral FP: MEM-DOUBLE-FREE (return-guarded branch) */
}

/* FN-3a: UAF through alias — scanner tracks 'p', not 'q' */
void uaf_fn1(void) {
    char* p = malloc(64);
    if (!p) return;
    char* q = p;
    free(p);
    printf("%s\n", q);                          /* FN: UAF via alias q */
}

/* FN-3b: UAF across function boundary */
static char* global_ptr;
void uaf_fn2_free(void) { free(global_ptr); }
void uaf_fn2_use(void) {
    printf("%s\n", global_ptr);                 /* FN: freed in another function */
}


/* ============================================================================
 *  RULE 4 — MEM-DOUBLE-FREE
 * ============================================================================*/

/* TP-4a: classic double free */
void df_tp1(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    free(p);                                    /* TP: MEM-DOUBLE-FREE */
}

/* TP-4b: double free with code in between */
void df_tp2(void) {
    int* nums = (int*)malloc(100 * sizeof(int));
    if (!nums) return;
    free(nums);
    printf("freed once\n");
    free(nums);                                 /* TP: MEM-DOUBLE-FREE */
}

/* TN-4a: free, reassign, free — safe.
   Collateral FP: MEM-USE-AFTER-FREE because scanner treats if(!p) as "use" of p after the original free,
   even though p was reassigned to a new malloc between them. */
void df_tn1(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p = malloc(128);
    if (!p) return;                             /* Collateral FP: MEM-USE-AFTER-FREE (null check != use) */
    free(p);                                    /* TN for double-free: p reassigned between frees */
}

/* TN-4b: different variables */
void df_tn2(void) {
    char* a = malloc(10);
    char* b = malloc(10);
    if (a) free(a);
    if (b) free(b);                             /* TN: different variables */
}

/* TN-4c: single free only */
void df_tn3(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    /* only freed once */                       /* TN: single free */
}

/* FP-4a: free in two exclusive if branches with return guard */
void df_fp1(int err) {
    char* p = malloc(64);
    if (!p) return;
    if (err) {
        free(p);
        return;
    }
    /* ... work ... */
    free(p);                                    /* FP: MEM-DOUBLE-FREE — branches exclusive (return guard) */
}

/* FN-4a: double free through alias — scanner doesn't track p == q */
void df_fn1(void) {
    char* p = malloc(64);
    if (!p) return;
    char* q = p;
    free(p);
    free(q);                                    /* FN: scanner doesn't track q == p */
}


/* ============================================================================
 *  RULE 5 — MEM-RETURN-LOCAL
 * ============================================================================*/

/* TP-5a: return address of stack array */
int* rlocal_tp1(void) {
    int arr[16];
    memset(arr, 0, sizeof(arr));
    return &arr[0];                             /* TP: MEM-RETURN-LOCAL */
}

/* TP-5b: return address of stack variable */
int* rlocal_tp2(void) {
    int x = 42;
    return &x;                                  /* TP: MEM-RETURN-LOCAL */
}

/* TN-5a: return heap pointer (no &) */
int* rlocal_tn1(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return NULL;
    *p = 42;
    return p;                                   /* TN: heap allocation */
}

/* TN-5b: return parameter pointer */
int* rlocal_tn2(int* input) {
    return input;                               /* TN: not a local */
}

/* FP-5a: return &static — scanner treats static as local */
int* rlocal_fp1(void) {
    static int x = 10;
    return &x;                                  /* FP: MEM-RETURN-LOCAL — x is static, address is valid */
}

/* FN-5a: return local array via implicit decay (no & operator) */
void* rlocal_fn1(void) {
    char buf[64];
    return (void*)buf;                          /* FN: no &, implicit array-to-pointer decay */
}


/* ============================================================================
 *  RULE 6 — MEM-DANGLING-PTR
 * ============================================================================*/

/* TP-6a: classic — ptr = &local via init; return ptr */
point_t* dangle_tp1(void) {
    point_t pt;
    point_t* p = &pt;
    p->x = 1;
    p->y = 2;
    return p;                                   /* TP: MEM-DANGLING-PTR */
}

/* TP-6b: assignment form — ptr = &local (not init) */
myconfig_t* dangle_tp2(void) {
    myconfig_t cfg;
    myconfig_t* result;
    result = &cfg;
    result->name = "test";
    result->port = 80;
    return result;                              /* TP: MEM-DANGLING-PTR */
}

/* TN-6a: ptr = malloc — heap, safe */
point_t* dangle_tn1(void) {
    point_t* p = (point_t*)malloc(sizeof(point_t));
    if (!p) return NULL;
    p->x = 1;
    return p;                                   /* TN: heap */
}

/* TN-6b: ptr = &local then reassigned to heap before return */
point_t* dangle_tn2(void) {
    point_t local;
    point_t* p = &local;
    p->x = 99;                                 /* temporary use */
    p = (point_t*)malloc(sizeof(point_t));      /* reassigned to heap */
    if (!p) return NULL;
    p->x = 1;
    return p;                                   /* TN: p reassigned before return */
}

/* TN-6c: ptr to local but never returned */
void dangle_tn3(void) {
    int val = 10;
    int* p = &val;
    printf("%d\n", *p);
    /* p is never returned */                   /* TN: not returned */
}

/* FN-6a: double indirection — scanner doesn't track **pp.
   Note: scanner flags this as MEM-RETURN-LOCAL FP (ptr is static, &ptr is valid).
   The real bug (ptr pointing to local) is missed. */
int** dangle_fn1(void) {
    int local = 5;
    static int* ptr;
    ptr = &local;                               /* ptr holds dangling after return */
    return &ptr;                                /* FP: MEM-RETURN-LOCAL (ptr is static)
                                                   FN: actual dangling through double indirection missed */
}

/* FN-6b: returned in struct field — scanner doesn't track struct members */
wrapper_t dangle_fn2(void) {
    int local_arr[10];
    wrapper_t w;
    w.data = local_arr;                         /* dangling array decay */
    return w;                                   /* FN: scanner doesn't track struct fields */
}


/* ============================================================================
 *  RULE 7 — MEM-NULL-DEREF
 * ============================================================================*/

/* TP-7a: malloc without NULL check, immediate deref */
void nderef_tp1(void) {
    char* buf = malloc(1024);
    buf[0] = 'A';                               /* TP: MEM-NULL-DEREF */
}

/* TP-7b: (char*)malloc cast, deref without check */
void nderef_tp2(size_t n) {
    char* data = (char*)malloc(n);
    memset(data, 0, n);                         /* TP: MEM-NULL-DEREF (passed to function) */
}

/* TP-7c: calloc without NULL check, field access */
void nderef_tp3(void) {
    point_t* pt = (point_t*)calloc(1, sizeof(point_t));
    pt->x = 10;                                /* TP: MEM-NULL-DEREF */
}

/* TP-7d: malloc + alias — alias used without check */
void nderef_tp4(void) {
    char* raw = (char*)malloc(256);
    char* cursor = raw;                         /* alias */
    read(0, cursor, 256);                       /* TP: MEM-NULL-DEREF (alias 'cursor') */
}

/* TP-7e: realloc without NULL check */
void nderef_tp5(char* old, size_t newsz) {
    char* p = (char*)realloc(old, newsz);
    p[0] = 'X';                                /* TP: MEM-NULL-DEREF */
}

/* TN-7a: malloc + if(!p) return + use */
void nderef_tn1(void) {
    char* buf = malloc(1024);
    if (!buf) return;
    buf[0] = 'A';                               /* TN: NULL checked */
}

/* TN-7b: malloc + (p == NULL) comparison form */
void nderef_tn2(void) {
    int* p = (int*)malloc(sizeof(int));
    if (p == NULL) return;
    *p = 42;                                    /* TN: NULL checked */
    free(p);
}

/* TN-7c: no malloc at all — normal variable */
void nderef_tn3(void) {
    int x = 5;
    int* p = &x;
    *p = 10;                                    /* TN: p points to stack, no alloc */
}

/* TN-7d: realloc with NULL check */
void nderef_tn4(char* old, size_t newsz) {
    char* tmp = (char*)realloc(old, newsz);
    if (tmp == NULL) return;
    tmp[0] = 'X';                               /* TN: checked */
}

/* TN-7e: malloc + if(p) guard */
void nderef_tn5(void) {
    char* buf = malloc(1024);
    if (buf) {
        buf[0] = 'Z';                           /* TN: guarded by if(buf) */
    }
    free(buf);
}

/* FN-7a: malloc result stored in struct field — scanner doesn't track struct members */
void nderef_fn1(void) {
    wrapper_t w;
    w.data = (int*)malloc(sizeof(int) * 10);
    w.data[0] = 1;                              /* FN: scanner doesn't track w.data */
}

/* FN-7b: malloc result returned directly — caller may deref without check */
char* nderef_fn2(size_t n) {
    return malloc(n);                           /* FN: cross-function, no deref in this function */
}

/* FP-7a: NULL check via ternary — scanner finds buf[0] as deref but doesn't
   recognize the ternary guard as a NULL check */
void nderef_fp1_ternary(void) {
    char* buf = malloc(64);
    char c = buf ? buf[0] : 0;                 /* FP: MEM-NULL-DEREF — ternary guards it but scanner can't tell */
    (void)c;
}


/* ============================================================================
 *  RULE 8 — MEM-UNVALIDATED-SIZE
 * ============================================================================*/

/* TP-8a: ntohl -> memcpy with unvalidated size */
void usize_tp1(char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 4, len);                  /* TP: MEM-UNVALIDATED-SIZE */
}

/* TP-8b: readU16BE -> safedup */
void usize_tp2(char* raw) {
    uint16_t name_len = readU16BE(raw);
    char* name = (char*)safedup(raw + 2, name_len + 1);  /* TP: MEM-UNVALIDATED-SIZE */
    (void)name;
}

/* TP-8c: ntohs -> memmove */
void usize_tp3(char* pkt, char* out) {
    uint16_t payload_len = ntohs(*(uint16_t*)pkt);
    memmove(out, pkt + 2, payload_len);         /* TP: MEM-UNVALIDATED-SIZE */
}

/* TN-8a: ntohl -> bounds check -> memcpy.
   TN for UNVALIDATED-SIZE (bounds checked), but still FP for MEM-UNSAFE-COPY (variable size). */
void usize_tn1(char* buf, char* dst, size_t dst_sz) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    if (len > dst_sz) return;                   /* bounds check */
    memcpy(dst, buf + 4, len);                  /* TN: UNVALIDATED-SIZE checked. FP: MEM-UNSAFE-COPY (var size) */
}

/* TN-8b: memcpy with constant size (no byte conversion) */
void usize_tn2(char* dst, char* src) {
    memcpy(dst, src, 32);                       /* TN: constant size */
}

/* TN-8c: ntohl result used for non-size purpose */
void usize_tn3(char* buf) {
    uint32_t version = ntohl(*(uint32_t*)buf);
    printf("version: %u\n", version);           /* TN: not used as size in memcpy */
}

/* FN-8a: indirect — ntohl to intermediate variable, then to memcpy */
void usize_fn1(char* buf, char* dst) {
    uint32_t raw_len = ntohl(*(uint32_t*)buf);
    size_t actual_len = raw_len;                /* intermediate variable */
    memcpy(dst, buf + 4, actual_len);           /* FN: scanner tracks raw_len, not actual_len */
}

/* TP-8d: size expression containing conversion variable — scanner substring-matches */
void usize_tp4(char* buf, char* dst) {
    uint32_t total = ntohl(*(uint32_t*)buf);
    uint32_t header = 12;
    memcpy(dst, buf + header, total - header);  /* TP: MEM-UNVALIDATED-SIZE — "total" appears in size arg */
}


/* ============================================================================
 *  RULE 9 — PTR-ARITH
 * ============================================================================*/

/* TP-9a: *(base + offset) */
char parith_tp1(char* base, int offset) {
    return *(base + offset);                    /* TP: PTR-ARITH */
}

/* TP-9b: *(ptr - n) */
char parith_tp2(char* end, int n) {
    return *(end - n);                          /* TP: PTR-ARITH */
}

/* TN-9a: pointer addition without dereference */
char* parith_tn1(char* base, int offset) {
    return base + offset;                       /* TN: no dereference */
}

/* TN-9b: subscript access (not *(p+n) syntax) */
char parith_tn2(char* base, int offset) {
    return base[offset];                        /* TN: subscript, different rule */
}

/* TN-9c: dereference of plain pointer (no arithmetic) */
char parith_tn3(char* p) {
    return *p;                                  /* TN: no arithmetic in deref */
}

/* FP-9a: *(arr + i) in bounded loop */
int parith_fp1(int* arr, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++)
        sum += *(arr + i);                      /* FP: PTR-ARITH — bounded by loop */
    return sum;
}


/* ============================================================================
 *  RULE 10 — PTR-OOB-INDEX
 * ============================================================================*/

/* TP-10a: negative constant index */
void pindex_tp1(int* arr) {
    int x = arr[-1];                            /* TP: PTR-OOB-INDEX (negative) */
    (void)x;
}

/* TP-10b: subtraction in index */
void pindex_tp2(int* arr, int idx) {
    int x = arr[idx - 1];                       /* TP: PTR-OOB-INDEX (subtraction) */
    (void)x;
}

/* TP-10c: very large constant index (>= 65536) */
void pindex_tp3(int* arr) {
    int x = arr[100000];                        /* TP: PTR-OOB-INDEX (>= 65536) */
    (void)x;
}

/* TP-10d: unary negative index */
void pindex_tp4(int* arr, int n) {
    int x = arr[-n];                            /* TP: PTR-OOB-INDEX (unary neg) */
    (void)x;
}

/* TN-10a: small constant indices */
void pindex_tn1(int* arr) {
    int x = arr[0];                             /* TN: constant 0 */
    int y = arr[100];                           /* TN: constant 100 */
    (void)x; (void)y;
}

/* TN-10b: addition in index (not subtraction) */
void pindex_tn2(int* arr, int n) {
    int x = arr[n + 1];                         /* TN: addition, not subtraction */
    (void)x;
}

/* TN-10c: plain variable index — no negative/subtraction/huge constant */
void pindex_tn3(int* arr, int i) {
    int x = arr[i];                             /* TN: plain variable read */
    (void)x;
}

/* FP-10a: arr[n-1] is an extremely common safe pattern (last element) */
void pindex_fp1(int* arr, int n) {
    int x = arr[n - 1];                         /* FP: PTR-OOB-INDEX — very common, usually safe */
    (void)x;
}


/* ============================================================================
 *  RULE 11 — INT-SIGN-COMPARE
 * ============================================================================*/

/* TP-11a: int vs size_t */
int signcmp_tp1(int idx, size_t len) {
    if (idx < len)                              /* TP: INT-SIGN-COMPARE */
        return 1;
    return 0;
}

/* TP-11b: int vs unsigned int */
int signcmp_tp2(int x, unsigned int y) {
    return x > y;                               /* TP: INT-SIGN-COMPARE */
}

/* TN-11a: both signed */
int signcmp_tn1(int a, int b) {
    return a < b;                               /* TN: both signed */
}

/* TN-11b: both unsigned */
int signcmp_tn2(size_t a, size_t b) {
    return a < b;                               /* TN: both unsigned */
}

/* TN-11c: comparison against constant — not two variables */
int signcmp_tn3(int x) {
    return x > 0;                               /* TN: constant, not variable */
}

/* TN-11d: uint8_t vs uint16_t — both unsigned */
int signcmp_tn4(uint8_t a, uint16_t b) {
    return a < b;                               /* TN: both unsigned */
}

/* FN-11a: typedef'd type — scanner can't resolve typedefs */
int signcmp_fn1(int idx, my_size len) {
    return idx < len;                           /* FN: scanner doesn't know my_size is unsigned long */
}


/* ============================================================================
 *  RULE 12 — INT-NARROW
 * ============================================================================*/

/* TP-12a: implicit narrowing — long to int */
void narrow_tp1(void) {
    long big = 0x1FFFFFFFF;
    int small = big;                            /* TP: INT-NARROW (64->32) */
    (void)small;
}

/* FN-12c: explicit cast narrowing — (short)int_val.
   Scanner's cast_expression path looks for 'primitive_type' but tree-sitter
   parses 'short' as 'sized_type_specifier'. So this is missed. */
void narrow_tp2(void) {
    int val = 100000;
    short s = (short)val;                       /* FN: INT-NARROW (32->16) — short is sized_type_specifier */
    (void)s;
}

/* TP-12c: size_t to int */
void narrow_tp3(size_t len) {
    int ilen = len;                             /* TP: INT-NARROW (64->32) */
    (void)ilen;
}

/* TN-12a: same width — int to int */
void narrow_tn1(void) {
    int a = 42;
    int b = a;                                  /* TN: same width */
    (void)b;
}

/* TN-12b: widening — short to int */
void narrow_tn2(void) {
    short s = 10;
    int i = s;                                  /* TN: widening, not narrowing */
    (void)i;
}

/* TN-12c: same width — uint32_t to int (both 32-bit) */
void narrow_tn3(void) {
    uint32_t u = 10;
    int i = u;                                  /* TN: same width */
    (void)i;
}

/* FN-12a: narrowing via function return — scanner doesn't track return types */
void narrow_fn1(void) {
    int x = get_big_val();                      /* FN: scanner doesn't know get_big_val returns long */
}

/* FN-12b: narrowing in function argument (not assignment) */
void narrow_fn2(void) {
    int val = 100000;
    takes_short(val);                           /* FN: narrowing in call arg, not init_declarator */
}


/* ============================================================================
 *  RULE 13 — INT-OVERFLOW-ALLOC
 * ============================================================================*/

/* TP-13a: malloc(n * sizeof(int)) */
int* ioverflow_tp1(size_t n) {
    return (int*)malloc(n * sizeof(int));       /* TP: INT-OVERFLOW-ALLOC */
}

/* TP-13b: malloc(a * b) — both variables */
char* ioverflow_tp2(size_t rows, size_t cols) {
    return (char*)malloc(rows * cols);          /* TP: INT-OVERFLOW-ALLOC */
}

/* TP-13c: realloc(old, n * 2) — variable * constant (n is non-const operand) */
char* ioverflow_tp3(char* old, size_t n) {
    return (char*)realloc(old, n * 2);          /* TP: INT-OVERFLOW-ALLOC */
}

/* TN-13a: malloc with pure constant */
void* ioverflow_tn1(void) {
    return malloc(1024);                        /* TN: constant */
}

/* TN-13b: calloc(n, sizeof(T)) — size_arg is args[0] = n, which is plain identifier, not binary expr */
int* ioverflow_tn2(size_t n) {
    return (int*)calloc(n, sizeof(int));        /* TN: first arg is not a multiplication */
}

/* TN-13c: malloc(sizeof(struct)) */
point_t* ioverflow_tn3(void) {
    return (point_t*)malloc(sizeof(point_t));   /* TN: sizeof only */
}

/* FN-13a: overflow pre-computed — scanner only sees plain variable in malloc */
char* ioverflow_fn1(size_t n) {
    size_t total = n * sizeof(int);             /* overflow happens here */
    return (char*)malloc(total);                /* FN: total is just an identifier */
}


/* ============================================================================
 *  RULE 14 — INT-UNDERFLOW
 * ============================================================================*/

/* TP-14a: size_t x = a - b */
void uflow_tp1(size_t total, size_t header) {
    size_t body = total - header;               /* TP: INT-UNDERFLOW */
    (void)body;
}

/* TP-14b: size_t -= */
void uflow_tp2(size_t remaining, size_t chunk) {
    remaining -= chunk;                         /* TP: INT-UNDERFLOW */
    (void)remaining;
}

/* TP-14c: unsigned int subtraction */
void uflow_tp3(unsigned int a, unsigned int b) {
    unsigned int diff = a - b;                  /* TP: INT-UNDERFLOW */
    (void)diff;
}

/* TP-14d: uint32_t subtraction */
void uflow_tp4(uint32_t length, uint32_t offset) {
    uint32_t remaining = length - offset;       /* TP: INT-UNDERFLOW */
    (void)remaining;
}

/* TN-14a: signed subtraction — doesn't wrap unsigned */
void uflow_tn1(int a, int b) {
    int diff = a - b;                           /* TN: signed type */
    (void)diff;
}

/* TN-14b: size_t addition — not subtraction */
void uflow_tn2(size_t a, size_t b) {
    size_t sum = a + b;                         /* TN: addition, not subtraction */
    (void)sum;
}

/* TN-14c: constant - constant (no variable operand) */
void uflow_tn3(void) {
    size_t x = 100 - 50;                        /* TN: both constants */
    (void)x;
}

/* FP-14a: subtraction after bounds check — scanner can't see the guard */
void uflow_fp1(size_t total, size_t header) {
    if (total < header) return;                 /* guard */
    size_t body = total - header;               /* FP: INT-UNDERFLOW — guarded but scanner can't tell */
    (void)body;
}

/* FN-14a: underflow hidden in function */
void uflow_fn1(size_t a, size_t b) {
    size_t result = safe_subtract(a, b);        /* FN: wrapped in function */
    (void)result;
}


/* ============================================================================
 *  RULE 15 — DANGER-EXEC
 * ============================================================================*/

/* TP-15a: system() with variable */
void dexec_tp1(const char* cmd) {
    system(cmd);                                /* TP: DANGER-EXEC (HIGH severity) */
}

/* TP-15b: popen() with variable */
void dexec_tp2(const char* cmd) {
    FILE* fp = popen(cmd, "r");                 /* TP: DANGER-EXEC (HIGH severity) */
    if (fp) pclose(fp);
}

/* TP-15c: system() with constructed buffer */
void dexec_tp3(const char* filename) {
    char buf[512];
    snprintf(buf, sizeof(buf), "cat %s", filename);
    system(buf);                                /* TP: DANGER-EXEC (HIGH severity) */
}

/* TP-15d: execv with variable args */
void dexec_tp4(const char* path, char* const argv[]) {
    execv(path, argv);                          /* TP: DANGER-EXEC (HIGH severity) */
}

/* TP-15e: system() with string literal — flagged at MEDIUM (lower risk) */
void dexec_tp5(void) {
    system("ls -la /tmp");                      /* TP: DANGER-EXEC (MEDIUM — literal arg) */
}

/* TN-15a: printf is not an exec function */
void dexec_tn1(const char* msg) {
    printf("%s\n", msg);                        /* TN: not in EXEC_FUNCS */
}

/* TN-15b: fork() is not in EXEC_FUNCS */
void dexec_tn2(void) {
    pid_t pid = fork();                         /* TN: fork not tracked */
    (void)pid;
}


/* ============================================================================
 *  RULE 16 — DANGER-FORMAT
 * ============================================================================*/

/* TP-16a: printf with variable format */
void dfmt_tp1(char* user_msg) {
    printf(user_msg);                           /* TP: DANGER-FORMAT */
}

/* TP-16b: fprintf with variable format */
void dfmt_tp2(FILE* log, char* msg) {
    fprintf(log, msg);                          /* TP: DANGER-FORMAT */
}

/* TP-16c: snprintf with variable format (3rd arg, index 2) */
void dfmt_tp3(char* buf, size_t sz, char* fmt) {
    snprintf(buf, sz, fmt);                     /* TP: DANGER-FORMAT */
}

/* TP-16d: syslog with variable format (2nd arg, index 1) */
void dfmt_tp4(int prio, char* msg) {
    syslog(prio, msg);                          /* TP: DANGER-FORMAT */
}

/* TP-16e: printf with function call as format (not a literal) */
void dfmt_tp5(int code, const char* name) {
    printf(get_format(code), name);             /* TP: DANGER-FORMAT — call_expression is not string_literal */
}

/* TN-16a: printf with literal format */
void dfmt_tn1(const char* name) {
    printf("Hello, %s\n", name);                /* TN: literal format */
}

/* TN-16b: fprintf with literal format */
void dfmt_tn2(FILE* f, int code) {
    fprintf(f, "Error: %d\n", code);            /* TN: literal format */
}

/* TN-16c: snprintf with literal format */
void dfmt_tn3(char* buf, size_t sz, int val) {
    snprintf(buf, sz, "val=%d", val);           /* TN: literal format */
}

/* TN-16d: puts is not a printf-family function */
void dfmt_tn4(char* msg) {
    puts(msg);                                  /* TN: puts not in PRINTF_FUNCS */
}


/* ============================================================================
 *  CROSS-RULE EDGE CASES
 * ============================================================================*/

/* EDGE-1: Multiple vulnerabilities in one function */
void edge_multi_vuln(char* input) {
    char buf[64];
    strcpy(buf, input);                         /* TP: MEM-UNSAFE-COPY */

    char* p = malloc(strlen(input));
    p[0] = 'A';                                /* TP: MEM-NULL-DEREF */
    free(p);
    free(p);                                    /* TP: MEM-DOUBLE-FREE */
}

/* EDGE-2: Byte conversion + malloc without check — two rules fire */
void edge_chain(char* raw_pkt) {
    uint32_t payload_len = ntohl(*(uint32_t*)raw_pkt);
    char* payload = (char*)malloc(payload_len);
    memcpy(payload, raw_pkt + 4, payload_len);  /* TP: MEM-UNVALIDATED-SIZE + MEM-NULL-DEREF (via arg) */
}

/* EDGE-3: Completely safe code — no findings expected */
void edge_safe(void) {
    char buf[256];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "hello world");
    printf("%s\n", buf);
    /* nothing suspicious */                    /* TN: no vulnerabilities */
}

/* EDGE-4: Macro constant in subtraction — scanner treats HEADER_LEN as identifier */
#define HEADER_LEN 16
void edge_define(size_t pkt_len) {
    size_t body_len = pkt_len - HEADER_LEN;     /* TP: INT-UNDERFLOW — HEADER_LEN expands to 16 by preprocessor,
                                                   but tree-sitter sees the macro name as identifier */
}

/* EDGE-5: free in nested scope, then use in outer scope */
void edge_nested_scope(void) {
    char* data = malloc(100);
    if (!data) return;
    if (1) {
        free(data);
    }
    printf("%s\n", data);                       /* TP: MEM-USE-AFTER-FREE */
}

/* EDGE-6: Correct multi-alloc with proper cleanup.
   Scanner produces FPs because free(a) in error branch is seen as preceding
   the later free(a) and memcpy(b,a,n) in the normal path. */
void edge_multi_alloc(size_t n) {
    char* a = malloc(n);
    if (!a) return;
    char* b = malloc(n);
    if (!b) { free(a); return; }                /* FP source: free(a) in exclusive branch */
    memcpy(b, a, n);                            /* TP: MEM-UNSAFE-COPY (variable size n)
                                                   FP: MEM-USE-AFTER-FREE (free(a) in error branch) */
    free(a);                                    /* FP: MEM-DOUBLE-FREE (free(a) in error branch) */
    free(b);
}

/* EDGE-7: Completely empty function */
void edge_empty(void) {
    /* nothing to flag */                       /* TN: empty */
}

/* EDGE-8: Global pointer — scanner doesn't track globals */
static int* g_buf;
void edge_global_alloc(void) {
    g_buf = (int*)malloc(100 * sizeof(int));
    g_buf[0] = 42;                              /* FN for MEM-NULL-DEREF — scanner only tracks locals */
}


/**
 * ============================================================================
 *  EXPECTED RESULTS SUMMARY  (verified against scanner output)
 * ============================================================================
 *
 *  Total findings: 89
 *  All 16 rules fire.
 *
 *  Legend:
 *    TP  = True Positive   (vulnerable code, scanner correctly flags)
 *    TN  = True Negative   (safe code, scanner correctly stays silent)
 *    FP  = False Positive  (safe code, scanner incorrectly flags — known weakness)
 *    FN  = False Negative  (vulnerable code, scanner misses — known limitation)
 *
 *  Dedicated test cases per rule:
 *  ──────────────────────────────────────────────────────────────────────────────
 *  Rule                 | TP | TN | FP | FN | Notes
 *  ---------------------|----|----|----|----|-------------------------------------------
 *  MEM-UNSAFE-COPY      |  7 |  5 |  1 |  1 | FP: bounded memcpy. FN: custom wrapper
 *  MEM-BUFFER-OOB       |  3 |  3 |  2 |  0 | FP: bounded loop, validated index
 *  MEM-USE-AFTER-FREE   |  3 |  1 |  5 |  2 | FP: reassign+nullchk, exclusive branch, return guard
 *  MEM-DOUBLE-FREE      |  3 |  3 |  5 |  1 | FP: exclusive branches (collateral from UAF tests too)
 *  MEM-RETURN-LOCAL     |  2 |  2 |  2 |  1 | FP: static var, static ptr. FN: array decay
 *  MEM-DANGLING-PTR     |  2 |  3 |  0 |  2 | FN: double indirection, struct field
 *  MEM-NULL-DEREF       |  7 |  5 |  1 |  2 | FP: ternary guard. FN: struct field, cross-func
 *  MEM-UNVALIDATED-SIZE |  5 |  3 |  0 |  1 | TP includes expression containing conv var. FN: intermediate
 *  PTR-ARITH            |  3 |  3 |  1 |  0 | FP: bounded loop
 *  PTR-OOB-INDEX        |  4 |  3 |  1 |  0 | FP: arr[n-1] common pattern
 *  INT-SIGN-COMPARE     |  2 |  4 |  0 |  1 | FN: typedef
 *  INT-NARROW           |  2 |  3 |  0 |  3 | FN: (short) cast, func return, call arg
 *  INT-OVERFLOW-ALLOC   |  3 |  3 |  0 |  1 | FN: pre-computed overflow
 *  INT-UNDERFLOW        |  5 |  3 |  1 |  1 | FP: guarded subtraction. FN: wrapped func
 *  DANGER-EXEC          |  5 |  2 |  0 |  0 | TP-15e is MEDIUM severity (literal arg)
 *  DANGER-FORMAT        |  6 |  4 |  0 |  0 | TP includes vsprintf cross-rule + call_expression fmt
 *  ---------------------|----|----|----|----|-------------------------------------------
 *
 *  Key scanner limitations exposed by this test:
 *    1. No control flow analysis — can't distinguish exclusive branches
 *       (causes FP for UAF, double-free, underflow in if/else patterns)
 *    2. No alias tracking in UAF/double-free rules (only in NULL-deref)
 *    3. No intervening reassignment check in UAF rule
 *    4. static storage class not distinguished from automatic locals
 *    5. No typedef resolution (custom types invisible to sign/width checks)
 *    6. Tree-sitter parses 'short' as sized_type_specifier, not primitive_type
 *       (causes FN in cast narrowing detection)
 *    7. Ternary operator not recognized as a NULL-check guard
 *
 *  Run with --all to see all findings.
 *  Default (no flags) shows only CRITICAL+HIGH confidence.
 */
