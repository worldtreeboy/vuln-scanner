/**
 * executor.c — Command execution and batch processing
 *
 * Mirrors source_code/operation.c (popen-based execution) and
 * source_code/helper.c (writeToFile, runOperation patterns).
 *
 * Expected scanner findings:
 *   Line 30: DANGER-EXEC           — popen() with variable command
 *   Line 54: DANGER-EXEC           — system() with variable command
 *   Line 55: DANGER-FORMAT          — printf with non-literal format
 *   Line 69: MEM-DOUBLE-FREE       — free(batch) twice without reassignment
 *   Line 72: MEM-USE-AFTER-FREE    — batch[i] used after free(batch)
 *   Line 83: MEM-NULL-DEREF        — malloc without NULL check, direct deref
 *   Line 92: INT-OVERFLOW-ALLOC    — malloc(count * sizeof(char*))
 *   Line 104: MEM-UNSAFE-COPY      — strcpy with no bounds
 *   Line 105: MEM-UNSAFE-COPY      — strcat with no bounds
 *   Line 106: MEM-UNSAFE-COPY      — sprintf with no bounds
 *   Line 107: MEM-UNSAFE-COPY      — gets with no bounds
 */

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int runDiagnostic(const char* toolpath, const char* target) {
    if (!fileExists(toolpath))
        return 0;

    size_t cmd_len = strlen(toolpath) + 1 + strlen(target) + 1;
    char* cmd = (char*)malloc(cmd_len);
    if (!cmd) return 0;

    snprintf(cmd, cmd_len, "%s %s", toolpath, target);

    FILE* fp = popen(cmd, "r");                     /* MATCH: DANGER-EXEC                    */

    free(cmd);
    if (!fp) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        printf("%s", line);
    }

    pclose(fp);
    return 1;
}

int executeQuery(const char* query, const char* arg) {
    if (!fileExists("/usr/bin/psql"))
        return 0;

    char buf[512];
    snprintf(buf, sizeof(buf), "psql -c \"%s\" %s", query, arg);

    /* Both dangerous patterns in one function */
    system(buf);                                    /* MATCH: DANGER-EXEC                    */
    printf(buf);                                    /* MATCH: DANGER-FORMAT                  */

    return 1;
}

/**
 * Batch processing with double-free and use-after-free.
 * Mirrors the double-free pattern in source_code/handler.c handleClient()
 * where cmd is freed at line 127 then again at 132.
 */
int batchProcess(message_t** msgs, size_t count) {
    char** batch = (char**)malloc(count * sizeof(char*));
                                                    /* MATCH: INT-OVERFLOW-ALLOC             */
    if (!batch) return 0;

    for (size_t i = 0; i < count; i++)
        batch[i] = msgs[i]->key;

    free(batch);

    /* Error path: tries to free again without reassignment */
    free(batch);                                    /* MATCH: MEM-DOUBLE-FREE                */

    /* Use after free — iterating after batch was freed */
    for (size_t i = 0; i < count; i++)
        printf("%s\n", batch[i]);                   /* MATCH: MEM-USE-AFTER-FREE             */

    return 1;
}

/**
 * Response builder with missing NULL check.
 * malloc may fail; immediate dereference crashes.
 */
char* buildResponse(const char* status, const char* body) {
    size_t len = strlen(status) + strlen(body) + 4;
    char* resp = malloc(len);
    resp[0] = '[';                                  /* MATCH: MEM-NULL-DEREF                 */
    snprintf(resp + 1, len - 1, "%s] %s", status, body);
    return resp;
}

/**
 * Index table construction with integer overflow in allocation.
 */
int* buildIndexTable(size_t count) {
    int* table = malloc(count * sizeof(int));       /* MATCH: INT-OVERFLOW-ALLOC             */
    if (!table) return NULL;
    for (size_t i = 0; i < count; i++)
        table[i] = 0;
    return table;
}

/**
 * Legacy string functions that should all flag.
 */
void legacyCopy(char* dst, char* src, char* fmt) {
    strcpy(dst, src);                               /* MATCH: MEM-UNSAFE-COPY (strcpy)       */
    strcat(dst, src);                               /* MATCH: MEM-UNSAFE-COPY (strcat)       */
    sprintf(dst, "%s", fmt);                        /* MATCH: MEM-UNSAFE-COPY (sprintf)      */
    gets(dst);                                      /* MATCH: MEM-UNSAFE-COPY (gets)         */
}

/**
 * Return address of local — direct &local in return.
 */
int* getLocalArray() {
    int arr[16];
    memset(arr, 0, sizeof(arr));
    return &arr[0];                                 /* MATCH: MEM-RETURN-LOCAL               */
}
