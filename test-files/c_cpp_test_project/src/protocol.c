/**
 * protocol.c — Binary protocol parser and stream reader
 *
 * Mirrors handler.c patterns: length-prefixed fields read from a network
 * buffer, struct returned on stack, fragmented recv loop.
 *
 * Expected scanner findings (CRITICAL):
 *   Line 38:  MEM-UNVALIDATED-SIZE — safedup using key_len from readU16BE without bounds check
 *   Line 51:  MEM-UNVALIDATED-SIZE — safedup using value_len from readU32BE without bounds check
 *   Line 58:  MEM-DANGLING-PTR     — returning &msg (stack local) via msg_ptr
 *   Line 70:  INT-UNDERFLOW        — size_t bodyLen = total_len - HEADER_SIZE; may wrap
 *   Line 71:  MEM-NULL-DEREF       — (char*)malloc(bodyLen) without NULL check; alias used
 *   Line 80:  INT-UNDERFLOW        — bodyLen -= nread (unsigned -=)
 *
 * Expected findings (HIGH):
 *   Line 48:  MEM-BUFFER-OOB       — msg_ptr->value[value_len] write with variable index
 *   Line 41:  MEM-BUFFER-OOB       — msg_ptr->key[key_len] write with variable index
 *
 * Expected findings (MEDIUM):
 *   Line 34:  MEM-UNSAFE-COPY      — memcpy with WORD_SIZE (macro / non-sizeof)
 *   Line 46:  MEM-UNSAFE-COPY      — memcpy with DWORD_SIZE
 */

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Parse a length-prefixed binary message from a raw buffer.
 * Same pattern as source_code/handler.c parseCommand().
 */
message_t* parseMessage(char* buf) {
    message_t msg;                                  /* stack local                           */
    message_t* msg_ptr = &msg;                      /* pointer to stack local                */

    /* --- msg_type (1 byte) --- */
    msg_ptr->msg_type = (uint8_t)*buf;
    buf += 1;

    /* --- key: 2-byte big-endian length prefix + data --- */
    char raw_key_len[WORD_SIZE];
    memcpy(raw_key_len, buf, WORD_SIZE);            /* MATCH: MEM-UNSAFE-COPY (macro size)   */
    uint16_t key_len = readU16BE(raw_key_len);

    buf += WORD_SIZE;
    msg_ptr->key = (char*)safedup(buf, key_len + 1);  /* MATCH: MEM-UNVALIDATED-SIZE         */
    if (msg_ptr->key == NULL)
        return NULL;
    msg_ptr->key[key_len] = '\0';                   /* MATCH: MEM-BUFFER-OOB (variable idx)  */
    msg_ptr->key_len = key_len;

    /* --- value: 4-byte big-endian length prefix + data --- */
    buf += key_len;
    char raw_val_len[DWORD_SIZE];
    memcpy(raw_val_len, buf, DWORD_SIZE);           /* MATCH: MEM-UNSAFE-COPY (macro size)   */
    uint32_t value_len = readU32BE(raw_val_len);

    buf += DWORD_SIZE;
    msg_ptr->value = (char*)safedup(buf, value_len + 1); /* MATCH: MEM-UNVALIDATED-SIZE      */
    if (msg_ptr->value == NULL)
        return NULL;                                /* Note: leaks msg_ptr->key here         */
    msg_ptr->value[value_len] = '\0';               /* MATCH: MEM-BUFFER-OOB (variable idx)  */
    msg_ptr->value_len = value_len;

    return msg_ptr;                                 /* MATCH: MEM-DANGLING-PTR               */
}

/**
 * Read a full message body over a stream socket (may arrive in fragments).
 * Same pattern as source_code/handler.c handleFrag().
 */
char* readStream(session_t* session, size_t total_len) {
    size_t bodyLen = total_len - HEADER_SIZE;        /* MATCH: INT-UNDERFLOW                  */
    char* body = (char*)malloc(bodyLen);              /* may return NULL after underflow        */
    char* cursor = body;                              /* alias                                 */

    while (bodyLen > 0) {
        size_t nread = recv(session->socket_fd, cursor, bodyLen, 0);
                                                     /* MATCH: MEM-NULL-DEREF (via alias)     */
        if (nread == 0)
            return NULL;                             /* Note: leaks body here                 */

        bodyLen -= nread;                            /* MATCH: INT-UNDERFLOW (-=)             */
        cursor  += nread;
    }

    return body;
}

/**
 * Main dispatch loop: reads header, then body, then parses.
 * Same pattern as source_code/handler.c handleClient().
 */
void dispatchMessage(session_t* session) {
    while (1) {
        char hdr[HEADER_SIZE];
        size_t n = recv(session->socket_fd, hdr, HEADER_SIZE, 0);
        if (n < HEADER_SIZE)
            break;

        size_t total_len = readU32BE(hdr);

        char* payload = readStream(session, total_len);
        if (payload == NULL)
            break;

        message_t* msg = parseMessage(payload);

        if (msg == NULL) {
            free(payload);
            continue;
        }

        /* process msg ... */
        free(payload);

        /* Note: msg->key and msg->value are never freed (memory leak) */
    }

    close(session->socket_fd);
    free(session);
}
