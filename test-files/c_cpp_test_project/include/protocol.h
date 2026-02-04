#pragma once

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define HEADER_SIZE 8
#define WORD_SIZE   2
#define DWORD_SIZE  4
#define MAX_CLIENTS 64
#define RECV_BUF    4096

typedef struct {
    int      socket_fd;
    struct   sockaddr_in address;
    uint32_t session_id;
} session_t;

/*
 * Wire format (big-endian):
 *   [4 bytes total_len][1 byte msg_type][2 bytes key_len][key_len bytes key]
 *   [4 bytes value_len][value_len bytes value]
 */
typedef struct {
    uint8_t  msg_type;
    char*    key;
    uint32_t key_len;
    char*    value;
    uint32_t value_len;
} message_t;

typedef struct {
    char*  name;
    char*  host;
    int    port;
    size_t max_conns;
} config_t;

/* protocol.c */
message_t* parseMessage(char* buf);
char*      readStream(session_t* session, size_t total_len);
void       dispatchMessage(session_t* session);

/* executor.c */
int executeQuery(const char* query, const char* arg);
int runDiagnostic(const char* toolpath, const char* target);
int batchProcess(message_t** msgs, size_t count);

/* config.c */
config_t* loadConfig(const char* path);
config_t* parseConfigBuf(char* raw, size_t len);

/* util.c */
uint32_t   readU32BE(const char* p);
uint16_t   readU16BE(const char* p);
void*      safedup(const void* src, size_t n);
int        fileExists(const char* path);
void       die(const char* msg);
