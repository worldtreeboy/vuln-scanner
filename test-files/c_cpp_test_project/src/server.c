/**
 * server.c — Network server entry point
 *
 * Mirrors source_code/main.c + socket.c accept loop.
 * Mostly clean code — only a few low-severity findings expected.
 *
 * Expected scanner findings:
 *   Line 44: DANGER-FORMAT — fprintf with non-literal format string
 */

#include "protocol.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int createServer(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        die("socket failed");

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("bind failed");
    if (listen(fd, MAX_CLIENTS) < 0)
        die("listen failed");

    return fd;
}

/* Logging helper with format string issue */
void logEvent(FILE* logfile, char* user_message) {
    fprintf(logfile, user_message);                    /* MATCH: DANGER-FORMAT          */
}

void startServer(int port) {
    int serverFd = createServer(port);
    printf("Listening on port %d\n", port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int clientFd = accept(serverFd, (struct sockaddr*)&client_addr, &client_len);
        if (clientFd < 0) {
            perror("accept");
            continue;
        }

        session_t* session = (session_t*)malloc(sizeof(session_t));
        if (!session) {
            close(clientFd);
            continue;
        }
        session->socket_fd  = clientFd;
        session->address    = client_addr;
        session->session_id = 0;

        pthread_t tid;
        if (pthread_create(&tid, NULL, (void*(*)(void*))dispatchMessage, session) != 0) {
            free(session);
            close(clientFd);
            continue;
        }
        pthread_detach(tid);
    }

    close(serverFd);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port\n");
        return 1;
    }

    startServer(port);
    return 0;
}
