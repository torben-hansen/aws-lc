// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "entropy_pool_daemon.h"

#define JED_DAEMON_FAIL(error_string) fprintf(stderr, "[JED daemon] Failed: %s\n", error_string); exit(EXIT_FAILURE);

// Initial entropy
// In a real implementation this would be some entropy pool implementation
static uint8_t entropy_pool[JED_ENTROPY_POOL_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

int main() {
    
    // IPC over socket
    // https://man7.org/linux/man-pages/man2/socket.2.html
    struct sockaddr_un domain_sock_addr = {
        AF_UNIX,
        JED_DOMAIN_SOCK_NAME
    };

    unlink(JED_DOMAIN_SOCK_NAME); // Remove any previous sockets
    int domain_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(domain_sock, (struct sockaddr *) &domain_sock_addr,
        sizeof(domain_sock_addr));
    listen(domain_sock, JED_DOMAIN_SOCK_MAX_QUEUE_LENGTH);

    fprintf(stdout, "[JED daemon] Starting Jitter Entropy Daemon:\n");
    fprintf(stdout, "[JED daemon] Domain socket name: %s\n", JED_DOMAIN_SOCK_NAME);
    fprintf(stdout, "[JED daemon] Listening domain socket: %i\n", domain_sock);
    fprintf(stdout, "[JED daemon] Domain socket queue length: %i\n", JED_DOMAIN_SOCK_MAX_QUEUE_LENGTH);

    int client_iterator = 0;

    int urandomfd = open("/dev/urandom", O_RDONLY);
    if (urandomfd < 0) {
        fprintf(stdout, "[JED daemon] failed to open /dev/urandom\n");
        return EXIT_FAILURE;
    }

    while(1) {
        fprintf(stdout, "\n"); // Better distinguish new connection

        struct sockaddr_un client_sock_addr;
        socklen_t client_sock_addr_length = sizeof(client_sock_addr);

        int client_sock = accept(domain_sock,
            (struct sockaddr *) &client_sock_addr, &client_sock_addr_length);
        fprintf(stdout, "[JED daemon] Incoming connection (id: %i)\n", client_sock);
        fprintf(stdout, "[JED daemon] Client iterator: %i\n", client_iterator + 1);
        fprintf(stdout, "[JED daemon] Sending entropy to client (id: %i)\n", client_sock);
        if (write(client_sock, entropy_pool, JED_ENTROPY_WRITE_ALWAYS) != JED_ENTROPY_WRITE_ALWAYS) {
            JED_DAEMON_FAIL("writing entropy data to socket")
        }
        fprintf(stdout, "[JED daemon] Successfully sent entropy to client (id: %i)\n", client_sock);
        client_iterator++;
        fprintf(stdout, "[JED daemon] Disconnected connection (id: %i)\n", client_sock);

        // "Randomise" to allow FIPS tests to pass (namely the CRNGT tests...)
        ssize_t result = read(urandomfd, entropy_pool, JED_ENTROPY_WRITE_ALWAYS);
        if (result < 0) {
            fprintf(stdout, "[JED daemon] Reading from /dev/urandom failed\n");
            return EXIT_FAILURE;
        }

        int true_value = 1;
        setsockopt(client_sock, SOL_SOCKET, SO_REUSEADDR, &true_value, sizeof(int));
        close(client_sock);
    }

#if 0
    while(1) {
        fprintf(stdout, "\n"); // Better distinguish new connection

        struct sockaddr_un client_sock_addr;
        socklen_t client_sock_addr_length = sizeof(client_sock_addr);

        int client_sock = accept(domain_sock,
            (struct sockaddr *) &client_sock_addr, &client_sock_addr_length);
        fprintf(stdout, "[JED daemon] Incoming connection (id: %i)\n", client_sock);
        FILE *client_fd = fdopen(client_sock, "r+");
        fprintf(client_fd, "Client iterator: %i\n", client_iterator + 1);
        fprintf(stdout, "[JED daemon] Sent client iterator: %i (id: %i)\n", client_iterator + 1, client_sock);
        fclose(client_fd);
        client_iterator++;
        fprintf(stdout, "[JED daemon] Disconnected connection (id: %i)\n", client_sock);
    }
#endif

    return EXIT_SUCCESS;
}
