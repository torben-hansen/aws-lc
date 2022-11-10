// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include "internal.h"

#include "../delocate.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>

#define JITTER_ENTROPY_DAEMON_DOMAIN_SOCK_NAME "/tmp/jitter_entropy_daemon"

struct jitter_entropy_daemon_client {
  bool daemon_connection_is_open;
  int socket_id;
};

// Will be allocated in .bss and hence initalised to 0. Therefore,
// |daemon_connection_is_open| should be false by default.
DEFINE_THREAD_LOCAL_BSS_GET(struct jitter_entropy_daemon_client, dynamic_jitter_entropy_daemon_client)

//#define DEBUG_DAEMON_ENTROPY_POOL 1

static void jitter_entropy_daemon_client_debug_print(
  struct jitter_entropy_daemon_client *client, const char *info) {

#ifdef DEBUG_DAEMON_ENTROPY_POOL
  pid_t tid = syscall(__NR_gettid);
  fprintf(stderr, "[daemon jitter entropy pool client] thread ID: %i\n", tid);
  if (info != NULL) {
    fprintf(stderr, "%s\n", info);
  }
  if (client != NULL) {
    fprintf(stderr, "daemon_connection_is_open: %s\n", client->daemon_connection_is_open ? "true" : "false");;
    fprintf(stderr, "socket_id: %i\n", client->socket_id);
  }
#endif

}

static int jitter_entropy_daemon_client_connect(
  struct jitter_entropy_daemon_client *client) {

  jitter_entropy_daemon_client_debug_print(client, __func__);

  if (!client->daemon_connection_is_open) {
    // IPC over socket
    // https://man7.org/linux/man-pages/man2/socket.2.html
    struct sockaddr_un client_domain_sock_addr = {
      AF_UNIX,
      JITTER_ENTROPY_DAEMON_DOMAIN_SOCK_NAME,
    };

    int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sock == -1) {
      jitter_entropy_daemon_client_debug_print(client, strerror(errno));
      return 0;
    }
    if (connect(client_sock, (struct sockaddr *) & client_domain_sock_addr,
      sizeof(client_domain_sock_addr)) != 0) {
      jitter_entropy_daemon_client_debug_print(client, strerror(errno));
      return 0;
    }

    client->socket_id = client_sock;
    client->daemon_connection_is_open = true;
    jitter_entropy_daemon_client_debug_print(client, NULL);
  }

  return 1;
}


static int jitter_entropy_daemon_client_teardown_connection(
  struct jitter_entropy_daemon_client *client) {

  return 1;
}

#define JITTER_ENTROPY_DAEMON_ENTROPY_SIZE 64
static int jitter_entropy_daemon_client_read(
  struct jitter_entropy_daemon_client *client,
  uint8_t buffer_read[JITTER_ENTROPY_DAEMON_ENTROPY_SIZE]) {

  jitter_entropy_daemon_client_debug_print(client, __func__);

  if (jitter_entropy_daemon_client_connect(client) != 1) {
    return 0;
  }

  ssize_t bytes_read = read(client->socket_id, buffer_read, JITTER_ENTROPY_DAEMON_ENTROPY_SIZE);
  if (bytes_read < 0) {
    jitter_entropy_daemon_client_debug_print(client, strerror(errno));
    return 0;
  }

  if ((size_t) bytes_read != JITTER_ENTROPY_DAEMON_ENTROPY_SIZE) {
    return 0;
  }

  // Daemon doesn't maintain a long-lived connection
  client->daemon_connection_is_open = false;

  return 1;
}

int daemon_entropy_pool_get_entropy(uint8_t *buffer_get, size_t buffer_get_size) {

  jitter_entropy_daemon_client_debug_print(NULL, __func__);

  // Make sure to round up here...
  size_t number_of_iterations = ((buffer_get_size + (JITTER_ENTROPY_DAEMON_ENTROPY_SIZE - 1)) / JITTER_ENTROPY_DAEMON_ENTROPY_SIZE);
  ssize_t total_bytes_read_until_now = 0;
  size_t total_bytes_copied_until_now = 0;
  uint8_t entropy_buffer[JITTER_ENTROPY_DAEMON_ENTROPY_SIZE] = { 0 };
  size_t residue = buffer_get_size % JITTER_ENTROPY_DAEMON_ENTROPY_SIZE;

  for (size_t iterator = 0; iterator < number_of_iterations; iterator++) {

    if (jitter_entropy_daemon_client_read(
      dynamic_jitter_entropy_daemon_client_bss_get(),
      entropy_buffer) != 1) {
      return 0;
    }

    size_t copy_size = JITTER_ENTROPY_DAEMON_ENTROPY_SIZE;
    if (iterator >= number_of_iterations - 1 && residue != 0) {
      // i.e last iteration, so only copy the residue but skip if on a
      // JITTER_ENTROPY_DAEMON_ENTROPY_SIZE boundary
      copy_size = residue;
    }

    if (total_bytes_copied_until_now + copy_size > buffer_get_size) {
      // Uhh ohh, overflow...
      return 0;
    }

    memcpy(buffer_get + total_bytes_copied_until_now, entropy_buffer, copy_size);
    total_bytes_read_until_now = total_bytes_read_until_now + JITTER_ENTROPY_DAEMON_ENTROPY_SIZE;
    total_bytes_copied_until_now = total_bytes_copied_until_now + copy_size;
  }

  if (total_bytes_copied_until_now != buffer_get_size) {
    return 0;
  }

  if ((size_t) total_bytes_read_until_now != (number_of_iterations * JITTER_ENTROPY_DAEMON_ENTROPY_SIZE)) {
    return 0;
  }

#if defined(DEBUG_DAEMON_ENTROPY_POOL)
  fprintf(stderr, "buffer_read:\n");
  for (size_t i = 0; i < buffer_read_size; i++) {
    fprintf(stdout, "%02X", buffer_read[i]);
  }
  fprintf(stdout, "\n");
#endif

  return 1;
}

int daemon_entropy_pool_clean_thread(void) {
  return jitter_entropy_daemon_client_teardown_connection(
    dynamic_jitter_entropy_daemon_client_bss_get());
}
