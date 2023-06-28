// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// PoC implementation of an entropy pool thread.
// Implemented as: API --> entropy pool --> circular buffer.

#include "internal.h"

#include "../delocate.h"

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

// Circular buffer implementation

#if defined(AWSLC_FIPS)

// Otherwise a useless circular buffer...
OPENSSL_STATIC_ASSERT(CIRCULAR_BUFFER_SIZE > 0, CIRCULAR_BUFFER_SIZE_must_be_strictly_larger_than_0);

static void circular_buffer_debug_print(struct circular_buffer *buffer,
  char *info) {
#ifdef DEBUG_THREAD_ENTROPY_POOL
  pid_t tid = syscall(__NR_gettid);
  fprintf(stderr, "[thread entropy pool] thread ID: %i\n", tid);
  if (info != NULL) {
    fprintf(stderr, "%s\n", info);
  }
  fprintf(stderr, "capacity: %zu\n", buffer->capacity);
  fprintf(stderr, "index_read: %zu\n", buffer->index_read);
  fprintf(stderr, "index_write: %zu\n", buffer->index_write);
  fprintf(stderr, "count: %zu\n", buffer->count);
  fprintf(stderr, "buffer:\n");
  printf("\n");
  for (size_t i = 0; i < CIRCULAR_BUFFER_SIZE; i++) {
    printf("0x%.2X ", buffer->buffer[i]);
  }
  printf("\n");
#endif
}

// circular_buffer_init initialises the circular buffer |buffer|
static void circular_buffer_init(struct circular_buffer *buffer) {
  circular_buffer_debug_print(buffer, (char *) "circular_buffer_init()");
  buffer->capacity = CIRCULAR_BUFFER_SIZE;
  buffer->index_read = 0;
  buffer->index_write = 0;
  buffer->count = 0;
  memset(buffer->buffer, 0, CIRCULAR_BUFFER_SIZE);
}

// circular_buffer_reset "resets" the circular buffer |buffer|. Currently
// equivalent to calling circular_buffer_init
static void circular_buffer_reset(struct circular_buffer *buffer) {
  // Assumes flat representation.
  memset(buffer, 0, sizeof(*buffer));
  buffer->capacity = CIRCULAR_BUFFER_SIZE;
}

// circular_buffer_validate_state performs various run-time validation on the
// circular buffer |buffer|.
// Should call this function for every mutable operation.
static bool circular_buffer_validate_state(struct circular_buffer *buffer) {
  circular_buffer_debug_print(buffer, NULL);
  if (buffer->count > sizeof(buffer->buffer)) {
    return false;
  }

  // TODO: Can add more here i.e. difference between read and write should be
  // the count.

  return true;
}

// circular_buffer_compute_overflow computes the index after adding
// |index_increments| to the index |index| of the circular buffer |buffer|.
// This can be used to compute the number of overflow bytes after a read or
// write operation against a circular buffer.
static size_t circular_buffer_compute_next_index(struct circular_buffer *buffer,
  size_t index, size_t index_increment) {

  // TODO: index+index_increment could potentially overflow the maximum value
  // of the type size_t. Should ensure this is not the case.

  // Do the calculation
  // modulo buffer->capacity because we want the index. If done modulo
  // buffer->capacity-1 we can instead get the number of overflow bytes for a
  // read or write operation (but we don't want that).
  return (index + index_increment) % (buffer->capacity);
}

// circular_buffer_max_can_put returns the maximum number of bytes that can be
// written to the circular buffer |buffer|
static size_t circular_buffer_max_can_put(struct circular_buffer *buffer) {
  return buffer->capacity - buffer->count;
}

// circular_buffer_write_and_update writes |buffer_write_size| of bytes from
// |buffer_write| to circular buffer |buffer|.
// Note!!!! this function cannot handle overflows.
static int circular_buffer_write(struct circular_buffer *buffer,
  const uint8_t *buffer_write, size_t buffer_write_size) {

  // Make sure not to overflow buffer. This means that this function cannot
  // handle overflows. -1 because we first write to
  // buffer->buffer[buffer->index_write]
  if ((buffer->index_write + buffer_write_size - 1) >= buffer->capacity) {
    return 0;
  }
  memcpy(buffer->buffer + buffer->index_write, buffer_write, buffer_write_size);

  // TODO: buffer->index_write + buffer_write_size could potentially overflow the
  // maximum value of the type size_t. Should ensure this is not the case.

  buffer->count = buffer->count + buffer_write_size;

  return 1;
}

// circular_buffer_put writes |buffer_put_size| bytes from |buffer_put| into the
// circular buffer |buffer|.
// This function handles overflow.
static int circular_buffer_put(struct circular_buffer *buffer,
  const uint8_t *buffer_put, size_t buffer_put_size) {

  circular_buffer_debug_print(buffer, (char *) "circular_buffer_put()");

  if (buffer_put_size > circular_buffer_max_can_put(buffer)) {
    // Can't satisfy put operation
    return 0;
  }

  size_t final_index = circular_buffer_compute_next_index(buffer,
    buffer->index_write, buffer_put_size);

  if (final_index < buffer->index_write) {

    size_t bytes_up_to_buffer_size = buffer->capacity - buffer->index_write;

    if (buffer_put_size != (bytes_up_to_buffer_size + final_index)) {
      // Uhh ohh, this is weird
      return 0;
    }
    // First write bytes up to the buffer size. We write to
    // buffer->buffer[index_write], so no need to subtract by 1.
    circular_buffer_write(buffer, buffer_put, bytes_up_to_buffer_size);

    buffer->index_write = 0;
    circular_buffer_write(buffer, buffer_put + bytes_up_to_buffer_size, final_index);
    buffer->index_write = final_index;
  } else {

    circular_buffer_write(buffer, buffer_put, buffer_put_size);
    buffer->index_write = final_index; 
  }

  if (!circular_buffer_validate_state(buffer)) {
    return 0;
  }

  return 1;
}

// circular_buffer_max_can_get returns the maximum number of bytes that can be
// read from the circular buffer |buffer|
static size_t circular_buffer_max_can_get(struct circular_buffer *buffer) {
  return buffer->count;
}

// circular_buffer_read reads |buffer_read_size| of bytes from
// |buffer_read| from circular buffer |buffer|.
// Note!!!! this function cannot handle overflows.
static void circular_buffer_read(struct circular_buffer *buffer,
  uint8_t *buffer_read, size_t buffer_read_size) {

  memcpy(buffer_read, buffer->buffer + buffer->index_read, buffer_read_size);
  memset(buffer->buffer + buffer->index_read, 0, buffer_read_size);

  buffer->count = buffer->count - buffer_read_size;
}

// circular_buffer_get reads |buffer_get_size| bytes from circular buffer
// |buffer| to |buffer_put|.
// This function handles overflow.
// NOTE!!!! |buffer_get| must be at least |buffer_get_size| in size.
static int circular_buffer_get(struct circular_buffer *buffer,
  uint8_t *buffer_get, size_t buffer_get_size) {

  circular_buffer_debug_print(buffer, (char *) "circular_buffer_get()");

  if (buffer_get_size > circular_buffer_max_can_get(buffer)) {
    // Can't satisfy get operation
    return 0;
  }

  size_t final_index = circular_buffer_compute_next_index(buffer,
    buffer->index_read, buffer_get_size);

  if (final_index < buffer->index_read) {

    size_t bytes_up_to_buffer_size = buffer->capacity - buffer->index_read;

    if (buffer_get_size != (bytes_up_to_buffer_size + final_index)) {
      // Uhh ohh, this is weird
      return 0;
    }
    // First write bytes up to the buffer size. We write to
    // buffer->buffer[index_read], so no need to subtract by 1.
    circular_buffer_read(buffer, buffer_get, bytes_up_to_buffer_size);

    buffer->index_read = 0;
    circular_buffer_read(buffer, buffer_get + bytes_up_to_buffer_size, final_index);
    buffer->index_read = final_index;
  } else {

    circular_buffer_read(buffer, buffer_get, buffer_get_size);
    buffer->index_read = final_index; 
  }

  if (!circular_buffer_validate_state(buffer)) {
    return 0;
  }

  return 1;
}


// Entropy pool

static void entropy_pool_debug_print(struct entropy_pool *entropy_pool,
  char *info) {
#ifdef DEBUG_THREAD_ENTROPY_POOL
  pid_t tid = syscall(__NR_gettid);
  fprintf(stderr, "[thread entropy pool] thread ID: %i\n", tid);
  if (info != NULL) {
    fprintf(stderr, "%s\n", info);
  }
  if (entropy_pool != NULL) {
    circular_buffer_debug_print(&entropy_pool->buffer, NULL);
  }
#endif
}

// entropy_pool_on_error manages error handling for entropy pool |entropy_pool|
// when an error is encountered.
// Should be called from top-level functions to minimise double work.
static void entropy_pool_on_error(struct entropy_pool *entropy_pool) {
  entropy_pool_reset(entropy_pool);
}

void entropy_pool_init(struct entropy_pool *entropy_pool) {

  entropy_pool_debug_print(entropy_pool, (char *) "entropy_pool_init()");

  circular_buffer_init(&entropy_pool->buffer);
}

// entropy_pool_reset resets the entropy pool |entropy_pool|.
void entropy_pool_reset(struct entropy_pool *entropy_pool) {
  entropy_pool_debug_print(entropy_pool, (char *) "entropy_pool_reset()");
  circular_buffer_reset(&entropy_pool->buffer);
}

// TODO could optimise this function by just always generating ENTROPY_POOL_ADD_ENTROPY_MAX_SIZE
// but without taking the lock...
int entropy_pool_add_entropy(struct entropy_pool *entropy_pool,
  const uint8_t *entropy, size_t entropy_len) {

  int ret = 0;

  entropy_pool_debug_print(entropy_pool, (char *) "entropy_pool_add_entropy()");


  size_t entropy_max_can_add = circular_buffer_max_can_put(&entropy_pool->buffer);
  if (entropy_max_can_add < entropy_len) {
    goto end;
  }

  if (circular_buffer_put(&entropy_pool->buffer, entropy, entropy_len) != 1) {
    goto end;
  }

  ret = 1;

end:
  if (ret != 1) {
    entropy_pool_on_error(entropy_pool);
  }
  return ret;
}

// entropy_pool_get_entropy writes |buffer_get_size| of entropy from
// |entropy_pool| into |buffer_get|.
// The size of |buffer_get| must be at least |buffer_get_size|.
int entropy_pool_get_entropy(struct entropy_pool *entropy_pool,
  uint8_t *buffer_get, size_t buffer_get_size) {

  entropy_pool_debug_print(entropy_pool, (char *) "entropy_pool_get_entropy()");

  int ret = 0;

  if (buffer_get_size > circular_buffer_max_can_get(&entropy_pool->buffer)) {
    goto end;
  }

  if (circular_buffer_get(&entropy_pool->buffer, buffer_get,
    buffer_get_size) != 1) {
    goto end;
  }

  ret = 1;

end:
  if (ret != 1) {
    entropy_pool_on_error(entropy_pool);
  }
  return ret;
}

#endif
