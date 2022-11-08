// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// PoC implementation of an entropy pool thread.
// This implements a thread that maintains an entropy pool as well as functions
// to retrieve entropy from the entropy pool.
// Implemented as: API --> entropy pool --> circular buffer.

#include "internal.h"

#include "../delocate.h"

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

static void thread_entropy_pool_get_jitter_entropy(uint8_t *out_entropy,
  size_t out_entropy_len);

// Circular buffer implementation

#define CIRCULAR_BUFFER_SIZE 320

// Fixed-sized circular buffer with no overwriting.
// Implementation assumes this is a completely flat representation and
// continuous memory.
//
// Yes, |capacity| is not strictly needed in the current implementation because
// the size of the memory area is known to be CIRCULAR_BUFFFER_SIZE|. But one
// might imagine a dynamic buffer, or a larger buffer but not all space is in
// use. Using |capacity| can allow an easier switch to such alternative
// implementations.
struct circular_buffer {
  size_t capacity;    // Max number of elements in the circular buffer
  size_t index_read;  // Next index to read from (get)
  size_t index_write; // Next index to write to (put)
  size_t count;       // Number of bytes written to buffer
  uint8_t buffer[CIRCULAR_BUFFER_SIZE]; // Continuous memory area
};

// Otherwise a useless circular buffer...
OPENSSL_STATIC_ASSERT(CIRCULAR_BUFFER_SIZE > 0, CIRCULAR_BUFFER_SIZE_must_be_strictly_larger_than_0);

static void circular_buffer_debug_print(struct circular_buffer *buffer,
  char *info) {
#ifdef DEBUG_THREAD_ENTROPY_POOL
  pid_t tid = syscall(__NR_gettid);
  fprint(stderr, "[thread entropy pool] thread ID: %i\n", tid);
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
// circular buffer |buffer|
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

  // If no overflow at all, return 0
  if (index + index_increment < buffer->capacity) {
    return 0;
  }

  // Okay, there is an overflow, we need to wrap around then. Do the calculation
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
  uint8_t *buffer_write, size_t buffer_write_size) {

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
  uint8_t *buffer_put, size_t buffer_put_size) {

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
static bool circular_buffer_max_can_get(struct circular_buffer *buffer) {
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

// Entropy injection latency constants
#define MILLISECONDS_100 INT64_C(100000000)
#define MILLISECONDS_900 INT64_C(900000000)
#define ENTROPY_POOL_THREAD_SLEEP MILLISECONDS_100

#define ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD 128
#define ENTROPY_POOL_ADD_ENTROPY_MAX_SIZE 64

DEFINE_STATIC_MUTEX(g_entropy_pool_lock)
DEFINE_STATIC_MUTEX(g_entropy_pool_start_lock)

struct entropy_pool {
  struct circular_buffer buffer;
};

DEFINE_BSS_GET(struct entropy_pool, dynamic_entropy_pool)

static void entropy_pool_init(void);

static void entropy_pool_init(void) {
  struct entropy_pool *entropy_pool = dynamic_entropy_pool_bss_get();
  circular_buffer_init(&entropy_pool->buffer);
}
OPENSSL_STATIC_ASSERT(ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD <= CIRCULAR_BUFFER_SIZE, something_is_wrong_with_entropy_add_threshold)

static void entropy_pool_reset(struct entropy_pool *entropy_pool) {
  struct CRYPTO_STATIC_MUTEX *const wlock = g_entropy_pool_lock_bss_get();
  CRYPTO_STATIC_MUTEX_lock_write(wlock);
#ifdef DEBUG_THREAD_POOL
  pid_t tid = syscall(__NR_gettid);
      fprintf(stdout, "[entropy pool thread][id: %i] In entropy_pool_reset...................\n", tid);
      fflush(stdout);
#endif
  circular_buffer_reset(&entropy_pool->buffer);
  CRYPTO_STATIC_MUTEX_unlock_write(wlock);
}

// Thread execution might switch to a thread consuming from the entropy pool,
// while executing this function. This 
// But a true solution requires locking in 
// But it will be quickly corrected.
static bool entropy_pool_can_add_entropy(struct entropy_pool *entropy_pool) {
  if (entropy_pool->buffer.count < CIRCULAR_BUFFER_SIZE) {
    return true;
  }
  return false;
}

static int entropy_pool_add_entropy(struct entropy_pool *entropy_pool) {

  int ret = 0;

  struct CRYPTO_STATIC_MUTEX *const wlock = g_entropy_pool_lock_bss_get();
  CRYPTO_STATIC_MUTEX_lock_write(wlock);

  size_t entropy_to_add_size = circular_buffer_max_can_put(&entropy_pool->buffer);

  // Only add ENTROPY_POOL_ADD_ENTROPY_SIZE at a time to decrease thread
  // contention (more entropy takes longer to generate!)
  if (entropy_to_add_size > ENTROPY_POOL_ADD_ENTROPY_MAX_SIZE) {
    entropy_to_add_size = ENTROPY_POOL_ADD_ENTROPY_MAX_SIZE;
  }

  uint8_t static_entropy_buffer[64] = {[0 ... 63] = 0x02};
  thread_entropy_pool_get_jitter_entropy(static_entropy_buffer, entropy_to_add_size);

  if (circular_buffer_put(&entropy_pool->buffer, static_entropy_buffer,
    entropy_to_add_size) != 1) {
    goto end;
  }

  ret = 1;

end:
  CRYPTO_STATIC_MUTEX_unlock_write(wlock);
  return ret;
}

static void entropy_pool_handle_retry(long *backoff);

static void entropy_pool_handle_retry(long *backoff) {
  // Exponential backoff.
  //
  // iteration          delay
  // ---------    -----------------
  //    1         10          nsec
  //    2         100         nsec
  //    3         1,000       nsec
  //    4         10,000      nsec
  //    5         100,000     nsec
  //    6         1,000,000   nsec
  //    7         10,000,000  nsec
  //    8         99,999,999  nsec
  //    9         99,999,999  nsec
  //    ...

  struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 0 };

  // Cap backoff at 99,999,999  nsec, which is the maximum value the nanoseconds
  // field in |timespec| can hold.
  *backoff = AWSLC_MIN((*backoff) * 10, ONE_SECOND - 1);
  // |nanosleep| can mutate |sleep_time|. Hence, we use |backoff| for state.
  sleep_time.tv_nsec = *backoff;

  nanosleep(&sleep_time, &sleep_time);
}

// Should fall back to a direct call to jitter entropy?
static int entropy_pool_get_entropy(struct entropy_pool *entropy_pool,
  uint8_t *buffer_get, size_t buffer_get_size) {

  int ret = 0;
  long backoff = INITIAL_BACKOFF_DELAY;
  struct CRYPTO_STATIC_MUTEX *const wlock = g_entropy_pool_start_lock_bss_get();

  

#ifdef DEBUG_THREAD_POOL
  pid_t tid = syscall(__NR_gettid);
      fprintf(stdout, "[entropy pool thread][id: %i] In entropy_pool_get_entropy\n", tid);
      fflush(stdout);
#endif
retry:
  CRYPTO_STATIC_MUTEX_lock_write(wlock);
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread][id: %i] In entropy_pool_get_entropy have lock\n", tid);
      fflush(stdout);
#endif
  if (buffer_get_size < circular_buffer_max_can_get(&entropy_pool->buffer)) {
    CRYPTO_STATIC_MUTEX_unlock_write(wlock);
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread][id: %i] In entropy_pool_get_entropy released lock and retrying\n", tid);
      fflush(stdout);
#endif
    entropy_pool_handle_retry(&backoff);
    goto retry;
  }

#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread][id: %i] In entropy_pool_get_entropy calling circular_buffer_get()\n", tid);
      fflush(stdout);
#endif
  if (circular_buffer_get(&entropy_pool->buffer, buffer_get,
    buffer_get_size) != 1) {
    goto end;
  }

#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread][id: %i] In entropy_pool_get_entropy finished circular_buffer_get()\n", tid);
      fflush(stdout);
#endif
  ret = 1;

end:
  CRYPTO_STATIC_MUTEX_unlock_write(wlock);
  return ret;
}

static void entropy_pool_on_error(struct entropy_pool *entropy_pool) {
  entropy_pool_reset(entropy_pool);
}

static void * entropy_thread_pool_loop(void *p) {

  size_t iteration_counter = 0;

#ifdef DEBUG_THREAD_POOL
    pid_t tid = syscall(__NR_gettid);
      fprintf(stdout, "[entropy pool thread][id: %i] In new pool thread\n", tid);
      fflush(stdout);
#endif

  entropy_pool_init();

#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread][id: %i] Initialised new entropy pool in thread\n", tid);
      fflush(stdout);
#endif

  while (1) {

    // Let's start from one
    iteration_counter++;

#ifdef DEBUG_THREAD_POOL
    fprintf(stdout, "[entropy pool thread][id: %i] New iteration (%zu)\n\n", tid, iteration_counter);
    fflush(stdout);

    fprintf(stdout, "[entropy pool thread][id: %i] Gathering write lock\n", tid);
    fflush(stdout);
#endif

#ifdef DEBUG_THREAD_POOL
    fprintf(stdout, "[entropy pool thread][id: %i] Checking whether we should add more entropy\n", tid);
    fflush(stdout);
#endif

    if (entropy_pool_can_add_entropy(dynamic_entropy_pool_bss_get())) {

#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread][id: %i] Adding more entropy to the entropy pool\n", tid);
      fflush(stdout);
#endif

      if (entropy_pool_add_entropy(dynamic_entropy_pool_bss_get()) != 1) {

#ifdef DEBUG_THREAD_POOL
        fprintf(stdout, "[entropy pool thread][id: %i] Exit - add_entropy_to_entropy_pool() failed\n", tid);
        fflush(stdout);
#endif
        entropy_pool_on_error(dynamic_entropy_pool_bss_get());
        goto end;     
      }
    }

#ifdef DEBUG_THREAD_POOL
    fprintf(stdout, "[entropy pool thread][id: %i] Releasing write lock\n", tid);
    fflush(stdout);
#endif

#ifdef DEBUG_THREAD_POOL
    fprintf(stdout, "[entropy pool thread][id: %i] Sleeping entropy pool thread\n", tid);
    fflush(stdout);
#endif

    struct timespec entropy_pool_tread_loop_sleep = {.tv_sec = 0, .tv_nsec = ENTROPY_POOL_THREAD_SLEEP };
    if (nanosleep(&entropy_pool_tread_loop_sleep, NULL) != 0) {

#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread][id: %i] Exit - nanosleep() failed\n", tid);
      fflush(stdout);
#endif
      entropy_pool_on_error(dynamic_entropy_pool_bss_get());
      // Some signal interrupted nanosleep(). Just assume this is fatal.
      goto end;       
    }

#ifdef DEBUG_THREAD_POOL
    //if (iteration_counter >= 5) {
    //  goto end;
    //}
#endif
  }

end:
  entropy_pool_reset(dynamic_entropy_pool_bss_get());
  return NULL;
}



// "Public" functions

int thread_entropy_pool_start(void) {

  int ret = 0;

  struct CRYPTO_STATIC_MUTEX *const wlock = g_entropy_pool_start_lock_bss_get();
  CRYPTO_STATIC_MUTEX_lock_write(wlock);

#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] Starting new pool thread\n");
      fflush(stdout);
#endif

  pthread_t thread_id;
  if (pthread_create(&thread_id, NULL, entropy_thread_pool_loop, NULL) != 0) {
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] Exit - pthread_create() failed\n");
      fflush(stdout);
#endif
    goto end;
  }

#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] Started new pool thread\n");
      fflush(stdout);
#endif

  ret = 1;

end:
  CRYPTO_STATIC_MUTEX_unlock_write(wlock);
  return ret;
}

// This needs to be able to retry...
int thread_entropy_pool_get_entropy(uint8_t *buffer_get,
  size_t buffer_get_size) {

  return entropy_pool_get_entropy(dynamic_entropy_pool_bss_get(), buffer_get, buffer_get_size);
}


int test_it(void) {

#if 0
  circular_buffer_reset(&static_circular_buffer);

  circular_buffer_print(&static_circular_buffer);

  uint8_t test_buffer_put[64] = {[0 ... 63] = 0x01};
  if (circular_buffer_put(&static_circular_buffer, test_buffer_put, 64) != 1) {
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] test 1 failed\n");
      fflush(stdout);
#endif
    return 0;
  }

  circular_buffer_print(&static_circular_buffer);

  uint8_t test_buffer_get[64] = {0};
  if (circular_buffer_get(&static_circular_buffer, test_buffer_get, 64) != 1) {
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] test 2 failed\n");
      fflush(stdout);
#endif
    return 0;
  }

  circular_buffer_print(&static_circular_buffer);

#endif
  //entropy_thread_pool_loop(NULL);

  if (thread_entropy_pool_start() != 1) {
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] test 3 failed\n");
      fflush(stdout);
#endif
    return 0;
  }

  uint8_t test_buffer_get[64] = {0};
  if (thread_entropy_pool_get_entropy(test_buffer_get, 64) != 1) {
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] test 4 failed\n");
      fflush(stdout);
#endif
    return  0;
  }

  if (thread_entropy_pool_get_entropy(test_buffer_get, 64) != 1) {
#ifdef DEBUG_THREAD_POOL
      fprintf(stdout, "[entropy pool thread] test 5 failed\n");
      fflush(stdout);
#endif
    return  0;
  }

  return 1;
}

#include "../../../third_party/jitterentropy/jitterentropy.h"

struct jitter_entropy_state {
  struct rand_data *jitter_entropy;
};

DEFINE_BSS_GET(struct jitter_entropy_state, jitter_entropy_state)

static void thread_entropy_pool_get_jitter_entropy(uint8_t *out_entropy, size_t out_entropy_len) {

#ifdef DEBUG_THREAD_POOL_IN_RAND_C
      fprintf(stdout, "[rand.c] RAND_bytes_with_additional_data() 1\n");
      fflush(stdout);
#endif

  struct jitter_entropy_state *jitter_entropy_st = jitter_entropy_state_bss_get();

  if (jitter_entropy_st->jitter_entropy == NULL) {
    // The first parameter passed to |jent_entropy_collector_alloc| function is
    // the desired oversampling rate. Passing a 0 tells Jitter module to use
    // the default rate (which is 3 in Jitter v3.1.0).
    jitter_entropy_st->jitter_entropy = jent_entropy_collector_alloc(0, JENT_FORCE_FIPS);
    if (jitter_entropy_st->jitter_entropy == NULL) {
      abort();
    }
  }

  // Every thread has its own Jitter instance so we fetch the one assigned
  // to the current thread.
  if (jitter_entropy_st == NULL || jitter_entropy_st->jitter_entropy == NULL) {
    abort();
  }

#ifdef DEBUG_THREAD_POOL_IN_RAND_C
      fprintf(stdout, "[rand.c] calling jent_read_entropy_safe\n");
      fflush(stdout);
#endif
  // Generate the required number of bytes with Jitter.
  if (jent_read_entropy_safe(&jitter_entropy_st->jitter_entropy, (char *) out_entropy,
                             out_entropy_len) != (ssize_t) out_entropy_len) {
    abort();
  }
#ifdef DEBUG_THREAD_POOL_IN_RAND_C
      fprintf(stdout, "[rand.c] finished jent_read_entropy_safe\n");
      fflush(stdout);
#endif
}
