// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// PoC implementation of entropy pool thread and client.
// This contains an implementation of a thread that maintains an entropy pool
// as well as client functions to retrieve entropy from the entropy pool thread.



/*
Implement as follows

public API
--> business logic (start, stop, manage the different operations, what to do at fork, etc)
--> manage the pool
--> Pool implementation API (implemented using a circular buffer)
--> Circular buffer implementation API




*/

#if 0
static void print_debug(char *debug_statement) {
#if DEBUG_ENTROPY_THREAD
	fprintf(stderr, "%s\n", debug_statement);
	fflush(stdout);
#else
	(void *) debug_statement;
#endif
}
#endif

#include "internal.h"

#include <pthread.h>
#include <unistd.h>


#define DEBUG_THREAD_POOL 1

// Circular buffer

#define CIRCULAR_BUFFER_SIZE 320

// Fixed-sized circular buffer with no overwriting.
// Implementation assumes this is a completely flat representation.
struct circular_buffer {
	size_t capacity; // Max number of elements in the circular buffer
	size_t index_read;
	size_t index_write;
	size_t count;
	uint8_t buffer[CIRCULAR_BUFFER_SIZE];
};

#if 0
// doesn't work in fips mode....
struct circular_buffer static_circular_buffer = {
	.capacity = CIRCULAR_BUFFER_SIZE,
	.index_read = 0,
	.index_write = 0,
	.count = 0,
	.buffer = { 0 },
}
#endif

static void circular_buffer_init(struct circular_buffer *circular_buffer);

static void circular_buffer_init(struct circular_buffer *circular_buffer) {
	circular_buffer->capacity = CIRCULAR_BUFFER_SIZE;
	circular_buffer->index_read = 0;
	circular_buffer->index_write = 0;
	circular_buffer->count = 0;
	memset(circular_buffer->buffer, 0, CIRCULAR_BUFFER_SIZE);
}

static void circular_buffer_print(struct circular_buffer *buffer) {
	fprintf(stderr, "capacity: %zu\n", buffer->capacity);
	fprintf(stderr, "index_read: %zu\n", buffer->index_read);
	fprintf(stderr, "index_write: %zu\n", buffer->index_write);
	fprintf(stderr, "count: %zu\n", buffer->count);
	printf("\n");
	for (size_t i = 0; i < CIRCULAR_BUFFER_SIZE; i++) {
		printf("0x%.2X ", buffer->buffer[i]);
	}
	printf("\n");	
}

static void circular_buffer_reset(struct circular_buffer *buffer) {
	// Assumes flat representation.
	memset(buffer, 0, sizeof(*buffer));
	buffer->capacity = CIRCULAR_BUFFER_SIZE;
}

static bool circular_buffer_validate(struct circular_buffer *buffer) {
	// Evaluate state of the circular buffer e.g. count can never be bigger than sizeof(buffer->buffer)...
	// Difference between read and write should be the count.
	circular_buffer_print(buffer);
	return true;
}

static size_t circular_buffer_compute_overflow(struct circular_buffer *buffer,
	size_t index, size_t increment_size) {

	OPENSSL_STATIC_ASSERT(sizeof(buffer->buffer) == CIRCULAR_BUFFER_SIZE, circular_buffer_size_is_not_CIRCULAR_BUFFER_SIZE)

	// Need to statically ensure that index+increment_size doesn't overflow the type size...

	// If no overflow at all, return 0
	if (index + increment_size < CIRCULAR_BUFFER_SIZE) {
		return 0;
	}

	// Okay, there is an overflow, return that size then...
	return (index + increment_size) % CIRCULAR_BUFFER_SIZE;
}

static size_t circular_buffer_max_can_put(struct circular_buffer *buffer) {
	return buffer->capacity - buffer->count;
}

static void circular_buffer_write_and_update(struct circular_buffer *buffer,
	uint8_t *buffer_put, size_t buffer_put_size) {

	memcpy(buffer->buffer + buffer->index_write, buffer_put, buffer_put_size);
	OPENSSL_STATIC_ASSERT(CIRCULAR_BUFFER_SIZE > 0, CIRCULAR_BUFFER_SIZE_must_be_strictly_larger_than_0);
	// Need to statically ensure that buffer->index_write + buffer_put_size doesn't overflow...
	buffer->index_write = (buffer->index_write + buffer_put_size) % (CIRCULAR_BUFFER_SIZE - 1);
	buffer->count = buffer->count + buffer_put_size;
}

static int circular_buffer_put(struct circular_buffer *buffer,
	uint8_t *buffer_put, size_t buffer_put_size) {

	if (buffer_put_size > circular_buffer_max_can_put(buffer)) {
		// Can't satisfy put operation
		return 0;
	}

	size_t size_after_overflow = circular_buffer_compute_overflow(buffer,
		buffer->index_write, buffer_put_size);
	size_t size_up_to_overflow = buffer_put_size - size_after_overflow;

	assert(buffer_put_size = (size_after_overflow + size_up_to_overflow));

	circular_buffer_write_and_update(buffer, buffer_put, size_up_to_overflow);
	if (size_after_overflow > 0) {
		circular_buffer_write_and_update(buffer,
			buffer_put + size_up_to_overflow, size_after_overflow);
	}

	if (!circular_buffer_validate(buffer)) {
		return 0;
	}

	return 1;
}

static bool circular_buffer_can_get(struct circular_buffer *buffer,
	size_t want_to_get_count) {
	if (want_to_get_count <= buffer->count) {
		return true;
	}
	return false;
}

static void circular_buffer_get_and_update(struct circular_buffer *buffer,
	uint8_t *buffer_get, size_t buffer_get_size) {

	memcpy(buffer_get, buffer->buffer + buffer->index_read, buffer_get_size);
	memset(buffer->buffer + buffer->index_read, 0, buffer_get_size);
	OPENSSL_STATIC_ASSERT(CIRCULAR_BUFFER_SIZE > 0, CIRCULAR_BUFFER_SIZE_must_be_strictly_larger_than_0);
	// Need to statically ensure that buffer->index_write + buffer_get_size doesn't overflow...
	buffer->index_read = (buffer->index_read + buffer_get_size) % (CIRCULAR_BUFFER_SIZE - 1);
	buffer->count = buffer->count - buffer_get_size;
}

// |buffer_get| must be at least |buffer_get_size| in size
static int circular_buffer_get(struct circular_buffer *buffer,
	uint8_t *buffer_get, size_t buffer_get_size) {

	if (!circular_buffer_can_get(buffer, buffer_get_size)) {
		// Can't satisfy get operation
		return 0;
	}

	size_t overflow_size = circular_buffer_compute_overflow(buffer,
		buffer->index_read, buffer_get_size);
	size_t size_up_to_overflow = buffer_get_size - overflow_size;

	assert(buffer_get_size = (overflow_size + size_up_to_overflow));

	circular_buffer_get_and_update(buffer, buffer_get, size_up_to_overflow);
	if (overflow_size > 0) {
		circular_buffer_get_and_update(buffer,
			buffer_get + size_up_to_overflow, overflow_size);
	}

	if (!circular_buffer_validate(buffer)) {
		return 0;
	}

	return 1;
}


// Entropy pool

// Entropy injection latency constants
#define MILLISECONDS_100 INT64_C(100000000)
#define MILLISECONDS_900 INT64_C(900000000)
#define ENTROPY_POOL_THREAD_SLEEP MILLISECONDS_900

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
	circular_buffer_reset(&entropy_pool->buffer);
	CRYPTO_STATIC_MUTEX_unlock_write(wlock);
}

// Thread execution might switch to a thread consuming from the entropy pool,
// while executing this function. This 
// But a true solution requires locking in 
// But it will be quickly corrected.
static bool entropy_pool_should_add_entropy(struct entropy_pool *entropy_pool) {
	if (entropy_pool->buffer.count < ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD) {
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
	get_jitter_entropy(static_entropy_buffer, entropy_to_add_size);

	if (circular_buffer_put(&entropy_pool->buffer, static_entropy_buffer,
		entropy_to_add_size) != 1) {
		goto end;
	}

	ret = 1;

end:
	CRYPTO_STATIC_MUTEX_unlock_write(wlock);
	return ret;
}

static void entropy_pool_handle_rety(long *backoff);

static void entropy_pool_handle_rety(long *backoff) {
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

static int entropy_pool_get_entropy(struct entropy_pool *entropy_pool,
	uint8_t *buffer_get, size_t buffer_get_size) {

	int ret = 0;
	long backoff = INITIAL_BACKOFF_DELAY;
	struct CRYPTO_STATIC_MUTEX *const wlock = g_entropy_pool_start_lock_bss_get();

#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] In entropy_pool_get_entropy\n");
 			fflush(stdout);
#endif
retry:
	CRYPTO_STATIC_MUTEX_lock_write(wlock);
#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] In entropy_pool_get_entropy have lock\n");
 			fflush(stdout);
#endif
	if (!circular_buffer_can_get(&entropy_pool->buffer, buffer_get_size)) {
		CRYPTO_STATIC_MUTEX_unlock_write(wlock);
#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] In entropy_pool_get_entropy released lock and retrying\n");
 			fflush(stdout);
#endif
		entropy_pool_handle_rety(&backoff);
		goto retry;
	}

#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] In entropy_pool_get_entropy calling circular_buffer_get()\n");
 			fflush(stdout);
#endif
	if (circular_buffer_get(&entropy_pool->buffer, buffer_get,
		buffer_get_size) != 1) {
		goto end;
	}

#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] In entropy_pool_get_entropy finished circular_buffer_get()\n");
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

void * entropy_thread_pool_loop(void *p);

void * entropy_thread_pool_loop(void *p) {

	size_t iteration_counter = 0;

#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] In new pool thread\n");
 			fflush(stdout);
#endif

	entropy_pool_init();

#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] Initialised new entropy pool in thread\n");
 			fflush(stdout);
#endif

	while (1) {

		// Let's start from one
		iteration_counter++;

#ifdef DEBUG_THREAD_POOL
 		fprintf(stdout, "[entropy pool thread] New iteration (%zu)\n\n", iteration_counter);
 		fflush(stdout);

 		fprintf(stdout, "[entropy pool thread] Gathering write lock\n");
 		fflush(stdout);
#endif

#ifdef DEBUG_THREAD_POOL
 		fprintf(stdout, "[entropy pool thread] Checking whether we should add more entropy\n");
 		fflush(stdout);
#endif

		if (entropy_pool_should_add_entropy(dynamic_entropy_pool_bss_get())) {

#ifdef DEBUG_THREAD_POOL
	 		fprintf(stdout, "[entropy pool thread] Adding more entropy to the entropy pool\n");
 			fflush(stdout);
#endif

			if (entropy_pool_add_entropy(dynamic_entropy_pool_bss_get()) != 1) {

#ifdef DEBUG_THREAD_POOL
		 		fprintf(stdout, "[entropy pool thread] Exit - add_entropy_to_entropy_pool() failed\n");
		 		fflush(stdout);
#endif
		 		entropy_pool_on_error(dynamic_entropy_pool_bss_get());
				goto end;			
			}
		}

#ifdef DEBUG_THREAD_POOL
 		fprintf(stdout, "[entropy pool thread] Releasing write lock\n");
 		fflush(stdout);
#endif

#ifdef DEBUG_THREAD_POOL
 		fprintf(stdout, "[entropy pool thread] Sleeping entropy pool thread\n");
 		fflush(stdout);
#endif

 		struct timespec entropy_pool_tread_loop_sleep = {.tv_sec = 0, .tv_nsec = ENTROPY_POOL_THREAD_SLEEP };
 		if (nanosleep(&entropy_pool_tread_loop_sleep, NULL) != 0) {

#ifdef DEBUG_THREAD_POOL
 	 		fprintf(stdout, "[entropy pool thread] Exit - nanosleep() failed\n");
 			fflush(stdout);
#endif
 			entropy_pool_on_error(dynamic_entropy_pool_bss_get());
 			// Some signal interrupted nanosleep(). Just assume this is fatal.
			goto end; 			
 		}

#ifdef DEBUG_THREAD_POOL
 		if (iteration_counter >= 5) {
 			goto end;
 		}
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
