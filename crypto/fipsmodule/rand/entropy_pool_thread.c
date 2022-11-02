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

struct circular_buffer static_circular_buffer = {
	.capacity = CIRCULAR_BUFFER_SIZE,
	.index_read = 0,
	.index_write = 0,
	.count = 0,
	.buffer = { 0 },
};

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

static uint8_t static_entropy_buffer[64] = {[0 ... 63] = 0x02};

struct entropy_pool {
	struct circular_buffer *buffer;
};

struct entropy_pool static_entropy_pool = {
	.buffer = &static_circular_buffer,
};
OPENSSL_STATIC_ASSERT(ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD <= CIRCULAR_BUFFER_SIZE, something_is_wrong_with_entropy_add_threshold)

static void entropy_pool_reset(struct entropy_pool *entropy_pool) {
	circular_buffer_reset(entropy_pool->buffer);
}

static bool entropy_pool_should_add_entropy(struct entropy_pool *entropy_pool) {
	if (entropy_pool->buffer->count < ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD) {
		return true;
	}
	return false;
}

static int entropy_pool_add_entropy(struct entropy_pool *entropy_pool) {

	size_t entropy_to_add_size = circular_buffer_max_can_put(entropy_pool->buffer);

	// Only add ENTROPY_POOL_ADD_ENTROPY_SIZE at a time to decrease thread
	// contention (more entropy takes longer to generate!)
	if (entropy_to_add_size > ENTROPY_POOL_ADD_ENTROPY_MAX_SIZE) {
		entropy_to_add_size = ENTROPY_POOL_ADD_ENTROPY_MAX_SIZE;
	}

	if (circular_buffer_put(entropy_pool->buffer, static_entropy_buffer,
		entropy_to_add_size) != 1) {
		return 0;
	}

	return 1;
}

static void entropy_pool_on_error(struct entropy_pool *entropy_pool) {
	entropy_pool_reset(entropy_pool);
}

static int entropy_thread_pool_loop(void);

static int entropy_thread_pool_loop(void) {

	int ret = 0;

	// Use lock for the entire existence of this thread
	struct CRYPTO_STATIC_MUTEX *const wlock = g_entropy_pool_lock_bss_get();

	size_t iteration_counter = 0;

	entropy_pool_reset(&static_entropy_pool);
	
	while (1) {

		// Let's start from one
		iteration_counter++;

#ifdef DEBUG_THREAD_POOL
 		fprintf(stdout, "[entropy pool thread] New iteration (%zu)\n\n", iteration_counter);
 		fflush(stdout);

 		fprintf(stdout, "[entropy pool thread] Gathering write lock\n");
 		fflush(stdout);
#endif

		CRYPTO_STATIC_MUTEX_lock_write(wlock);


#ifdef DEBUG_THREAD_POOL
 		fprintf(stdout, "[entropy pool thread] Checking whether we should add more entropy\n");
 		fflush(stdout);
#endif

		if (entropy_pool_should_add_entropy(&static_entropy_pool)) {

#ifdef DEBUG_THREAD_POOL
	 		fprintf(stdout, "[entropy pool thread] Adding more entropy to the entropy pool\n");
 			fflush(stdout);
#endif

			if (entropy_pool_add_entropy(&static_entropy_pool) != 1) {

#ifdef DEBUG_THREAD_POOL
		 		fprintf(stdout, "[entropy pool thread] Exit - add_entropy_to_entropy_pool() failed\n");
		 		fflush(stdout);
#endif
		 		entropy_pool_on_error(&static_entropy_pool);
				CRYPTO_STATIC_MUTEX_unlock_write(wlock);
				goto end;			
			}
		}

#ifdef DEBUG_THREAD_POOL
 		fprintf(stdout, "[entropy pool thread] Releasing write lock\n");
 		fflush(stdout);
#endif

		// Must release lock before sleeping thread.
 		CRYPTO_STATIC_MUTEX_unlock_write(wlock);

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
 			entropy_pool_on_error(&static_entropy_pool);
 			// Some signal interrupted nanosleep(). Just assume this is fatal.
			goto end; 			
 		}

#ifdef DEBUG_THREAD_POOL
 		if (iteration_counter >= 5) {
 			goto end;
 		}
#endif
	}

	ret = 1; // Somehow we need to be able to actually kill this thread...

end:
	entropy_pool_reset(&static_entropy_pool);
	return ret;
}


int test_it(void) {
	circular_buffer_reset(&static_circular_buffer);

	circular_buffer_print(&static_circular_buffer);

	uint8_t test_buffer_put[64] = {[0 ... 63] = 0x01};
	if (circular_buffer_put(&static_circular_buffer, test_buffer_put, 64) != 1) {
		return 0;
	}

	circular_buffer_print(&static_circular_buffer);

	uint8_t test_buffer_get[64] = {0};
	if (circular_buffer_get(&static_circular_buffer, test_buffer_get, 64) != 1) {
		return 0;
	}

	circular_buffer_print(&static_circular_buffer);

	entropy_thread_pool_loop();

	return 1;
}


// Internally exported functions



#if 0

#include <openssl/base.h>

#include <time.h>

// 5x64 bytes. Pretty randomly chosen...
#define ENTROPY_POOL_THREAD_LENGTH_BYTES 320
#define ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD 128
#define ENTROPY_POOL_ADD_ENTROPY_SIZE 64

// Gonna try out 100ms first
#define MILLISECONDS_100 INT64_C(100000000)
#define MILLISECONDS_900 INT64_C(900000000)

#define ENTROPY_POOL_THREAD_SLEEP MILLISECONDS_900


OPENSSL_STATIC_ASSERT(ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD <= ENTROPY_POOL_THREAD_LENGTH_BYTES, something_is_wrong_with_entropy_add_threshold)

DEFINE_STATIC_MUTEX(g_entropy_pool_lock)

enum entropy_pool_state_values {
	NOT_INITIALIZED,
	INITIALIZED,
	ERROR,
};

// Circular buffer
struct entropy_pool {
	size_t capacity;
	size_t bytes_available;
	size_t bytes_unavailable;
	size_t index_first_available_byte_index; // First available byte
	size_t index_first_unavailable_byte_index;
	uint8_t pool[ENTROPY_POOL_THREAD_LENGTH_BYTES];
	bool add_more_entropy;
	enum entropy_pool_state_values state;
};

static struct entropy_pool entropy_pool_state = {
	.capacity = ENTROPY_POOL_THREAD_LENGTH_BYTES,
	.bytes_available = 0,
	.bytes_unavailable = ENTROPY_POOL_THREAD_LENGTH_BYTES,
	.index_first_available_byte_index = 0,
	.index_first_unavailable_byte_index = 0,
	.pool = { 0 },
	.add_more_entropy = true,
	.state = NOT_INITIALIZED,
};

static bool entropy_pool_is_initialised(void);
static bool entropy_pool_is_error(void);
static void entropy_pool_at_error(void);
static void reset_entropy_pool(void);
static int add_entropy_to_entropy_pool(void);
static int entropy_pool_loop(void);

static bool entropy_pool_is_initialised(void) {
	if (entropy_pool_state.state == INITIALIZED) {
		return true;
	}
	fprintf(stdout, "[entropy pool thread] entropy pool state not initialised\n");
	fflush(stdout);
	return false;
}

static bool entropy_pool_is_error(void) {
	if (entropy_pool_state.state == ERROR) {
		fprintf(stdout, "[entropy pool thread] entropy pool state in error\n");
		fflush(stdout);
		return true;
	}
	return false;
}

static bool entropy_pool_should_add_entropy(void) {
	if (entropy_pool_state.bytes_available < ENTROPY_POOL_THREAD_ADD_ENTROPY_THRESHOLD) {
		return true;
	}
	return false;
}

static void entropy_pool_at_error(void) {
	reset_entropy_pool();
	entropy_pool_state.state = ERROR;
}

static void reset_entropy_pool(void) {
	memset(entropy_pool_state.pool, 0, sizeof(entropy_pool_state.pool));
	entropy_pool_state.bytes_available = 0;
	entropy_pool_state.bytes_unavailable = ENTROPY_POOL_THREAD_LENGTH_BYTES;
	entropy_pool_state.index_first_available_byte_index = 0;
	entropy_pool_state.index_first_unavailable_byte_index = 0;
	entropy_pool_state.add_more_entropy = true;
}

static bool entropy_pool_ensure_can_add_entropy(size_t length_of_entropy_to_add) {
	if (length_of_entropy_to_add <= entropy_pool_state.bytes_unavailable) {
		return true;
	}
	return false;
}


// Managing the circular buffer here is pretty complex...
static int add_entropy_to_entropy_pool(void) {

	if (entropy_pool_ensure_can_add_entropy(ENTROPY_POOL_ADD_ENTROPY_SIZE) == false) {
		// This is not an error. We just have too much available entropy in the
		// pool already.
		return 1
	}

	uint8_t fake_entropy[ENTROPY_POOL_ADD_ENTROPY_SIZE] = { 0 };

	// Do we need to wrap around the circular buffer?
	size_t bytes_available_up_to_max_index = (entropy_pool_state.capacity - 1) - entropy_pool_state.index_first_unavailable_byte_index;
	size_t number_of_bytes_that_wraps_around = 0;
	if (bytes_available_up_to_max_index < ENTROPY_POOL_ADD_ENTROPY_SIZE) {
		// Yes, we need to wrap around
		number_of_bytes_that_wraps_around = ENTROPY_POOL_ADD_ENTROPY_SIZE - bytes_available_up_to_max_index;
	}

	// Now copy bytes into the circular buffer
	memcpy(&entropy_pool_state.pool[entropy_pool_state.index_first_unavailable_byte_index],
			fake_entropy,
			ENTROPY_POOL_ADD_ENTROPY_SIZE - number_of_bytes_that_wraps_around);

	if (number_of_bytes_that_wraps_around != 0) {
		entropy_pool_state.index_first_unavailable_byte_index = 0;		
	}

	memcpy(&entropy_pool_state.pool[entropy_pool_state.index_first_unavailable_byte_index],
			fake_entropy,
			number_of_bytes_that_wraps_around);

	entropy_pool_state.index_first_unavailable_byte_index = number_of_bytes_that_wraps_around;

	return 1;
}

static int entropy_pool_loop(void) {

	int ret = 0;

	if (entropy_pool_is_initialised() == false) {
		entropy_pool_at_error();
		goto end;
	}

	struct CRYPTO_STATIC_MUTEX *const wlock = g_entropy_pool_lock_bss_get();

	size_t iteration_counter = 0;
	
	while (1) {

		// Let's start from one
		iteration_counter++;

 		fprintf(stdout, "\n[entropy pool thread] New iteration (%zu)\n\n", iteration_counter);
 		fflush(stdout);

 		fprintf(stdout, "[entropy pool thread] Gathering write lock\n");
 		fflush(stdout);

		CRYPTO_STATIC_MUTEX_lock_write(wlock);

 		fprintf(stdout, "[entropy pool thread] Checking whether in error state\n");
 		fflush(stdout);

		if (entropy_pool_is_error() == true) {
	 		fprintf(stdout, "[entropy pool thread] Exit - in error state\n");
	 		fflush(stdout);
			CRYPTO_STATIC_MUTEX_unlock_write(wlock);
			entropy_pool_at_error();
			goto end;
		}

 		fprintf(stdout, "[entropy pool thread] Checking whether we should add more entropy\n");
 		fflush(stdout);

		if (entropy_pool_should_add_entropy() == true) {
	 		fprintf(stdout, "[entropy pool thread] Adding more entropy to the entropy pool\n");
 			fflush(stdout);

			if (add_entropy_to_entropy_pool() == 0) {
		 		fprintf(stdout, "[entropy pool thread] Exit - add_entropy_to_entropy_pool() failed\n");
		 		fflush(stdout);
				CRYPTO_STATIC_MUTEX_unlock_write(wlock);
				entropy_pool_at_error();
				goto end;			
			}
		}

 		fprintf(stdout, "[entropy pool thread] Releasing write lock\n");
 		fflush(stdout);

		// Must release lock before sleeping thread.
 		CRYPTO_STATIC_MUTEX_unlock_write(wlock);

 		fprintf(stdout, "[entropy pool thread] Sleeping entropy pool thread\n");
 		fflush(stdout);

 		struct timespec entropy_pool_tread_loop_sleep = {.tv_sec = 0, .tv_nsec = ENTROPY_POOL_THREAD_SLEEP };
 		if (nanosleep(&entropy_pool_tread_loop_sleep, NULL) != 0) {
 	 		fprintf(stdout, "[entropy pool thread] Exit - nanosleep() failed\n");
 			fflush(stdout);
 			// Some signal interrupted nanosleep(). Just assume this is fatal.
			entropy_pool_at_error();
			goto end; 			
 		}
	}

	ret = 1; // Somehow we need to be able to actually kill this thread...

end:
	return ret;
}

int init_entropy_pool(void) {
	reset_entropy_pool();
	entropy_pool_state.state = INITIALIZED;
	return 1;
}

int start_entropy_pool_thread(void) {
	return entropy_pool_loop();
}

int get_entropy_from_entropy_pool(size_t requested_entropy_length) {


	return 1;
}


#endif


// reinit_thread_pool
// after a fork for example

// main entropy pool loop
// define state model

// Pool is just an array
// Should be maintained here

// lazy init pool in new process
// First time called, don't fill pool
// just generate enough entropy to fullfill request

