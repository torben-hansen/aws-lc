// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// PoC implementation of entropy pool thread and client.
// This contains an implementation of a thread that maintains an entropy pool
// as well as client functions to retrieve entropy from the entropy pool thread.

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

	entropy_pool_state.index_first_unavailable_byte_index

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





// reinit_thread_pool
// after a fork for example

// main entropy pool loop
// define state model

// Pool is just an array
// Should be maintained here

// lazy init pool in new process
// First time called, don't fill pool
// just generate enough entropy to fullfill request

