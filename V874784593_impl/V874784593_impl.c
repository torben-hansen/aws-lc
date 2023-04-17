

#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>

#include <openssl/evp.h>

#define ERROR_SUCCESS 1
#define ERROR_INVALID_PARAMETER 2
#define ERROR_CIPHER_CONTEXT_INITIALIZATION_FAILURE 3
#define ERROR_CIPHER_PADDING_FAILURE 4
#define ERROR_CIPHER_UPDATE_FAILURE 5

#define SECTOR_SIZE 512
#define AES_XTS_MINIMUM_BUFFER_SIZE 16

void update_initialization_vector(uint64_t offset, unsigned char *iv)
{
    int i = 0;
    for (; i < 8; i++) {
        uint8_t index = offset;
        iv[i] = index;
        offset = offset >> 8;
    }
}

// IMPLEMENTATION

int encrypt(
    const unsigned char* encryption_key,
    uint64_t sector_no,
    const unsigned char* input_buffer,
    unsigned char* output_buffer,
    int buffer_length
)
{
    unsigned char iv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    int error = ERROR_SUCCESS;
    int buffer_offset = 0;
    int output_buffer_len;


    if (input_buffer == NULL || output_buffer == NULL || buffer_length <= 0) {
        return ERROR_INVALID_PARAMETER;
    }

    if (buffer_length % SECTOR_SIZE != 0) {
        return ERROR_INVALID_PARAMETER;
    }

    EVP_CIPHER_CTX *ctx_encrypt = EVP_CIPHER_CTX_new();

    uint64_t current_sector_no = sector_no;
    int totalSectors = buffer_length / SECTOR_SIZE;

#if defined(ONLY_ONE_KEY_INIT)
        if (!EVP_EncryptInit_ex(ctx_encrypt, EVP_aes_256_xts(), NULL, encryption_key, NULL)) {
            error = ERROR_CIPHER_CONTEXT_INITIALIZATION_FAILURE;
            return error;
        }
        EVP_CIPHER_CTX_set_padding(ctx_encrypt, 0);
#endif


    for (int iter = 0; iter < totalSectors; iter++)
    {

        update_initialization_vector(current_sector_no, iv);
#if defined(ONLY_ONE_KEY_INIT)
        if (!EVP_EncryptInit_ex(ctx_encrypt, NULL, NULL, NULL, iv)) {
            error = ERROR_CIPHER_CONTEXT_INITIALIZATION_FAILURE;
            break;
        }
#else
        if (!EVP_EncryptInit_ex(ctx_encrypt, EVP_aes_256_xts(), NULL, encryption_key, iv)) {
            error = ERROR_CIPHER_CONTEXT_INITIALIZATION_FAILURE;
            break;
        }

        EVP_CIPHER_CTX_set_padding(ctx_encrypt, 0);
#endif


        if (!EVP_EncryptUpdate(
            ctx_encrypt,
            output_buffer + buffer_offset,
            &output_buffer_len,
            input_buffer + buffer_offset,
            SECTOR_SIZE
        )) {
            error = ERROR_CIPHER_UPDATE_FAILURE;
            break;
        }

        if (output_buffer_len != SECTOR_SIZE) {
            error = ERROR_CIPHER_PADDING_FAILURE;
            break;
        }

        buffer_offset += SECTOR_SIZE;
        current_sector_no++;
    }

    EVP_CIPHER_CTX_free(ctx_encrypt);
    return error;
}



// PERFORMANCE MEASUREMENT

static uint64_t g_timeout_seconds = 1;

static uint64_t time_now() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  uint64_t ret = ts.tv_sec;
  ret *= 1000000;
  ret += ts.tv_nsec / 1000;
  return ret;
}

void perf_impl(void) {
    const unsigned char encryption_key[] = 
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // the two keys must be different!
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    uint64_t sector_no = 0;

#define NUMBER_OF_SECTORS 1024
    unsigned char* input_buffer = malloc(NUMBER_OF_SECTORS * SECTOR_SIZE);
    unsigned char* output_buffer = malloc(NUMBER_OF_SECTORS * SECTOR_SIZE);


  // total_us is the total amount of time that we'll aim to measure a function
  // for.
  const uint64_t total_us = g_timeout_seconds * 1000000;
  uint64_t start = time_now(), now, delta;

    int error = 1;
    if ((error = encrypt(encryption_key, sector_no, (const unsigned char*)input_buffer, output_buffer, NUMBER_OF_SECTORS * SECTOR_SIZE)) != ERROR_SUCCESS) {
        fprintf(stderr, "Ouch, error! error = %i\n", error);
        free(input_buffer);
        free(output_buffer);
        abort();
    }
  now = time_now();
  delta = now - start;
  unsigned iterations_between_time_checks;
  if (delta == 0) {
    iterations_between_time_checks = 250;
  } else {
    // Aim for about 100ms between time checks.
    iterations_between_time_checks =
        (double)100000 / (double)delta;
    if (iterations_between_time_checks > 1000) {
      iterations_between_time_checks = 1000;
    } else if (iterations_between_time_checks < 1) {
      iterations_between_time_checks = 1;
    }
  }

  // Don't include the time taken to run |func| to calculate
  // |iterations_between_time_checks|
  start = time_now();
  uint64_t done = 0;
  for (;;) {
    for (unsigned i = 0; i < iterations_between_time_checks; i++) {
        if ((error = encrypt(encryption_key, sector_no, (const unsigned char*)input_buffer, output_buffer, NUMBER_OF_SECTORS * SECTOR_SIZE)) != ERROR_SUCCESS) {
            fprintf(stderr, "Ouch, error! error = %i\n", error);
            free(input_buffer);
            free(output_buffer);
            abort();
        }
        done++;
    }

    now = time_now();
    if (now - start > total_us) {
      break;
    }
  }

    fprintf(stderr, "Did %" PRIu64 " operations in %" PRIu64 "us (%.1f ops/sec)\n",
          done, now - start, ((double)done / ((double)(now - start))) * 1000000);

}

int main() {
    perf_impl();
    return 1;
}
