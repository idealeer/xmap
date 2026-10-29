/* cc -std=gnu99 -g -fsanitize=address,undefined tests/bloom_memory.c -lm -o /tmp/bloom_memory */
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

static int fail_allocation;
static size_t requested_bytes;
static void *test_calloc(size_t count, size_t size) {
    requested_bytes = count * size;
    if (fail_allocation) {
        errno = ENOMEM;
        return NULL;
    }
    return calloc(count, size);
}

#define calloc test_calloc
#include "../lib/bloom.c"
#undef calloc

int main(void) {
    BloomFilter bf;
    uint64_t hashes[64] = {0};
    fail_allocation = 1;
    assert(bloom_filter_init(&bf, 500000000, 1e-5f) == BLOOM_FAILURE);
    assert(errno == ENOMEM);
    assert(bf.bloom == NULL);
    assert(requested_bytes > 1400000000 && requested_bytes < 1600000000);
    assert(bloom_filter_check_string(&bf, "test", 4) == BLOOM_FAILURE);
    assert(bloom_filter_add_string_alt(&bf, hashes, 64) == BLOOM_FAILURE);
    bloom_filter_destroy(&bf);

    fail_allocation = 0;
    assert(bloom_filter_init(&bf, 10000, 1e-5f) == BLOOM_SUCCESS);
    assert(requested_bytes < 40000);
    assert(bloom_filter_check_string(&bf, "test", 4) == BLOOM_FAILURE);
    assert(bloom_filter_add_string(&bf, "test", 4) == BLOOM_SUCCESS);
    assert(bloom_filter_check_string(&bf, "test", 4) == BLOOM_SUCCESS);
    fail_allocation = 1;
    assert(bloom_filter_add_string(&bf, "test", 4) == BLOOM_FAILURE);
    assert(bloom_filter_check_string(&bf, "test", 4) == BLOOM_FAILURE);
    fail_allocation = 0;
    char *hex = bloom_filter_export_hex_string(&bf);
    bloom_filter_destroy(&bf);
    fail_allocation = 1;
    assert(bloom_filter_import_hex_string_alt(&bf, hex, NULL) == BLOOM_FAILURE);
    bloom_filter_destroy(&bf);
    fail_allocation = 0;
    assert(bloom_filter_import_hex_string_alt(&bf, hex, NULL) == BLOOM_SUCCESS);
    assert(bloom_filter_check_string(&bf, "test", 4) == BLOOM_SUCCESS);
    bloom_filter_destroy(&bf);
    free(hex);

    assert(bloom_filter_init(&bf, 0, 1e-5f) == BLOOM_FAILURE);
    assert(errno == EINVAL);
    bloom_filter_destroy(&bf);
    assert(bloom_filter_init(&bf, UINT64_MAX, 1e-5f) == BLOOM_FAILURE);
    assert(errno == EOVERFLOW);
    bloom_filter_destroy(&bf);
    assert(bloom_filter_init(&bf, 10000, NAN) == BLOOM_FAILURE);
    bloom_filter_destroy(&bf);
    assert(bloom_filter_init(&bf, 10000, INFINITY) == BLOOM_FAILURE);
    bloom_filter_destroy(&bf);
    assert(bloom_filter_init(&bf, 1, 0.99f) == BLOOM_SUCCESS);
    assert(bf.number_hashes >= 1 && bf.number_bits >= 1);
    bloom_filter_destroy(&bf);
    puts("Bloom memory regression tests passed");
    return 0;
}
