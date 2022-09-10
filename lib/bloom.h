/*******************************************************************************
***
***     Author: Tyler Barrus
***     email:  barrust@gmail.com
***
***     Version: 1.8.0
***     Purpose: Simple, yet effective, bloom filter implementation
***
***     License: MIT 2015
***
***     URL: https://github.com/barrust/bloom
***
***     change: add arg: len at 09/08/2020
***     int bloom_filter_add_string(BloomFilter *bf, const char *str, int len);
*******************************************************************************/
#ifndef BARRUST_BLOOM_FILTER_H__
#define BARRUST_BLOOM_FILTER_H__

#include <inttypes.h> /* PRIu64 */
#include <stdio.h>

/* https://gcc.gnu.org/onlinedocs/gcc/Alternate-Keywords.html#Alternate-Keywords
 */
#ifndef __GNUC__
#define __inline__ inline
#endif

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#define BLOOMFILTER_VERSION "1.8.0"
#define BLOOMFILTER_MAJOR 1
#define BLOOMFILTER_MINOR 8
#define BLOOMFILTER_REVISION 0

#define BLOOM_SUCCESS 0
#define BLOOM_FAILURE -1

#define bloom_filter_get_version() (BLOOMFILTER_VERSION)

typedef uint64_t *(*BloomHashFunction)(int num_hashes, const char *str,
                                       int len);

typedef struct bloom_filter {
    /* bloom parameters */
    uint64_t     estimated_elements;
    float        false_positive_probability;
    unsigned int number_hashes;
    uint64_t     number_bits;
    /* bloom filter */
    unsigned char    *bloom;
    long              bloom_length;
    uint64_t          elements_added;
    BloomHashFunction hash_function;
    /* on disk handeling */
    short    __is_on_disk;
    FILE    *filepointer;
    uint64_t __filesize;
} BloomFilter;

/*  Initialize a standard bloom filter in memory; this will provide 'optimal'
   size and hash numbers. Estimated elements is 0 < x <= UINT64_MAX. False
   positive rate is 0.0 < x < 1.0 */
int bloom_filter_init_alt(BloomFilter *bf, uint64_t estimated_elements,
                          float             false_positive_rate,
                          BloomHashFunction hash_function);

__inline__ static int bloom_filter_init(BloomFilter *bf,
                                        uint64_t     estimated_elements,
                                        float        false_positive_rate) {
    return bloom_filter_init_alt(bf, estimated_elements, false_positive_rate,
                                 NULL);
}

/* Initialize a bloom filter directly into file; useful if the bloom filter is
 * larger than available RAM */
int bloom_filter_init_on_disk_alt(BloomFilter *bf, uint64_t estimated_elements,
                                  float             false_positive_rate,
                                  const char       *filepath,
                                  BloomHashFunction hash_function);

__inline__ static int bloom_filter_init_on_disk(BloomFilter *bf,
                                                uint64_t     estimated_elements,
                                                float       false_positive_rate,
                                                const char *filepath) {
    return bloom_filter_init_on_disk_alt(bf, estimated_elements,
                                         false_positive_rate, filepath, NULL);
}

/* Import a previously exported bloom filter from a file into memory */
int bloom_filter_import_alt(BloomFilter *bf, const char *filepath,
                            BloomHashFunction hash_function);

__inline__ static int bloom_filter_import(BloomFilter *bf,
                                          const char  *filepath) {
    return bloom_filter_import_alt(bf, filepath, NULL);
}

/*  Import a previously exported bloom filter from a file but do not pull the
   full bloom into memory. This is allows for the speed / storage trade off of
   not needing to put the full bloom filter into RAM. */
int bloom_filter_import_on_disk_alt(BloomFilter *bf, const char *filepath,
                                    BloomHashFunction hash_function);

__inline__ static int bloom_filter_import_on_disk(BloomFilter *bf,
                                                  const char  *filepath) {
    return bloom_filter_import_on_disk_alt(bf, filepath, NULL);
}

/* Export the current bloom filter to file */
int bloom_filter_export(BloomFilter *bf, const char *filepath);

/*  Export and import as a hex string; not space effecient but allows for
   storing multiple blooms in a single file or in a database, etc. NOTE: It is
   up to the caller to free the allocated memory */
char *bloom_filter_export_hex_string(BloomFilter *bf);

int bloom_filter_import_hex_string_alt(BloomFilter *bf, const char *hex,
                                       BloomHashFunction hash_function);

__inline__ static int bloom_filter_import_hex_string(BloomFilter *bf,
                                                     char        *hex) {
    return bloom_filter_import_hex_string_alt(bf, hex, NULL);
}

/* Set or change the hashing function */
void bloom_filter_set_hash_function(BloomFilter      *bf,
                                    BloomHashFunction hash_function);

/* Print out statistics about the bloom filter */
void bloom_filter_stats(BloomFilter *bf);

/* Release all memory used by the bloom filter */
int bloom_filter_destroy(BloomFilter *bf);

/* reset filter to unused state */
int bloom_filter_clear(BloomFilter *bf);

/* Add a string (or element) to the bloom filter */
int bloom_filter_add_string(BloomFilter *bf, const char *str, int len);

/* Add a string to a bloom filter using the defined hashes */
int bloom_filter_add_string_alt(BloomFilter *bf, uint64_t *hashes,
                                unsigned int number_hashes_passed);

/* Check to see if a string (or element) is or is not in the bloom filter */
int bloom_filter_check_string(BloomFilter *bf, const char *str, int len);

/* Check if a string is in the bloom filter using the passed hashes */
int bloom_filter_check_string_alt(BloomFilter *bf, uint64_t *hashes,
                                  unsigned int number_hashes_passed);

/* Calculates the current false positive rate based on the number of inserted
 * elements */
float bloom_filter_current_false_positive_rate(BloomFilter *bf);

/* Count the number of bits set to 1 */
uint64_t bloom_filter_count_set_bits(BloomFilter *bf);

/*  Estimate the number of unique elements in a Bloom Filter instead of using
   the overall count
    https://en.wikipedia.org/wiki/Bloom_filter#Approximating_the_number_of_items_in_a_Bloom_filter
    m = bits in Bloom filter
    k = number hashes
    X = count of flipped bits in filter */
uint64_t bloom_filter_estimate_elements(BloomFilter *bf);

uint64_t bloom_filter_estimate_elements_by_values(uint64_t m, uint64_t X,
                                                  int k);

/* Wrapper to set the inserted elements count to the estimated elements
 * calculation */
void bloom_filter_set_elements_to_estimated(BloomFilter *bf);

/*  Generate the desired number of hashes for the provided string
    NOTE: It is up to the caller to free the allocated memory */
uint64_t *bloom_filter_calculate_hashes(BloomFilter *bf, const char *str,
                                        unsigned int number_hashes, int len);

/* Calculate the size the bloom filter will take on disk when exported in bytes
 */
uint64_t bloom_filter_export_size(BloomFilter *bf);

/*******************************************************************************
    Merging, Intersection, and Jaccard Index Functions
    NOTE: Requires that the bloom filters be of the same type: hash, estimated
    elements, etc.
*******************************************************************************/

/* Merge Bloom Filters - inserts information into res */
int bloom_filter_union(BloomFilter *res, BloomFilter *bf1, BloomFilter *bf2);

uint64_t bloom_filter_count_union_bits_set(BloomFilter *bf1, BloomFilter *bf2);

/*  Find the intersection of Bloom Filters - insert into res with the
   intersection The number of inserted elements is updated to the estimated
   elements calculation */
int bloom_filter_intersect(BloomFilter *res, BloomFilter *bf1,
                           BloomFilter *bf2);

uint64_t bloom_filter_count_intersection_bits_set(BloomFilter *bf1,
                                                  BloomFilter *bf2);

/*  Calculate the Jacccard Index of the Bloom Filters
    NOTE: The closer to 1 the index, the closer in bloom filters. If it is 1,
   then the Bloom Filters contain the same elements, 0.5 would mean about 1/2
   the same elements are in common. 0 would mean the Bloom Filters are
   completely different. */
float bloom_filter_jaccard_index(BloomFilter *bf1, BloomFilter *bf2);

#endif /* END BLOOM FILTER HEADER */
