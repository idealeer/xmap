/*******************************************************************************
***
***     Author: Tyler Barrus
***     email:  barrust@gmail.com
***
***     Version: 1.8.0
***
***     License: MIT 2015
***
***     change: add arg: len at 09/08/2020
***     int bloom_filter_add_string(BloomFilter *bf, const char *str, int len);
*******************************************************************************/

#include "bloom.h"
#include <fcntl.h> /* O_RDWR */
#include <math.h>  /* pow, exp */
#include <stdio.h> /* printf */
#include <stdlib.h>
#include <string.h>    /* strlen */
#include <sys/mman.h>  /* mmap, mummap */
#include <sys/stat.h>  /* fstat */
#include <sys/types.h> /* */
#include <unistd.h>    /* close */

#define CHECK_BIT_CHAR(c, k) (c & (1 << (k)))
#define CHECK_BIT(A, k) (CHECK_BIT_CHAR(A[((k) / 8)], ((k) % 8)))
// #define set_bit(A,k)          (A[((k) / 8)] |=  (1 << ((k) % 8)))
// #define clear_bit(A,k)        (A[((k) / 8)] &= ~(1 << ((k) % 8)))

#if defined(_OPENMP)
#define ATOMIC _Pragma("omp atomic")
#define CRITICAL _Pragma("omp critical (bloom_filter_critical)")
#else
#define ATOMIC
#define CRITICAL
#endif

/* define some constant magic looking numbers */
#define CHAR_LEN 8
#define LOG_TWO_SQUARED 0.4804530139182
#define LOG_TWO 0.6931471805599453

/*******************************************************************************
***  PRIVATE FUNCTIONS
*******************************************************************************/
static uint64_t *__default_hash(int num_hashes, const char *str, int len);

static uint64_t __fnv_1a(const char *key, int len);

static void __calculate_optimal_hashes(BloomFilter *bf);

static void __read_from_file(BloomFilter *bf, FILE *fp, short on_disk,
                             const char *filename);

static void __write_to_file(BloomFilter *bf, FILE *fp, short on_disk);

static int __sum_bits_set_char(char c);

static int __check_if_union_or_intersection_ok(BloomFilter *res,
                                               BloomFilter *bf1,
                                               BloomFilter *bf2);

int bloom_filter_init_alt(BloomFilter *bf, uint64_t estimated_elements,
                          float             false_positive_rate,
                          BloomHashFunction hash_function) {
    if (estimated_elements <= 0 || estimated_elements > UINT64_MAX ||
        false_positive_rate <= 0.0 || false_positive_rate >= 1.0) {
        return BLOOM_FAILURE;
    }
    bf->estimated_elements         = estimated_elements;
    bf->false_positive_probability = false_positive_rate;
    __calculate_optimal_hashes(bf);
    bf->bloom          = calloc(bf->bloom_length + 1,
                                sizeof(char)); // pad to ensure no running off the end
    bf->elements_added = 0;
    bloom_filter_set_hash_function(bf, hash_function);
    bf->__is_on_disk = 0; // not on disk
    return BLOOM_SUCCESS;
}

int bloom_filter_init_on_disk_alt(BloomFilter *bf, uint64_t estimated_elements,
                                  float             false_positive_rate,
                                  const char       *filepath,
                                  BloomHashFunction hash_function) {
    if (estimated_elements <= 0 || estimated_elements > UINT64_MAX ||
        false_positive_rate <= 0.0 || false_positive_rate >= 1.0) {
        return BLOOM_FAILURE;
    }
    bf->estimated_elements         = estimated_elements;
    bf->false_positive_probability = false_positive_rate;
    __calculate_optimal_hashes(bf);
    bf->elements_added = 0;
    FILE *fp;
    fp = fopen(filepath, "w+b");
    if (fp == NULL) {
        fprintf(stderr, "Can't open file %s!\n", filepath);
        return BLOOM_FAILURE;
    }
    __write_to_file(bf, fp, 1);
    fclose(fp);
    // slightly ineffecient to redo some of the calculations...
    return bloom_filter_import_on_disk_alt(bf, filepath, hash_function);
}

void bloom_filter_set_hash_function(BloomFilter      *bf,
                                    BloomHashFunction hash_function) {
    bf->hash_function =
        (hash_function == NULL) ? __default_hash : hash_function;
}

int bloom_filter_destroy(BloomFilter *bf) {
    if (bf->__is_on_disk == 0) {
        free(bf->bloom);
    } else {
        fclose(bf->filepointer);
        munmap(bf->bloom, bf->__filesize);
    }
    bf->bloom                      = NULL;
    bf->filepointer                = NULL;
    bf->elements_added             = 0;
    bf->estimated_elements         = 0;
    bf->false_positive_probability = 0;
    bf->number_hashes              = 0;
    bf->number_bits                = 0;
    bf->hash_function              = NULL;
    bf->__is_on_disk               = 0;
    bf->__filesize                 = 0;
    return BLOOM_SUCCESS;
}

int bloom_filter_clear(BloomFilter *bf) {
    long i;
    for (i = 0; i < bf->bloom_length; ++i) {
        bf->bloom[i] = 0;
    }
    bf->elements_added = 0;
    return BLOOM_SUCCESS;
}

void bloom_filter_stats(BloomFilter *bf) {
    const char *is_on_disk   = (bf->__is_on_disk == 0 ? "no" : "yes");
    uint64_t    size_on_disk = bloom_filter_export_size(bf);

    printf("BloomFilter\n\
    bits: %" PRIu64 "\n\
    estimated elements: %" PRIu64 "\n\
    number hashes: %d\n\
    max false positive rate: %f\n\
    bloom length (8 bits): %ld\n\
    elements added: %" PRIu64 "\n\
    estimated elements added: %" PRIu64 "\n\
    current false positive rate: %f\n\
    export size (bytes): %" PRIu64 "\n\
    number bits set: %" PRIu64 "\n\
    is on disk: %s\n",
           bf->number_bits, bf->estimated_elements, bf->number_hashes,
           bf->false_positive_probability, bf->bloom_length, bf->elements_added,
           bloom_filter_estimate_elements(bf),
           bloom_filter_current_false_positive_rate(bf), size_on_disk,
           bloom_filter_count_set_bits(bf), is_on_disk);
}

int bloom_filter_add_string(BloomFilter *bf, const char *str, int len) {
    uint64_t *hashes =
        bloom_filter_calculate_hashes(bf, str, bf->number_hashes, len);
    int res = bloom_filter_add_string_alt(bf, hashes, bf->number_hashes);
    free(hashes);
    return res;
}

int bloom_filter_check_string(BloomFilter *bf, const char *str, int len) {
    uint64_t *hashes =
        bloom_filter_calculate_hashes(bf, str, bf->number_hashes, len);
    int res = bloom_filter_check_string_alt(bf, hashes, bf->number_hashes);
    free(hashes);
    return res;
}

uint64_t *bloom_filter_calculate_hashes(BloomFilter *bf, const char *str,
                                        unsigned int number_hashes, int len) {
    return bf->hash_function(number_hashes, str, len);
}

/* Add a string to a bloom filter using the defined hashes */
int bloom_filter_add_string_alt(BloomFilter *bf, uint64_t *hashes,
                                unsigned int number_hashes_passed) {
    if (number_hashes_passed < bf->number_hashes) {
        fprintf(stderr,
                "Error: not enough hashes passed in to correctly check!\n");
        return BLOOM_FAILURE;
    }

    unsigned int i;
    for (i = 0; i < bf->number_hashes; ++i) {
        ATOMIC
        bf->bloom[(hashes[i] % bf->number_bits) / 8] |=
            (1u << ((hashes[i] % bf->number_bits) % 8)); // set the bit
    }

    ATOMIC
    ++bf->elements_added;
    if (bf->__is_on_disk == 1) { // only do this if it is on disk!
        int offset = sizeof(uint64_t) + sizeof(float);
        CRITICAL {
            fseek(bf->filepointer, offset * -1, SEEK_END);
            fwrite(&bf->elements_added, sizeof(uint64_t), 1, bf->filepointer);
        }
    }
    return BLOOM_SUCCESS;
}

/* Check if a string is in the bloom filter using the passed hashes */
int bloom_filter_check_string_alt(BloomFilter *bf, uint64_t *hashes,
                                  unsigned int number_hashes_passed) {
    if (number_hashes_passed < bf->number_hashes) {
        fprintf(stderr,
                "Error: not enough hashes passed in to correctly check!\n");
        return BLOOM_FAILURE;
    }

    unsigned int i;
    int          r = BLOOM_SUCCESS;
    for (i = 0; i < bf->number_hashes; ++i) {
        int tmp_check = CHECK_BIT(bf->bloom, (hashes[i] % bf->number_bits));
        if (tmp_check == 0) {
            r = BLOOM_FAILURE;
            break; // no need to continue checking
        }
    }
    return r;
}

float bloom_filter_current_false_positive_rate(BloomFilter *bf) {
    int    num = (bf->number_hashes * -1 * bf->elements_added);
    double d   = num / (float) bf->number_bits;
    double e   = exp(d);
    return pow((1 - e), bf->number_hashes);
}

int bloom_filter_export(BloomFilter *bf, const char *filepath) {
    // if the bloom is initialized on disk, no need to export it
    if (bf->__is_on_disk == 1) {
        return BLOOM_SUCCESS;
    }
    FILE *fp;
    fp = fopen(filepath, "w+b");
    if (fp == NULL) {
        fprintf(stderr, "Can't open file %s!\n", filepath);
        return BLOOM_FAILURE;
    }
    __write_to_file(bf, fp, 0);
    fclose(fp);
    return BLOOM_SUCCESS;
}

int bloom_filter_import_alt(BloomFilter *bf, const char *filepath,
                            BloomHashFunction hash_function) {
    FILE *fp;
    fp = fopen(filepath, "r+b");
    if (fp == NULL) {
        fprintf(stderr, "Can't open file %s!\n", filepath);
        return BLOOM_FAILURE;
    }
    __read_from_file(bf, fp, 0, NULL);
    fclose(fp);
    bloom_filter_set_hash_function(bf, hash_function);
    bf->__is_on_disk = 0; // not on disk
    return BLOOM_SUCCESS;
}

int bloom_filter_import_on_disk_alt(BloomFilter *bf, const char *filepath,
                                    BloomHashFunction hash_function) {
    bf->filepointer = fopen(filepath, "r+b");
    if (bf->filepointer == NULL) {
        fprintf(stderr, "Can't open file %s!\n", filepath);
        return BLOOM_FAILURE;
    }
    __read_from_file(bf, bf->filepointer, 1, filepath);
    // don't close the file pointer here...
    bloom_filter_set_hash_function(bf, hash_function);
    bf->__is_on_disk = 1; // on disk
    return BLOOM_SUCCESS;
}

char *bloom_filter_export_hex_string(BloomFilter *bf) {
    uint64_t i,
        bytes = sizeof(uint64_t) * 2 + sizeof(float) + (bf->bloom_length);
    char *hex = malloc((bytes * 2 + 1) * sizeof(char));
    for (i = 0; i < (uint64_t) bf->bloom_length; ++i) {
        sprintf(hex + (i * 2), "%02x",
                bf->bloom[i]); // not the fastest way, but works
    }
    i = bf->bloom_length * 2;
    sprintf(hex + i, "%016" PRIx64 "", bf->estimated_elements);
    i += 16; // 8 bytes * 2 for hex
    sprintf(hex + i, "%016" PRIx64 "", bf->elements_added);

    unsigned int ui;
    memcpy(&ui, &bf->false_positive_probability, sizeof(ui));
    i += 16; // 8 bytes * 2 for hex
    sprintf(hex + i, "%08x", ui);
    return hex;
}

int bloom_filter_import_hex_string_alt(BloomFilter *bf, const char *hex,
                                       BloomHashFunction hash_function) {
    uint64_t len = strlen(hex);
    if (len % 2 != 0) {
        fprintf(stderr, "Unable to parse; exiting\n");
        return BLOOM_FAILURE;
    }
    char fpr[9]      = {0};
    char est_els[17] = {0};
    char ins_els[17] = {0};
    memcpy(fpr, hex + (len - 8), 8);
    memcpy(ins_els, hex + (len - 24), 16);
    memcpy(est_els, hex + (len - 40), 16);
    uint32_t t_fpr;

    bf->estimated_elements = strtoull(est_els, NULL, 16);
    bf->elements_added     = strtoull(ins_els, NULL, 16);
    sscanf(fpr, "%x", &t_fpr);
    float f;
    memcpy(&f, &t_fpr, sizeof(float));
    bf->false_positive_probability = f;
    bloom_filter_set_hash_function(bf, hash_function);

    __calculate_optimal_hashes(bf);
    bf->bloom        = calloc(bf->bloom_length + 1, sizeof(char)); // pad
    bf->__is_on_disk = 0; // not on disk

    uint64_t i;
    for (i = 0; i < (uint64_t) bf->bloom_length; ++i) {
        sscanf(hex + (i * 2), "%2hhx", &bf->bloom[i]);
    }
    return BLOOM_SUCCESS;
}

uint64_t bloom_filter_export_size(BloomFilter *bf) {
    return (uint64_t) (bf->bloom_length * sizeof(unsigned char)) +
           (2 * sizeof(uint64_t)) + sizeof(float);
}

uint64_t bloom_filter_count_set_bits(BloomFilter *bf) {
    uint64_t i, res = 0;
    for (i = 0; i < (uint64_t) bf->bloom_length; ++i) {
        res += __sum_bits_set_char(bf->bloom[i]);
    }
    return res;
}

uint64_t bloom_filter_estimate_elements(BloomFilter *bf) {
    return bloom_filter_estimate_elements_by_values(
        bf->number_bits, bloom_filter_count_set_bits(bf), bf->number_hashes);
}

uint64_t bloom_filter_estimate_elements_by_values(uint64_t m, uint64_t X,
                                                  int k) {
    /* m = number bits; X = count of flipped bits; k = number hashes */
    double log_n = log(1 - ((double) X / (double) m));
    return (uint64_t) - (((double) m / k) * log_n);
}

int bloom_filter_union(BloomFilter *res, BloomFilter *bf1, BloomFilter *bf2) {
    // Ensure the bloom filters can be unioned
    if (__check_if_union_or_intersection_ok(res, bf1, bf2) == BLOOM_FAILURE) {
        return BLOOM_FAILURE;
    }
    uint64_t i;
    for (i = 0; i < (uint64_t) bf1->bloom_length; ++i) {
        res->bloom[i] = bf1->bloom[i] | bf2->bloom[i];
    }
    bloom_filter_set_elements_to_estimated(res);
    return BLOOM_SUCCESS;
}

uint64_t bloom_filter_count_union_bits_set(BloomFilter *bf1, BloomFilter *bf2) {
    // Ensure the bloom filters can be unioned
    if (__check_if_union_or_intersection_ok(bf1, bf1, bf2) ==
        BLOOM_FAILURE) { // use bf1 as res
        return BLOOM_FAILURE;
    }
    uint64_t i, res = 0;
    for (i = 0; i < (uint64_t) bf1->bloom_length; ++i) {
        res += __sum_bits_set_char(bf1->bloom[i] | bf2->bloom[i]);
    }
    return res;
}

int bloom_filter_intersect(BloomFilter *res, BloomFilter *bf1,
                           BloomFilter *bf2) {
    // Ensure the bloom filters can be used in an intersection
    if (__check_if_union_or_intersection_ok(res, bf1, bf2) == BLOOM_FAILURE) {
        return BLOOM_FAILURE;
    }
    uint64_t i;
    for (i = 0; i < (uint64_t) bf1->bloom_length; ++i) {
        res->bloom[i] = bf1->bloom[i] & bf2->bloom[i];
    }
    bloom_filter_set_elements_to_estimated(res);
    return BLOOM_SUCCESS;
}

void bloom_filter_set_elements_to_estimated(BloomFilter *bf) {
    bf->elements_added = bloom_filter_estimate_elements(bf);
}

uint64_t bloom_filter_count_intersection_bits_set(BloomFilter *bf1,
                                                  BloomFilter *bf2) {
    // Ensure the bloom filters can be used in an intersection
    if (__check_if_union_or_intersection_ok(bf1, bf1, bf2) ==
        BLOOM_FAILURE) { // use bf1 as res
        return BLOOM_FAILURE;
    }
    uint64_t i, res = 0;
    for (i = 0; i < (uint64_t) bf1->bloom_length; ++i) {
        res += __sum_bits_set_char(bf1->bloom[i] & bf2->bloom[i]);
    }
    return res;
}

float bloom_filter_jaccard_index(BloomFilter *bf1, BloomFilter *bf2) {
    // Ensure the bloom filters can be used in an intersection and union
    if (__check_if_union_or_intersection_ok(bf1, bf1, bf2) ==
        BLOOM_FAILURE) { // use bf1 as res
        return (float) BLOOM_FAILURE;
    }
    float set_union_bits =
        (float) (bloom_filter_count_union_bits_set(bf1, bf2));
    if (set_union_bits == 0.0) { // check for divide by 0 error
        return (float) 1.0; // they must be both empty for this to occur and are
        // therefore the same
    }
    return (float) (bloom_filter_count_intersection_bits_set(bf1, bf2)) /
           set_union_bits;
}

/*******************************************************************************
 *    PRIVATE FUNCTIONS
 *******************************************************************************/
static void __calculate_optimal_hashes(BloomFilter *bf) {
    // calc optimized values
    long     n = bf->estimated_elements;
    float    p = bf->false_positive_probability;
    uint64_t m = ceil((-n * log(p)) / LOG_TWO_SQUARED); // AKA pow(log(2), 2);
    unsigned int k = round(LOG_TWO * m / n);            // AKA log(2.0);
    // set paramenters
    bf->number_hashes = k; // should check to make sure it is at least 1...
    bf->number_bits   = m;
    long num_pos      = ceil(m / (CHAR_LEN * 1.0));
    bf->bloom_length  = num_pos;
}

static int __sum_bits_set_char(char c) {
    int j, res = 0;
    for (j = 0; j < CHAR_LEN; ++j) {
        res += (CHECK_BIT_CHAR(c, j) != 0) ? 1 : 0;
    }
    return res;
}

static int __check_if_union_or_intersection_ok(BloomFilter *res,
                                               BloomFilter *bf1,
                                               BloomFilter *bf2) {
    if (res->number_hashes != bf1->number_hashes ||
        bf1->number_hashes != bf2->number_hashes) {
        return BLOOM_FAILURE;
    } else if (res->number_bits != bf1->number_bits ||
               bf1->number_bits != bf2->number_bits) {
        return BLOOM_FAILURE;
    } else if (res->hash_function != bf1->hash_function ||
               bf1->hash_function != bf2->hash_function) {
        return BLOOM_FAILURE;
    }
    return BLOOM_SUCCESS;
}

/* NOTE: this assumes that the file handler is open and ready to use */
static void __write_to_file(BloomFilter *bf, FILE *fp, short on_disk) {
    if (on_disk == 0) {
        fwrite(bf->bloom, bf->bloom_length, 1, fp);
    } else {
        // will need to write out everything by hand
        uint64_t i;
        for (i = 0; i < (uint64_t) bf->bloom_length; ++i) {
            fputc(0, fp);
        }
    }
    fwrite(&bf->estimated_elements, sizeof(uint64_t), 1, fp);
    fwrite(&bf->elements_added, sizeof(uint64_t), 1, fp);
    fwrite(&bf->false_positive_probability, sizeof(float), 1, fp);
}

/* NOTE: this assumes that the file handler is open and ready to use */
static void __read_from_file(BloomFilter *bf, FILE *fp, short on_disk,
                             const char *filename) {
    int offset = sizeof(uint64_t) * 2 + sizeof(float);
    fseek(fp, offset * -1, SEEK_END);
    size_t read;
    read = fread(&bf->estimated_elements, sizeof(uint64_t), 1, fp);
    read = fread(&bf->elements_added, sizeof(uint64_t), 1, fp);
    read = fread(&bf->false_positive_probability, sizeof(float), 1, fp);
    __calculate_optimal_hashes(bf);
    rewind(fp);
    if (on_disk == 0) {
        bf->bloom = calloc(bf->bloom_length + 1, sizeof(char));
        read      = fread(bf->bloom, sizeof(char), bf->bloom_length, fp);
        if (read != (uint64_t) bf->bloom_length) {
            perror("__read_from_file: ");
            exit(1);
        }
    } else {
        struct stat buf;
        int         fd = open(filename, O_RDWR);
        if (fd < 0) {
            perror("open: ");
            exit(1);
        }
        fstat(fd, &buf);
        bf->__filesize = buf.st_size;
        bf->bloom = mmap((caddr_t) 0, bf->__filesize, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
        if (bf->bloom == (unsigned char *) -1) {
            perror("mmap: ");
            exit(1);
        }
        // close the file descriptor
        close(fd);
    }
}

/* NOTE: The caller will free the results */
static uint64_t *__default_hash(int num_hashes, const char *str, int len) {
    uint64_t *results = calloc(num_hashes, sizeof(uint64_t));
    int       i;
    char      key[32] = {
        0}; // largest value is 7FFF,FFFF,FFFF,FFFF TODO the real str len
    results[0] = __fnv_1a(str, len);
    for (i = 1; i < num_hashes; ++i) {
        sprintf(key, "%" PRIx64 "", results[i - 1]);
        results[i] = __fnv_1a(key, len);
    }
    return results;
}

static uint64_t __fnv_1a(const char *key, int len) {
    // FNV-1a hash (http://www.isthe.com/chongo/tech/comp/fnv/)
    int      i;
    uint64_t h = 14695981039346656073ULL; // FNV_OFFSET 64 bit
    for (i = 0; i < len; ++i) {
        h = h ^ (unsigned char) key[i];
        h = h * 1099511628211ULL; // FNV_PRIME 64 bit
    }
    return h;
}
