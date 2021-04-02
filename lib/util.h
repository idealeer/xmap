#ifndef XMAP_UTIL_H
#define XMAP_UTIL_H

#include <stdint.h>
#include <stdio.h>

#include "types.h"

#define IPV6_FLAG 6
#define IPV4_FLAG 4

int max_int(int a, int b);

uint32_t parse_max_hosts(char *max_targets);

void enforce_range(const char *name, int v, int min, int max);

// Splits comma delimited string into char*[]. Does not handle
// escaping or complicated setups - designed to process a set
// of fields that the user wants output
void split_string(char *in, int *len, char ***results);

// Print a string using w length long lines, attempting to break on
// spaces
void fprintw(FILE *f, char *s, size_t w);

// pretty print elapsed (or estimated) number of seconds
void time_string(uint32_t time, int est, char *buf, size_t len);

// pretty print quantities
void number_string(uint64_t n, char *buf, size_t len);

// pretty print quantities (bandwidth)
void bits_string(uint64_t n, char *buf, size_t len);

// Convert a string representation of a MAC address to a byte array
int parse_mac(macaddr_t *out, char *in);

int check_range(int v, int min, int max);

int file_exists(char *name);

// If running as root, drops privileges to that of user "nobody".
// Otherwise, does nothing.
int drop_privs();

// Set CPU affinity to a single core
int set_cpu(uint32_t core);

// IP string to IP address struct
int inet_str2in(const char *str, void *in, int ipv46_flag);

// IP address struct to IP string
int inet_in2str(const void *in, char *str, int len, int ipv46_flag);

// Note: caller must free return value
char *inet_in2constr(const void *in, int ipv46_flag);

// get file lines
int64_t get_file_lines(char *fileName);

#endif // XMAP_UTIL_H
