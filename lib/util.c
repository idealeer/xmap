#define _GNU_SOURCE

#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <sys/types.h>
#include <unistd.h>

#include "includes.h"
#include "logger.h"
#include "xalloc.h"

#define MAX_SPLITS 128

int max_int(int a, int b) {
    if (a >= b) {
        return a;
    }

    return b;
}

void enforce_range(const char *name, int v, int min, int max) {
    if (check_range(v, min, max) == EXIT_FAILURE) {
        log_fatal("xmap", "argument `%s' must be between %d and %d\n", name,
                  min, max);
    }
}

void split_string(char *in, int *len, char ***results) {
    char **fields  = xcalloc(MAX_SPLITS, sizeof(char *));
    int    retvlen = 0;
    char  *currloc = in;

    // parse csv into a set of strings
    while (1) {
        assert(retvlen < MAX_SPLITS);
        size_t len = strcspn(currloc, ", ");
        if (len == 0) {
            currloc++;
        } else {
            char *new = xmalloc(len + 1);
            strncpy(new, currloc, len);
            new[len]          = '\0';
            fields[retvlen++] = new;
            assert(fields[retvlen - 1]);
        }
        if (len == strlen(currloc)) {
            break;
        }
        currloc += len;
    }

    *results = fields;
    *len     = retvlen;
}

void fprintw(FILE *f, char *s, size_t w) {
    if (strlen(s) <= w) {
        fprintf(f, "%s", s);
        return;
    }

    // process each line individually in order to
    // respect existing line breaks in string.
    char *news = strdup(s);
    char *pch  = strtok(news, "\n");
    while (pch) {
        if (strlen(pch) <= w) {
            printf("%s\n", pch);
            pch = strtok(NULL, "\n");
            continue;
        }
        char *t = pch;
        while (strlen(t)) {
            size_t numchars = 0; // number of chars to print
            char  *tmp      = t;
            while (1) {
                size_t new = strcspn(tmp, " ") + 1;
                if (new == strlen(tmp) || new > w) {
                    // there are no spaces in the string,
                    // so, just print the entire thing on
                    // one line;
                    numchars += new;
                    break;
                } else if (numchars + new > w) {
                    // if we added any more, we'd be over w
                    // chars so time to print the line and
                    // move on to the next.
                    break;
                } else {
                    tmp += (size_t) new;
                    numchars += new;
                }
            }
            fprintf(f, "%.*s\n", (int) numchars, t);
            t += (size_t) numchars;
            if (t > pch + (size_t) strlen(pch)) {
                break;
            }
        }
        pch = strtok(NULL, "\n");
    }

    free(news);
}

uint32_t parse_max_hosts(char *max_targets) {
    int    errno = 0;
    char  *end;
    double v = strtod(max_targets, &end);
    if (end == max_targets || errno != 0) {
        log_fatal("argparse", "can't convert max-targets to a number");
    }

    if (end[0] == '%' && end[1] == '\0') {
        // treat as percentage
        v = v * ((unsigned long long int) 1 << 32u) / 100.;
    } else if (end[0] != '\0') {
        log_fatal("eargparse", "extra characters after max-targets");
    }

    if (v <= 0) {
        return 0;
    } else if (v >= ((unsigned long long int) 1 << 32u)) {
        return 0xFFFFFFFF;
    } else {
        return v;
    }
}

// pretty print elapsed (or estimated) number of seconds
void time_string(uint32_t time, int est, char *buf, size_t len) {
    int y = time / 31556736;
    int d = (time % 31556736) / 86400;
    int h = (time % 86400) / 3600;
    int m = (time % 3600) / 60;
    int s = time % 60;

    if (est) {
        if (y > 0) {
            snprintf(buf, len, "%d years", y);
        } else if (d > 9) {
            snprintf(buf, len, "%dd", d);
        } else if (d > 0) {
            snprintf(buf, len, "%dd%02dh", d, h);
        } else if (h > 9) {
            snprintf(buf, len, "%dh", h);
        } else if (h > 0) {
            snprintf(buf, len, "%dh%02dm", h, m);
        } else if (m > 9) {
            snprintf(buf, len, "%dm", m);
        } else if (m > 0) {
            snprintf(buf, len, "%dm%02ds", m, s);
        } else {
            snprintf(buf, len, "%ds", s);
        }
    } else {
        if (d > 0) {
            snprintf(buf, len, "%dd%d:%02d:%02d", d, h, m, s);
        } else if (h > 0) {
            snprintf(buf, len, "%d:%02d:%02d", h, m, s);
        } else {
            snprintf(buf, len, "%d:%02d", m, s);
        }
    }
}

// pretty print quantities
void number_string(uint64_t n, char *buf, size_t len) {
    int figs = 0;
    if (n < 1e3) {
        snprintf(buf, len, "%u ", n);
    } else if (n < 1e6) {
        if (n < 1e4) {
            figs = 2;
        } else if (n < 1e5) {
            figs = 1;
        }
        snprintf(buf, len, "%0.*f K", figs, (float) n / (float) 1e3);
    } else if (n < 1e9) {
        if (n < 1e7) {
            figs = 2;
        } else if (n < 1e8) {
            figs = 1;
        }
        snprintf(buf, len, "%0.*f M", figs, (float) n / (float) 1e6);
    } else { // 1e12
        if (n < 1e10) {
            figs = 2;
        } else if (n < 1e11) {
            figs = 1;
        }
        snprintf(buf, len, "%0.*f G", figs, (float) n / (float) 1e9);
    }
}

// pretty print quantities (bandwidth)
void bits_string(uint64_t n, char *buf, size_t len) {
    int figs = 0;
    if (n < 1024) {
        snprintf(buf, len, "%u ", n);
    } else if (n < 1048576) { // 1024^2
        if (n < 65536) {      // /16
            figs = 2;
        } else if (n < 262144) { // /4
            figs = 1;
        }
        snprintf(buf, len, "%0.*f K", figs, (float) n / (float) 1024); // 1024
    } else if (n < 1073741824) {                                       // 1024^3
        if (n < 67108864) {                                            // 16
            figs = 2;
        } else if (n < 268435456) { // /4
            figs = 1;
        }
        snprintf(buf, len, "%0.*f M", figs,
                 (float) n / (float) 1048576); // 1024^2
    } else {                                   // 1024^4
        if (n < 68719476736) {                 // /16
            figs = 2;
        } else if (n < 274877906944) { // /4
            figs = 1;
        }
        snprintf(buf, len, "%0.*f G", figs,
                 (float) n / (float) 1073741824); // 1024^3
    }
}

int parse_mac(macaddr_t *out, char *in) {
    if (strlen(in) < MAC_ADDR_LEN * 3 - 1) return 0;
    char octet[4];
    octet[2] = '\0';

    for (int i = 0; i < MAC_ADDR_LEN; i++) {
        if (i < MAC_ADDR_LEN - 1 && in[i * 3 + 2] != ':') {
            return 0;
        }
        strncpy(octet, &in[i * 3], 2);
        char *err = NULL;
        long  b   = strtol(octet, &err, 16);
        if (err && *err != '\0') {
            return 0;
        }
        out[i] = b & 0xFF;
    }

    return 1;
}

int check_range(int v, int min, int max) {
    if (v < min || v > max) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int file_exists(char *name) {
    FILE *file = fopen(name, "r");
    if (!file) return 0;
    fclose(file);

    return 1;
}

// IP string to IP address struct
int inet_str2in(const char *str, void *in, int ipv46_flag) {
    switch (ipv46_flag) {
    case IPV6_FLAG: {
        int ret = inet_pton(AF_INET6, str, (struct in6_addr *) in);
        if (ret != 1) {
            return 0;
        }
        return 1;
    }
    case IPV4_FLAG: {
        int ret = inet_pton(AF_INET, str, (struct in_addr *) in);
        if (ret != 1) {
            return 0;
        }
        return 1;
    }
    default:
        return 0;
    }
}

// IP address struct to IP string
int inet_in2str(const void *in, char *str, int len, int ipv46_flag) {
    switch (ipv46_flag) {
    case IPV6_FLAG: {
        char *err = (char *) inet_ntop(AF_INET6, in, str, len);
        if (err == NULL) {
            return 0;
        }
        return 1;
    }
    case IPV4_FLAG: {
        char *err = (char *) inet_ntop(AF_INET, in, str, len);
        if (err == NULL) {
            return 0;
        }
        return 1;
    }
    default:
        return 0;
    }
}

// Note: caller must free return value
char *inet_in2constr(const void *in, int ipv46_flag) {
    char *constr = xmalloc(64);
    switch (ipv46_flag) {
    case IPV6_FLAG: {
        char *err = (char *) inet_ntop(AF_INET6, in, constr, 64);
        if (err == NULL) {
            return NULL;
        }
        return constr;
    }
    case IPV4_FLAG: {
        char *err = (char *) inet_ntop(AF_INET, in, constr, 64);
        if (err == NULL) {
            return NULL;
        }
        return constr;
    }
    default:
        return NULL;
    }
}

int64_t get_file_lines(char *fileName) {
    assert(strlen(fileName) < 1024);
    char  buff[1030] = {0x00};
    FILE *fp         = NULL;
    strcpy(buff, "wc -l ");
    strcat(buff, fileName);

    fp = popen(buff, "r");
    if (fp) {
        memset(buff, 0x00, sizeof(buff));
        if (fgets(buff, sizeof(buff), fp)) {
            pclose(fp);
            return strtoll(buff, NULL, 10);
        }
    }
    if (fp) pclose(fp);

    return -1;
}

#if defined(__APPLE__)

#include <uuid/uuid.h>

#endif

int drop_privs() {
    struct passwd *pw;

    if (geteuid() != 0) {
        /* Not root */
        return EXIT_SUCCESS;
    }

    if ((pw = getpwnam("nobody")) != NULL) {
        if (setuid(pw->pw_uid) == 0) {
            return EXIT_SUCCESS; // success
        }
    }

    return EXIT_FAILURE;
}

#if defined(__APPLE__)

#include <mach/thread_act.h>

int set_cpu(uint32_t core) {
    mach_port_t                   tid = pthread_mach_thread_np(pthread_self());
    struct thread_affinity_policy policy;
    policy.affinity_tag = core;

    kern_return_t ret = thread_policy_set(tid, THREAD_AFFINITY_POLICY,
                                          (thread_policy_t) &policy,
                                          THREAD_AFFINITY_POLICY_COUNT);
    if (ret != KERN_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#elif defined(__DragonFly__)
#include <sys/usched.h>

int set_cpu(uint32_t core) {
    if (usched_set(getpid(), USCHED_SET_CPU, &core, sizeof(core)) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#elif defined(__NetBSD__)
int set_cpu(uint32_t core) {
    cpuset_t *cpuset = cpuset_create();
    if (cpuset == NULL) {
        return EXIT_FAILURE;
    }

    cpuset_zero(cpuset);
    cpuset_set(core, cpuset);
    cpuset_destroy(cpuset);

    if (pthread_setaffinity_np(pthread_self(), cpuset_size(cpuset), cpuset) !=
        0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#else

#if defined(__FreeBSD__)
#include <pthread_np.h>
#include <sys/cpuset.h>
#include <sys/param.h>
#define cpu_set_t cpuset_t
#endif

int set_cpu(uint32_t core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) !=
        0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#endif
