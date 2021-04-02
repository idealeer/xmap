#ifndef XMAP_LOCKFD_H
#define XMAP_LOCKFD_H

#include <stdio.h>

int lock_fd(int fd);

int unlock_fd(int fd);

int lock_file(FILE *f);

int unlock_file(FILE *f);

#endif // XMAP_LOCKFD_H
