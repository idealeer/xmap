#ifndef XMAP_XALLOC_H
#define XMAP_XALLOC_H

#include <stddef.h>

void *xcalloc(size_t count, size_t size);

void xfree(void *ptr);

void *xmalloc(size_t size);

void *xrealloc(void *ptr, size_t size);

#endif // XMAP_XALLOC_H
