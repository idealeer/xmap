/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "constraint.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "gmp-ext.h"
#include "logger.h"
#include "xalloc.h"

//
// Efficient address-space constraints  (AH 7/2013)
//
// This module uses a tree-based representation to efficiently manipulate and
// query constraints on the address space to be scanned.It provides a value for
// every IP(v6) address, and these values are applied by setting them for
// network prefixes. Order matters: setting a value replaces any existing value
// for that prefix or subsets of it. We use this to implement network whitelist
// and blacklist.
//
// Think of setting values in this structure like painting subnets with
// different colors.  We can paint subnets black to exclude them and white to
// allow them.  Only the top color shows. This makes for potentially very
// powerful constraint specifications.
//
// Internally, this is implemented using a binary tree, where each node
// corresponds to a network prefix.  (E.g., the root is ::0.0.0.0/0(::/0), and
// its children, if present, are ::0.0.0.0/1(::/1) and
// 8000::0.0.0.0/1(8000::/1).)  Each leaf of the tree stores the value that
// applies to every address within the leaf's portion of the prefix space.
//
// As an optimization, after all values are set, we look up the value or subtree
// for every /20 prefix and cache them as an array.
//

// As an optimization, we precompute lookups for every prefix of this length.
// Mem at least is 2^len * 16B (for a mpz_t).

// As an extension, we build a constraint accepting any MAX IP length. Further,
// the IPvX below could consist of a max IP length and a max port length and
// a max index length for generating random <ip-prefix, port, index>

// IPvX mask
static int IPVX_MAX_PREFIX_LEN = 0;
static int RADIX_LENGTH        = 20;
static int IPVX_MASK_FLAG      = 0;

static mpz_t IPVX_HALF_INDEX;
static mpz_t IPVX_MAX_INDEX;
static mpz_t RADIX_SIZE;

typedef struct node {
    struct node *l;
    struct node *r;
    mpz_t        value; // value implying white, black or other
    mpz_t        count; // number of being painted
} node_t;

struct _constraint {
    node_t *root;  // root node of the tree
    mpz_t  *radix; // array of prefixes (/RADIX_LENGTH) that
    // are painted paint_value
    size_t radix_len;   // number of prefixes in radix array
    int    painted;     // have we precomputed counts for each node?
    mpz_t  paint_value; // value for which we precomputed counts
};

// Tree operations respect the invariant that every node that isn't a
// leaf has exactly two children.
#define IS_LEAF(node) ((node)->l == NULL)

// Allocate a new leaf with the given value
static node_t *_create_leaf(const mpz_t value) {
    node_t *node = xmalloc(sizeof(node_t));
    node->l      = NULL;
    node->r      = NULL;
    mpz_init_set(node->value, value);

    return node;
}

// calculate the initial IPvX mask
static void cal_ipvx_mask(size_t ip_max_len) {
    assert(0 < ip_max_len);

    if (!IPVX_MASK_FLAG) {
        log_debug("constraint", "calculating mask for IPvX, max-len=%d",
                  ip_max_len);
        IPVX_MAX_PREFIX_LEN = ip_max_len;
        if (IPVX_MAX_PREFIX_LEN < RADIX_LENGTH)
            RADIX_LENGTH = IPVX_MAX_PREFIX_LEN;

        mpz_t two;
        mpz_init_set_ui(two, 2);
        mpz_init(IPVX_HALF_INDEX);
        mpz_pow_ui(IPVX_HALF_INDEX, two, IPVX_MAX_PREFIX_LEN - 1);
        mpz_init(IPVX_MAX_INDEX);
        mpz_pow_ui(IPVX_MAX_INDEX, two, IPVX_MAX_PREFIX_LEN);
        mpz_init(RADIX_SIZE);
        mpz_pow_ui(RADIX_SIZE, two, IPVX_MAX_PREFIX_LEN - RADIX_LENGTH);
        mpz_clear(two);
        IPVX_MASK_FLAG = 1;

        log_debug("constraint", "IPvX_MAX_PREFIX_LEN: %d", IPVX_MAX_PREFIX_LEN);
        log_debug("constraint", "IPvX_HALF_INDEX: 2^%d = %s",
                  IPVX_MAX_PREFIX_LEN - 1, mpz_to_str10(IPVX_HALF_INDEX));
        log_debug("constraint", "IPvX_MAX_INDEX: 2^%d = %s",
                  IPVX_MAX_PREFIX_LEN, mpz_to_str10(IPVX_MAX_INDEX));
        log_debug("constraint", "IPvX RADIX_LENGTH: %d, RADIX_SIZE: 2^%d = %s",
                  RADIX_LENGTH, IPVX_MAX_PREFIX_LEN - RADIX_LENGTH,
                  mpz_to_str10(RADIX_SIZE));
    }
}

// Initialize the tree.
// All addresses will initially have the given value.
constraint_t *constraint_init(const mpz_t value, size_t ipvx_max_len) {
    log_debug("constraint", "initializing for IPvX, max-len=%d", ipvx_max_len);

    cal_ipvx_mask(ipvx_max_len);
    constraint_t *con = xmalloc(sizeof(constraint_t));
    con->root         = _create_leaf(value);
    con->radix        = xcalloc(sizeof(mpz_t), 1u << RADIX_LENGTH);
    con->painted      = 0;

    return con;
}

// Free the subtree rooted at node.
static void _destroy_subtree(node_t *node) {
    if (node == NULL) return;

    mpz_clear(node->value);
    mpz_clear(node->count);
    _destroy_subtree(node->l);
    _destroy_subtree(node->r);
    free(node);
}

// Deinitialize and free the tree.
void constraint_free(constraint_t *con) {
    assert(con);

    _destroy_subtree(con->root);
    for (uint32_t i = 0; i < (1u << RADIX_LENGTH); i++)
        mpz_clear(con->radix[i]);
    mpz_clear(con->paint_value);
    free(con);
    mpz_clear(IPVX_HALF_INDEX);
    mpz_clear(IPVX_MAX_INDEX);
    mpz_clear(RADIX_SIZE);

    log_debug("constraint", "cleaning up");
}

// Convert from an internal node to a leaf.
static void _convert_to_leaf(node_t *node) {
    assert(node);
    assert(!IS_LEAF(node));

    _destroy_subtree(node->l);
    _destroy_subtree(node->r);
    node->l = NULL;
    node->r = NULL;
}

// Recursive function to set value for a given network prefix within
// the tree. (Note: prefix must be in host byte order.)
static void _set_recurse(node_t *node, const mpz_t prefix, int len,
                         const mpz_t value) {
    assert(node);
    assert(0 <= len && len <= IPVX_MAX_PREFIX_LEN);

    //    _print_ip(prefix, len);
    if (len == 0) {
        // We're at the end of the prefix; make this a leaf and set the
        // value.
        if (!IS_LEAF(node)) {
            _convert_to_leaf(node);
        }
        mpz_set(node->value, value);
        return;
    }

    if (IS_LEAF(node)) {
        // We're not at the end of the prefix, but we hit a leaf.
        if (mpz_eq(node->value, value)) {
            // A larger prefix has the same value, so we're done.
            return;
        }
        // The larger prefix has a different value, so we need to
        // convert it into an internal node and continue processing on
        // one of the leaves.
        node->l = _create_leaf(node->value);
        node->r = _create_leaf(node->value);
    }

    // We're not at the end of the prefix, and we're at an internal
    // node.  Recurse on the left or right subtree.
    mpz_t flag, prefix_1;
    mpz_init(flag);
    mpz_and(flag, prefix, IPVX_HALF_INDEX);
    mpz_init(prefix_1);
    mpz_mul_ui(prefix_1, prefix, 2);
    mpz_mod(prefix_1, prefix_1, IPVX_MAX_INDEX);

    if (mpz_not_zero(flag)) {
        _set_recurse(node->r, prefix_1, len - 1, value);
    } else {
        _set_recurse(node->l, prefix_1, len - 1, value);
    }

    mpz_clear(flag);
    mpz_clear(prefix_1);

    // At this point, we're an internal node, and the value is set
    // by one of our children or its descendent.  If both children are
    // leaves with the same value, we can discard them and become a left.
    if (IS_LEAF(node->r) && IS_LEAF(node->l) &&
        mpz_eq(node->r->value, node->l->value)) {
        mpz_set(node->value, node->l->value);
        _convert_to_leaf(node);
    }
}

// Set the value for a given network prefix, overwriting any existing
// values on that prefix or subsets of it.
// (Note: prefix must be in host byte order.)
void constraint_set(constraint_t *con, const mpz_t prefix, int len,
                    const mpz_t value) {
    assert(con);

    _set_recurse(con->root, prefix, len, value);
    con->painted = 0;
}

// Return the value pertaining to an address, according to the tree
// starting at given root.  (Note: address must be in host byte order.)
static void _lookup_ipvx(mpz_t value, node_t *root, const mpz_t address) {
    assert(root);

    node_t *node = root;
    mpz_t   flag, mask;
    mpz_init(flag);
    mpz_init_set(mask, IPVX_HALF_INDEX);

    for (;;) {
        if (IS_LEAF(node)) {
            mpz_set(value, node->value);
            mpz_clear(flag);
            mpz_clear(mask);
            return;
        }
        mpz_and(flag, address, mask);

        if (mpz_not_zero(flag)) {
            node = node->r;
        } else {
            node = node->l;
        }
        mpz_fdiv_q_ui(mask, mask, 2);
    }
}

// Return the value pertaining to an address.
// (Note: address must be in host byte order.)
void constraint_lookup_ipvx_for_value(mpz_t value, constraint_t *con,
                                      const mpz_t ipvx) {
    assert(con);

    _lookup_ipvx(value, con->root, ipvx);
}

// Implement count_ips by recursing on halves of the tree.  Size represents
// the number of addresses in a prefix at the current level of the tree.
// If paint is specified, each node will have its count set to the number of
// leaves under it set to value.
// If exclude_radix is specified, the number of addresses will exclude prefixes
// that are a /RADIX_LENGTH or larger
static void _count_ipvx_recurse(mpz_t count, node_t *node, const mpz_t value,
                                const mpz_t size, int paint,
                                int exclude_radix) {
    assert(node);

    //    log_debug("constraint", "_count_ips_recurse(size): %s",
    //    mpz_to_str10(size));
    if (IS_LEAF(node)) {
        if (mpz_eq(node->value, value)) {
            mpz_set(count, size);
            // Exclude prefixes already included in the radix
            if (exclude_radix &&
                mpz_ge(size, RADIX_SIZE)) { // save for length > RADIX_LENGTH
                mpz_set_ui(count, 0);
            }
        } else {
            mpz_set_ui(count, 0);
        }
    } else { // +
        mpz_t count_l, count_r, size_2;
        mpz_init(count_l);
        mpz_init(count_r);
        mpz_init(size_2);
        mpz_fdiv_q_ui(size_2, size, 2);
        _count_ipvx_recurse(count_l, node->l, value, size_2, paint,
                            exclude_radix);
        _count_ipvx_recurse(count_r, node->r, value, size_2, paint,
                            exclude_radix);
        mpz_add(count, count_l, count_r);
        //        log_debug("constraint", "_count_ipvx_recurse(count_l): %s",
        //        mpz_to_str10(count_l)); log_debug("constraint",
        //        "_count_ipvx_recurse(count_r): %s", mpz_to_str10(count_r));
        //        log_debug("constraint", "_count_ipvx_recurse(count): %s",
        //        mpz_to_str10(count));

        mpz_clear(count_l);
        mpz_clear(count_r);
        mpz_clear(size_2);
    }

    if (paint) {
        mpz_set(node->count, count);
    }
}

// Return the number of addresses that have a given value.
void constraint_count_ipvx_of_value(mpz_t count, constraint_t *con,
                                    const mpz_t value) {
    assert(con);

    if (con->painted && mpz_eq(con->paint_value, value)) {
        //        log_debug("constraint",
        //        "constraint_count_ipvx_of_value(painted)");
        mpz_t t;
        mpz_init(t);
        mpz_mul_ui(t, RADIX_SIZE, con->radix_len);
        mpz_add(count, con->root->count, t);
        mpz_clear(t);

        return;
    } else {
        //        log_debug("constraint",
        //        "constraint_count_ipvx_of_value(recurse)");
        _count_ipvx_recurse(count, con->root, value, IPVX_MAX_INDEX, 0, 0);
    }
}

// Return a node that determines the values for the addresses with
// the given prefix.  This is either the internal node that
// corresponds to the end of the prefix or a leaf node that
// encompasses the prefix. (Note: prefix must be in host byte order.)
static node_t *_lookup_node(node_t *root, const mpz_t prefix, int len) {
    assert(root);
    assert(0 <= len && len <= IPVX_MAX_PREFIX_LEN);

    node_t *node = root;
    mpz_t   flag, mask;
    mpz_init(flag);
    mpz_init_set(mask, IPVX_HALF_INDEX);

    int i;
    for (i = 0; i < len; i++) {
        if (IS_LEAF(node)) {
            goto cleanup;
        }
        mpz_and(flag, prefix, mask);
        if (mpz_not_zero(flag)) {
            node = node->r;
        } else {
            node = node->l;
        }
        mpz_fdiv_q_ui(mask, mask, 2);
    }

cleanup:
    mpz_clear(flag);
    mpz_clear(mask);

    return node;
}

// For each node, precompute the count of leaves beneath it set to value.
// Note that the tree can be painted for only one value at a time.
void constraint_paint_value(constraint_t *con, const mpz_t value) {
    assert(con);
    log_debug("constraint", "painting value %s", mpz_to_str10(value));

    // Paint everything(count) except what we will put in radix
    mpz_t count;
    mpz_init(count);
    _count_ipvx_recurse(count, con->root, value, IPVX_MAX_INDEX, 1, 1);
    mpz_clear(count);

    // Fill in the radix array with a list of addresses
    size_t i;
    con->radix_len = 0;
    mpz_t prefix;
    mpz_init(prefix);
    for (i = 0; i < (1u << RADIX_LENGTH); i++) { // /RADIX_LENGTH = /20
        mpz_mul_ui(prefix, RADIX_SIZE, i);
        node_t *node = _lookup_node(con->root, prefix, RADIX_LENGTH);
        if (IS_LEAF(node) && mpz_eq(node->value, value)) {
            // Add this prefix to the radix
            mpz_init_set(con->radix[con->radix_len++], prefix);
        }
    }
    mpz_clear(prefix);

    mpz_t radix_c;
    mpz_init(radix_c);
    mpz_mul_ui(radix_c, RADIX_SIZE, con->radix_len);
    log_debug(
        "constraint", "%s IPvXs in radix array, %s IPvXs in tree, radix-len=%d",
        mpz_to_str10(radix_c), mpz_to_str10(con->root->count), con->radix_len);
    mpz_clear(radix_c);

    con->painted = 1;
    mpz_set(con->paint_value, value);
}

// Return the nth painted IP address.
static void _lookup_index(mpz_t ip, node_t *root, const mpz_t index) {
    assert(root);

    node_t *node = root;
    mpz_set_ui(ip, 0);
    mpz_t mask, n;
    mpz_init_set(mask, IPVX_HALF_INDEX);
    mpz_init_set(n, index);

    for (;;) {
        if (IS_LEAF(node)) {
            mpz_ior(ip, ip, n); // prefix
            mpz_clear(mask);
            mpz_clear(n);
            return;
        }
        if (mpz_lt(n, node->l->count)) {
            node = node->l;
        } else {
            mpz_sub(n, n, node->l->count);
            node = node->r;
            mpz_ior(ip, ip, mask);
        }
        mpz_fdiv_q_ui(mask, mask, 2);
    }
}

// For a given value, return the IP address with zero-based index n.
// (i.e., if there are three addresses with value 0xFF, looking up index 1
// will return the second one).
// Note that the tree must have been previously painted with this value.
void constraint_lookup_index_for_ipvx(mpz_t ipvx, constraint_t *con,
                                      const mpz_t index, const mpz_t value) {
    assert(con);

    if (!con->painted || mpz_ne(con->paint_value, value)) {
        constraint_paint_value(con, value);
    }

    mpz_t radix_idx;
    mpz_init(radix_idx);
    mpz_fdiv_q(radix_idx, index, RADIX_SIZE);
    if (mpz_lt_ui(radix_idx, con->radix_len)) {
        // Radix lookup
        mpz_t radix_offset;
        mpz_init(radix_offset);
        mpz_mod(radix_offset, index, RADIX_SIZE);
        mpz_ior(ipvx, con->radix[mpz_get_ui(radix_idx)],
                radix_offset); // TODO radix_idx is no more than int32
        mpz_clear(radix_offset);
        mpz_clear(radix_idx);
        return;
    }
    mpz_clear(radix_idx);

    // Otherwise, do the "slow" lookup in tree.
    // Note that tree counts do NOT include things in the radix,
    // so we subtract these off here.
    mpz_t t, n;
    mpz_init(t);
    mpz_mul_ui(t, RADIX_SIZE, con->radix_len);
    mpz_init(n);
    mpz_sub(n, index, t);
    mpz_clear(t);
    assert(mpz_lt(n, con->root->count));
    _lookup_index(ipvx, con->root, n);
    mpz_clear(n);
}

// ui using
constraint_t *constraint_init_ui(mpz_t_ui32 value, size_t ipvx_max_len) {
    mpz_t value_m;
    mpz_init_set_ui(value_m, value);
    constraint_t *con = constraint_init(value_m, ipvx_max_len);
    mpz_clear(value_m);

    return con;
}

void constraint_set_ui(constraint_t *con, const mpz_t prefix, int len,
                       mpz_t_ui32 value) {
    mpz_t value_m;
    mpz_init_set_ui(value_m, value);
    constraint_set(con, prefix, len, value_m);
    mpz_clear(value_m);
}

void constraint_paint_value_ui(constraint_t *con, mpz_t_ui32 value) {
    mpz_t value_m;
    mpz_init_set_ui(value_m, value);
    constraint_paint_value(con, value_m);
    mpz_clear(value_m);
}

void constraint_lookup_index_for_ipvx_ui(mpz_t ipvx, constraint_t *con,
                                         const mpz_t index, mpz_t_ui32 value) {
    mpz_t value_m;
    mpz_init_set_ui(value_m, value);
    constraint_lookup_index_for_ipvx(ipvx, con, index, value_m);
    mpz_clear(value_m);
}

void constraint_count_ipvx_of_value_ui(mpz_t count, constraint_t *con,
                                       mpz_t_ui32 value) {
    mpz_t value_m;
    mpz_init_set_ui(value_m, value);
    constraint_count_ipvx_of_value(count, con, value_m);
    mpz_clear(value_m);
}

mpz_t_ui32 constraint_lookup_ipvx_for_value_ui(constraint_t *con,
                                               const mpz_t   ipvx) {
    mpz_t value_m;
    mpz_init(value_m);
    constraint_lookup_ipvx_for_value(value_m, con, ipvx);
    mpz_t_ui32 value = (mpz_t_ui32) mpz_get_ui(value_m);
    mpz_clear(value_m);

    return value;
}

// uint32_t compatible
void constraint_set_32(constraint_t *con, mpz_t_ui32 prefix, int len,
                       mpz_t_ui32 value) {
    mpz_t prefix_m, value_m;
    mpz_init_set_ui(prefix_m, prefix);
    mpz_init_set_ui(value_m, value);
    constraint_set(con, prefix_m, len, value_m);
    mpz_clear(prefix_m);
    mpz_clear(value_m);
}

mpz_t_ui32 constraint_lookup_ipvx_for_value_32(constraint_t *con,
                                               mpz_t_ui32    ipvx) {
    mpz_t value_m, address_m;
    mpz_init(value_m);
    mpz_init_set_ui(address_m, ipvx);
    constraint_lookup_ipvx_for_value(value_m, con, address_m);
    mpz_t_ui32 value = (mpz_t_ui32) mpz_get_ui(value_m);
    mpz_clear(value_m);
    mpz_clear(address_m);

    return value;
}

mpz_t_ui64 constraint_count_ipvx_of_value_32(constraint_t *con,
                                             mpz_t_ui32    value) {
    mpz_t count_m, value_m;
    mpz_init(count_m);
    mpz_init_set_ui(value_m, value);
    constraint_count_ipvx_of_value(count_m, con, value_m);
    mpz_t_ui64 count = (mpz_t_ui64) mpz_get_ui(count_m);
    mpz_clear(value_m);
    mpz_clear(count_m);

    return count;
}

mpz_t_ui32 constraint_lookup_index_for_ipvx_32(constraint_t *con,
                                               mpz_t_ui64    index,
                                               mpz_t_ui32    value) {
    mpz_t index_m, value_m, ipvx_m;
    mpz_init_set_ui(index_m, index);
    mpz_init_set_ui(value_m, value);
    mpz_init(ipvx_m);
    constraint_lookup_index_for_ipvx(ipvx_m, con, index_m, value_m);
    mpz_t_ui32 ipvx = (mpz_t_ui32) mpz_get_ui(ipvx_m);
    mpz_clear(index_m);
    mpz_clear(value_m);
    mpz_clear(ipvx_m);

    return ipvx;
}
