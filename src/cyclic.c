/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "cyclic.h"

#include <assert.h>
#include <gmp-ext.h>

#include "../lib/logger.h"

#define GROUPS_SIZE 41

static cyclic_group_t groups[GROUPS_SIZE];

static _cyclic_group_t _groups[GROUPS_SIZE] = {
    {
        // 2^4 + 1
        .prime          = "17",
        .known_primroot = "3",
        .prime_factors =
            {
                "2",
            },
        .num_prime_factors = 1,
    },
    {
        // 2^8 + 1
        .prime          = "257",
        .known_primroot = "3",
        .prime_factors =
            {
                "2",
            },
        .num_prime_factors = 1,
    },
    {
        // 2^12 + 3
        .prime          = "4099",
        .known_primroot = "2",
        .prime_factors =
            {
                "2",
                "3",
                "683",
            },
        .num_prime_factors = 3,
    },
    {
        // 2^16 + 1
        .prime          = "65537",
        .known_primroot = "3",
        .prime_factors =
            {
                "2",
            },
        .num_prime_factors = 1,
    },
    {
        // 2^20 + 7
        .prime          = "1048583",
        .known_primroot = "5",
        .prime_factors =
            {
                "101",
                "179",
                "2",
                "29",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^24 + 43
        .prime          = "16777259",
        .known_primroot = "2",
        .prime_factors =
            {
                "103",
                "2",
                "23",
                "3541",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^28 + 3
        .prime          = "268435459",
        .known_primroot = "2",
        .prime_factors =
            {
                "19",
                "2",
                "3",
                "87211",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^32 + 15
        .prime          = "4294967311",
        .known_primroot = "3",
        .prime_factors =
            {
                "131",
                "2",
                "3",
                "364289",
                "5",
            },
        .num_prime_factors = 5,
    },
    {
        // 2^36 + 31
        .prime          = "68719476767",
        .known_primroot = "5",
        .prime_factors =
            {
                "163",
                "2",
                "238727",
                "883",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^40 + 15
        .prime          = "1099511627791",
        .known_primroot = "3",
        .prime_factors =
            {
                "2",
                "3",
                "36650387593",
                "5",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^44 + 7
        .prime          = "17592186044423",
        .known_primroot = "5",
        .prime_factors =
            {
                "11",
                "155542661",
                "2",
                "53",
                "97",
            },
        .num_prime_factors = 5,
    },
    {
        // 2^48 + 21
        .prime          = "281474976710677",
        .known_primroot = "6",
        .prime_factors =
            {
                "1361",
                "2",
                "2462081249",
                "3",
                "7",
            },
        .num_prime_factors = 5,
    },
    {
        // 2^52 + 21
        .prime          = "4503599627370517",
        .known_primroot = "2",
        .prime_factors =
            {
                "2",
                "23",
                "3",
                "612229",
                "987127",
            },
        .num_prime_factors = 5,
    },
    {
        // 2^56 + 81
        .prime          = "72057594037928017",
        .known_primroot = "10",
        .prime_factors =
            {
                "14557303",
                "2",
                "3",
                "34501",
                "61",
                "7",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^60 + 33
        .prime          = "1152921504606847009",
        .known_primroot = "13",
        .prime_factors =
            {
                "11",
                "2",
                "2971",
                "3",
                "48912491",
                "683",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^64 + 13
        .prime          = "18446744073709551629",
        .known_primroot = "2",
        .prime_factors =
            {
                "2",
                "658812288346769701",
                "7",
            },
        .num_prime_factors = 3,
    },
    {
        // 2^68 + 33
        .prime          = "295147905179352825889",
        .known_primroot = "29",
        .prime_factors =
            {
                "19",
                "2",
                "3",
                "43",
                "5419",
                "77158673929",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^72 + 15
        .prime          = "4722366482869645213711",
        .known_primroot = "6",
        .prime_factors =
            {
                "2",
                "3",
                "4799",
                "5",
                "541316653",
                "60594931",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^76 + 15
        .prime          = "75557863725914323419151",
        .known_primroot = "3",
        .prime_factors =
            {
                "2",
                "3",
                "5",
                "518763225032024191",
                "971",
            },
        .num_prime_factors = 5,
    },
    {
        // 2^80 + 13
        .prime          = "1208925819614629174706189",
        .known_primroot = "2",
        .prime_factors =
            {
                "1093",
                "2",
                "31039",
                "8908647580887961",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^84 + 3
        .prime          = "19342813113834066795298819",
        .known_primroot = "2",
        .prime_factors =
            {
                "1163",
                "13455809771",
                "155377",
                "2",
                "2657",
                "3",
                "499",
            },
        .num_prime_factors = 7,
    },
    {
        // 2^88 + 7
        .prime          = "309485009821345068724781063",
        .known_primroot = "5",
        .prime_factors =
            {
                "2",
                "228791153858291",
                "676348286641",
            },
        .num_prime_factors = 3,
    },
    {
        // 2^92 + 25
        .prime          = "4951760157141521099596496921",
        .known_primroot = "3",
        .prime_factors =
            {
                "11411",
                "2",
                "296131229",
                "5",
                "5233517194231",
                "7",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^96 + 61
        .prime          = "79228162514264337593543950397",
        .known_primroot = "2",
        .prime_factors =
            {
                "1032208068610458304152691",
                "2",
                "31",
                "619",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^100 + 277
        .prime          = "1267650600228229401496703205653",
        .known_primroot = "2",
        .prime_factors =
            {
                "2",
                "52203989",
                "6070659658921032842417",
            },
        .num_prime_factors = 3,
    },
    {
        // 2^104 + 111
        .prime          = "20282409603651670423947251286127",
        .known_primroot = "3",
        .prime_factors =
            {
                "2",
                "3",
                "3544157",
                "953795670058807140125153",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^108 + 33
        .prime          = "324518553658426726783156020576289",
        .known_primroot = "13",
        .prime_factors =
            {
                "2",
                "3",
                "415141630193",
                "8142767081771726171",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^112 + 25
        .prime          = "5192296858534827628530496329220121",
        .known_primroot = "3",
        .prime_factors =
            {
                "1201",
                "2",
                "28976429",
                "3730024228806121761107",
                "5",
            },
        .num_prime_factors = 5,
    },
    {
        // 2^116 + 33
        .prime          = "83076749736557242056487941267521569",
        .known_primroot = "23",
        .prime_factors =
            {
                "107775231312019",
                "17539",
                "1777",
                "2",
                "25781083",
                "3",
                "3331",
            },
        .num_prime_factors = 7,
    },
    {
        // 2^120 + 451
        .prime          = "1329227995784915872903807060280345027",
        .known_primroot = "2",
        .prime_factors =
            {
                "1097",
                "11",
                "1361",
                "170777",
                "2",
                "233",
                "322747",
                "41",
                "76856512570457",
            },
        .num_prime_factors = 9,
    },
    {
        // 2^124 + 67
        .prime          = "21267647932558653966460912964485513283",
        .known_primroot = "2",
        .prime_factors =
            {
                "1216997",
                "187385987",
                "2",
                "30265284680791",
                "37578049",
                "41",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^128 + 51
        .prime          = "340282366920938463463374607431768211507",
        .known_primroot = "2",
        .prime_factors =
            {
                "12275703273579557140363",
                "17",
                "2",
                "3",
                "5816689",
                "6481",
                "89",
            },
        .num_prime_factors = 7,
    },
    {
        // 2^132 + 67
        .prime          = "5444517870735015415413993718908291383363",
        .known_primroot = "2",
        .prime_factors =
            {
                "1203053633927087259807466469264791",
                "2",
                "33773",
                "67",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^136 + 85
        .prime          = "87112285931760246646623899502532662132821",
        .known_primroot = "2",
        .prime_factors =
            {
                "17",
                "2",
                "2971",
                "5",
                "909288538628219561960108944043",
                "94841",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^140 + 37
        .prime          = "1393796574908163946345982392040522594123813",
        .known_primroot = "2",
        .prime_factors =
            {
                "2",
                "577",
                "603897996060729612801552162929169234889",
            },
        .num_prime_factors = 3,
    },
    {
        // 2^144 + 175
        .prime          = "22300745198530623141535718272648361505980591",
        .known_primroot = "11",
        .prime_factors =
            {
                "2",
                "318582074264723187736224546752119450085437",
                "5",
                "7",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^148 + 91
        .prime          = "356811923176489970264571492362373784095686747",
        .known_primroot = "2",
        .prime_factors =
            {
                "2",
                "2101356628765871089073845955673091001",
                "84900373",
            },
        .num_prime_factors = 3,
    },
    {
        // 2^152 + 253
        .prime          = "5708990770823839524233143877797980545530986749",
        .known_primroot = "2",
        .prime_factors =
            {
                "2",
                "4078967803638757",
                "5869896824746875009979",
                "59609929",
            },
        .num_prime_factors = 4,
    },
    {
        // 2^156 + 45
        .prime          = "91343852333181432387730302044767688728495783981",
        .known_primroot = "2",
        .prime_factors =
            {
                "192877",
                "2",
                "254572484479",
                "279758154954693590105219",
                "3",
                "36943",
                "5",
            },
        .num_prime_factors = 7,
    },
    {
        // 2^160 + 7
        .prime          = "1461501637330902918203684832716283019655932542983",
        .known_primroot = "7",
        .prime_factors =
            {
                "173848897619",
                "2",
                "227",
                "23597270538777567674355013037",
                "27059",
                "29",
            },
        .num_prime_factors = 6,
    },
    {
        // 2^164 + 117
        .prime          = "23384026197294446691258957323460528314494920687733",
        .known_primroot = "2",
        .prime_factors =
            {
                "11",
                "14895633521",
                "2",
                "3",
                "371631372010427",
                "5536990114014791",
                "5779633",
            },
        .num_prime_factors = 7,
    },
};

#define MPZ_STR_BASE 10

// Generate groups from _groups
static void make_groups() {
    for (size_t i = 0; i < GROUPS_SIZE; i++) {
        mpz_init_set_str(groups[i].prime, _groups[i].prime, MPZ_STR_BASE);
        mpz_init_set_str(groups[i].known_primroot, _groups[i].known_primroot,
                         MPZ_STR_BASE);
        groups[i].num_prime_factors = _groups[i].num_prime_factors;

        for (size_t j = 0; j < _groups[i].num_prime_factors; j++) {
            mpz_init_set_str(groups[i].prime_factors[j],
                             _groups[i].prime_factors[j], MPZ_STR_BASE);
        }
    }
}

// Check whether an integer is coprime with (p - 1)
static int is_coprime(const mpz_t check, const cyclic_group_t *group) {
    int flag = 0;
    if (mpz_eq_ui(check, 0) || mpz_eq_ui(check, 1)) {
        return flag;
    }

    mpz_t t;
    mpz_init(t);
    for (size_t i = 0; i < group->num_prime_factors; i++) {
        if (mpz_gt(group->prime_factors[i], check)) {
            mpz_mod(t, group->prime_factors[i], check);
            if (mpz_eq_ui(t, 0)) goto cleanup;
        } else if (mpz_lt(group->prime_factors[i], check)) {
            mpz_mod(t, check, group->prime_factors[i]);
            if (mpz_eq_ui(t, 0)) goto cleanup;
        } else
            goto cleanup;
    }

    flag = 1;
cleanup:
    mpz_clear(t);

    return flag;
}

// Perform the isomorphism from (Z/pZ)+ to (Z/pZ)*
// Given known primitive root of (Z/pZ)* n, with x in (Z/pZ)+, do:
//	f(x) = n^x mod p
//
// The isomorphism in the reverse direction is discrete log, and is
// therefore hard.
static void isomorphism(mpz_t primroot, const mpz_t additive_elt,
                        const cyclic_group_t *mult_group) {
    assert(mpz_lt(additive_elt, mult_group->prime));
    mpz_powm(primroot, mult_group->known_primroot, additive_elt,
             mult_group->prime);

    log_debug("cyclic", "isomorphism: %s", mpz_to_str10(primroot));
}

// Return a (random) number coprime with (p - 1) of the group,
// which is a generator of the additive group mod (p - 1)
static void find_primroot(mpz_t primroot, const cyclic_group_t *group,
                          aesrand_t *aes) {
    mpz_t candidate;
    //    mpz_init_set_ui(candidate, aesrand_getword(aes));
    mpz_init(candidate);
    aesrand_get128bits(candidate, aes);
    mpz_mod(candidate, candidate, group->prime);

    while (!is_coprime(candidate, group)) {
        mpz_add_ui(candidate, candidate, 1);
        mpz_mod(candidate, candidate, group->prime);
    }
    isomorphism(primroot, candidate, group);
    log_debug("cyclic", "primitive root: %s", mpz_to_str10(primroot));
    mpz_clear(candidate);
}

// Get a cyclic_group_t of at least min_size.
// Pointer into static data, do not free().
const cyclic_group_t *get_group(const mpz_t min_size) {
    make_groups();
    for (size_t i = 0; i < GROUPS_SIZE; i++) {
        if (mpz_gt(groups[i].prime, min_size)) {
            log_debug("cyclic", "prime: %s", mpz_to_str10(groups[i].prime));
            return &groups[i];
        }
    }

    // Should not reach, final group should always be larger than 2^32
    assert(0);
}

cycle_t make_cycle(const cyclic_group_t *group, aesrand_t *aes) {
    cycle_t cycle;

    cycle.group = group;
    mpz_init(cycle.generator);
    find_primroot(cycle.generator, group, aes);

    mpz_t t;
    // mpz_init_set_ui(t, aesrand_getword(aes));
    mpz_init(t);
    aesrand_get128bits(t, aes);
    mpz_init(cycle.offset);
    mpz_mod(cycle.offset, t, group->prime);
    log_debug("cyclic", "cycle offset: %s", mpz_to_str10(cycle.offset));
    mpz_clear(t);

    mpz_init(cycle.order);
    mpz_sub_ui(cycle.order, group->prime, 1);
    log_debug("cyclic", "cycle order: %s", mpz_to_str10(cycle.order));

    return cycle;
}

void close_cycle(cycle_t cycle) {
    mpz_clear(cycle.generator);
    mpz_clear(cycle.offset);
    mpz_clear(cycle.order);

    log_debug("cycle", "cleaning up");
}
