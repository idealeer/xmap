# sources file
set(LIB_SOURCES
        blocklist.c
        bloom.c
        constraint.c
        csv.c
        gmp-ext.c
        lockfd.c
        logger.c
        random.c
        rijndael-alg-fst.c
        util.c
        xalloc.c
        )

if (WITH_REDIS)
    SET(LIB_SOURCES ${LIB_SOURCES} redis.c)
endif()

# gen link target
add_library(xmaplib
        STATIC ${LIB_SOURCES}
        )

# specify the dir for gen target
target_include_directories(xmaplib
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
        )
