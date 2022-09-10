include_directories(
        "${CMAKE_CURRENT_BINARY_DIR}"
        ${PROJECT_SOURCE_DIR}/lib
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/src/output_modules
        ${PROJECT_SOURCE_DIR}/src/tests
)

# ADD YOUR OUTPUT MODULE HERE
set(EXTRA_SOURCES_OUTPUT_MODULES
        )

# ADD YOUR PROBE MODULE HERE
set(EXTRA_SOURCES_PROBE_MODULES
        )

# ADD YOUR IID MODULE HERE
set(EXTRA_SOURCES_IID_MODULES
        )

set(SOURCES_OUTPUT_MODULES
        output_modules/output_modules.c
        output_modules/module_csv.c
        )

# Handle optional output modules
if(WITH_JSON)
    set(SOURCES_OUTPUT_MODULES
            ${SOURCES_OUTPUT_MODULES}
            output_modules/module_json.c
            )
endif()

if(WITH_REDIS)
    set(SOURCES_OUTPUT_MODULES
            ${SOURCES_OUTPUT_MODULES}
            output_modules/module_redis_csv.c
            output_modules/module_redis_packed.c
            )
endif()

set(SOURCES_PROBE_MODULES
        probe_modules/packet.c
        probe_modules/packet_icmp.c
        probe_modules/packet_icmp6.c
        probe_modules/probe_modules.c
        probe_modules/module_icmp_echo.c
        probe_modules/module_icmp6_echo.c
        probe_modules/module_icmp6_echo_gw.c
        probe_modules/module_icmp6_echo_tmxd.c
        probe_modules/module_tcp_scan.c
        probe_modules/module_tcp_syn.c
        probe_modules/module_tcp6_syn.c
        probe_modules/module_udp.c
        probe_modules/module_udp6.c
        probe_modules/module_dns.c
        probe_modules/module_dnsr.c
        probe_modules/module_dnsx.c
        probe_modules/module_dnsf.c
        probe_modules/module_dnsz.c
        probe_modules/module_dnss.c
        probe_modules/module_dnsv.c
        )

set(SOURCES_IID_MODULES
        iid_modules/iid_modules.c
        iid_modules/module_full.c
        iid_modules/module_low.c
        iid_modules/module_low_fill.c
        iid_modules/module_rand.c
        iid_modules/module_set.c
        iid_modules/module_zero.c
        )

set(SOURCES
        aesrand.c
        cyclic.c
        expression.c
        fieldset.c
        filter.c
        get_gateway.c
        iterator.c
        ip_target_file.c
        monitor.c
        recv.c
        send.c
        shard.c
        socket.c
        state.c
        summary.c
        utility.c
        validate.c
        xmap.c
        xopt_include.c
        "${CMAKE_CURRENT_BINARY_DIR}/xopt.h"
        "${CMAKE_CURRENT_BINARY_DIR}/lexer.c"
        "${CMAKE_CURRENT_BINARY_DIR}/parser.c"
        ${SOURCES_IID_MODULES}
        ${SOURCES_OUTPUT_MODULES}
        ${SOURCES_PROBE_MODULES}
        ${EXTRA_SOURCES_IID_MODULES}
        ${EXTRA_SOURCES_OUTPUT_MODULES}
        ${EXTRA_SOURCES_PROBE_MODULES}
        )

#set(SOURCES_XTEST
#        aesrand.c
#        cyclic.c
#        expression.c
#        fieldset.c
#        filter.c
#        get_gateway.c
#        iterator.c
#        ip_target_file.c
#        monitor.c
#        recv.c
#        send.c
#        shard.c
#        socket.c
#        state.c
#        summary.c
#        utility.c
#        validate.c
#        tests/xtest.c
#        xopt_include.c
#        "${CMAKE_CURRENT_BINARY_DIR}/xopt.h"
#        "${CMAKE_CURRENT_BINARY_DIR}/lexer.c"
#        "${CMAKE_CURRENT_BINARY_DIR}/parser.c"
#        ${SOURCES_IID_MODULES}
#        ${SOURCES_OUTPUT_MODULES}
#        ${SOURCES_PROBE_MODULES}
#        ${EXTRA_SOURCES_IID_MODULES}
#        ${EXTRA_SOURCES_OUTPUT_MODULES}
#        ${EXTRA_SOURCES_PROBE_MODULES}
#        )

# Handle various versions of socket
if (WITH_PFRING)
    set(SOURCES ${SOURCES} socket-pfring.c)
    #    set(SOURCES_XTEST ${SOURCES_XTEST} socket-pfring.c)
elseif (APPLE OR BSD)
    set(SOURCES ${SOURCES} socket-bsd.c)
    #    set(SOURCES_XTEST ${SOURCES_XTEST} socket-bsd.c)
else ()
    set(SOURCES ${SOURCES} socket-linux.c)
    #    set(SOURCES_XTEST ${SOURCES_XTEST} socket-linux.c)
endif ()

# Handle various versions of recv
if (WITH_PFRING)
    set(SOURCES ${SOURCES} recv-pfring.c)
    #    set(SOURCES_XTEST ${SOURCES_XTEST} recv-pfring.c)
else ()
    set(SOURCES ${SOURCES} recv-pcap.c)
    #    set(SOURCES_XTEST ${SOURCES_XTEST} recv-pcap.c)
endif ()

# Set configure time xmap version
configure_file(xopt.ggo.in ${CMAKE_BINARY_DIR}/src/xopt.ggo @ONLY)
# Additional ggo.in's should be added here and CMakeVersion.txt

# This sets a *build* time dependency that checks git
if("${XMAP_VERSION}" STREQUAL "DEVELOPMENT")
    add_custom_target(git_versioning ALL
            COMMAND ${CMAKE_COMMAND} -D ORIG_SRC_DIR:STRING="${CMAKE_SOURCE_DIR}" -P "${CMAKE_SOURCE_DIR}/src/CMakeVersion.txt"
            )
endif()

add_custom_command(
        OUTPUT xopt.h
        COMMAND gengetopt -C --no-help --no-version --unamed-opts=SUBNETS -i "${CMAKE_CURRENT_BINARY_DIR}/xopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/xopt"
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/xopt.ggo"
)

add_custom_command(
        OUTPUT lexer.c
        COMMAND flex -o "${CMAKE_CURRENT_BINARY_DIR}/lexer.c" --header-file="${CMAKE_CURRENT_BINARY_DIR}/lexer.h" "${CMAKE_CURRENT_SOURCE_DIR}/lexer.l"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/lexer.l"
)

if (NetBSD)
    add_custom_command(
            OUTPUT parser.c
            COMMAND yacc -d -o "${CMAKE_CURRENT_BINARY_DIR}/parser.c" "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
    )
else ()
    add_custom_command(
            OUTPUT parser.c
            COMMAND byacc -d -o "${CMAKE_CURRENT_BINARY_DIR}/parser.c" "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
    )
endif ()

add_custom_target(manpages
        ronn "${CMAKE_CURRENT_SOURCE_DIR}/xmap.1.ronn" --organization="XMap" --manual="xmap"
        SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/xmap.1.ronn"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        )

# gen target
#add_executable(xtest
#        ${SOURCES_XTEST}
#        )

add_executable(xmap
        ${SOURCES}
        )

if (APPLE OR BSD)
    set(DNET_LIBRARIES "dnet")
else ()
    set(DNET_LIBRARIES "")
endif ()

# lib for gen target
#target_link_libraries(xtest
#        xmaplib
#        ${PFRING_LIBRARIES}
#        pcap gmp m unistring
#        ${DNET_LIBRARIES}
#        ${REDIS_LIBS}
#        ${JSON_LIBRARIES}
#        )

target_link_libraries(xmap
        xmaplib
        ${PFRING_LIBRARIES}
        pcap gmp m unistring
        ${DNET_LIBRARIES}
        ${REDIS_LIBS}
        ${JSON_LIBRARIES}
        )

# Install binary
install(
        TARGETS
        xmap
        RUNTIME DESTINATION sbin
)

# Install Manpages
install(
        FILES
        xmap.1
        DESTINATION share/man/man1
)
