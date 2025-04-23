####
# A Docker container for running xmap
#
# To build, beware of caching and:
#
#   * If you wish to build current master
#
#        docker build --build-arg xmapVersion={version} -t xmap_ubuntu -f Dockerfile .
#
#   * If you wish to build a specific commit, use the XMAP_COMMIT build argument.
#
#        docker build --build-arg xmapVersion={version} -t xmap_ubuntu -f Dockerfile --build-arg XMAP_COMMIT=<your commit> .
#
# To run:
#
#     docker run -it --rm --net=host xmap_ubuntu <xmap args>
####

FROM ubuntu

ARG xmapVersion=latest

RUN set -x; buildDeps='build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc \
    libjson-c-dev pkg-config libunistring-dev wget' \
    && apt-get update \
    && apt-get install -y $buildDeps \
    && wget "https://github.com/idealeer/xmap/releases/download/${xmapVersion}/xmap-${xmapVersion}.tar.gz" \
    && tar -xzf xmap-$xmapVersion.tar.gz \
    && cd xmap-$xmapVersion \
    && cmake . \
    && make -j4 \
    && make install \
    && cd .. \
    && rm -rf xmap-$xmapVersion \
    && rm xmap-$xmapVersion.tar.gz \
    && apt-get purge \
    && apt-get autoremove
