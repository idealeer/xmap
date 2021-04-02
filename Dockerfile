####
# A Docker container for running xmap
#
# To build, beware of caching and:
#
#   * If you wish to build current master
#
#        docker build -t xmap_ubuntu -f Dockerfile .
#
#   * If you wish to build a specific commit, use the XMAP_COMMIT build argument.
#
#        docker build -t xmap_ubuntu -f Dockerfile --build-arg XMAP_COMMIT=<your commit> .
#
# To run:
#
#     docker run  -it --rm --net=host xmap_ubuntu <xmap args>
####

FROM ubuntu:16.04

ARG XMAP_COMMIT=master
ENV XMAP_COMMIT ${XMAP_COMMIT}

RUN apt-get -qq update && apt-get -qqy upgrade
# install xmap build dependencies
RUN apt-get -qqy install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev wget unzip
# install xmap+Docker specific things, currently just dumb-init, which allows
# us to more easily send signals to xmap, for example by allowing ctrl-c of
# a running container and xmap will stop.
RUN apt-get -qqy install python-dev python-pip
RUN pip install dumb-init
RUN wget -q https://github.com/idealeer/xmap/archive/${XMAP_COMMIT}.zip && unzip -q ${XMAP_COMMIT}.zip && cd xmap-${XMAP_COMMIT} && (cmake . && make -j4 && make install) 2>&1 > /dev/null

ENTRYPOINT ["dumb-init", "/usr/local/sbin/xmap"]
