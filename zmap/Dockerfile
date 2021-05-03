FROM ubuntu
LABEL maintainer="Kaspar Hageman <kh@es.aau.dk>"

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev git
RUN git clone https://github.com/zmap/zmap.git && cd zmap && cmake . && make -j4 && make install && cd .. && rm -rf zmap
