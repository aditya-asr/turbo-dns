FROM ubuntu:22.04
ARG LISTENIP

RUN apt update -y
RUN apt upgrade -y
RUN apt update -y
RUN DEBIAN_FRONTEND="noninteractive" TZ="Asia/Kolkata" apt install ssh vim git pkg-config autoconf automake build-essential libnghttp2-dev libtool libtool-bin libuv1-dev libcap-dev libssl-dev iproute2 liburcu-dev -y
RUN DEBIAN_FRONTEND="noninteractive" TZ="Asia/Kolkata" apt install astyle cmake gcc ninja-build  python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz tshark -y
RUN apt install iptables iputils-ping iperf gcc make net-tools libnetfilter-queue-dev netcat traceroute vim -y
RUN apt install git libnl-3-dev libnl-genl-3-dev binutils-dev libreadline6-dev libpcap-dev -y

RUN git clone https://github.com/openssl/openssl.git
RUN cd openssl && git checkout cf2877791ce7508684109664f467c9e40987692f
RUN cd openssl && ./Configure
RUN cd openssl && make
RUN cd openssl && make install_sw

RUN git clone https://github.com/open-quantum-safe/liboqs.git
RUN cd liboqs && git checkout 36be57445d8ca53f7095160fde548efe82ace09d
RUN mkdir liboqs/build
RUN cd liboqs/build && cmake -GNinja ..
RUN cd liboqs/build && ninja
RUN cd liboqs/build && ninja install

RUN git clone https://github.com/open-quantum-safe/oqs-provider.git
RUN cd oqs-provider && git checkout 0ec51eca39d72867f309878f5bb9002f1c3e07fb
RUN cd oqs-provider && cmake -S . -B _build && cmake --build _build && ctest --test-dir _build && cmake --install _build

# COPY ./OQS-bind OQS-bind
RUN git clone https://github.com/aditya-asr/OQS-bind-latest OQS-bind
RUN cd OQS-bind && autoreconf -fi
RUN cd OQS-bind && ./configure
RUN cd OQS-bind && make
RUN cd OQS-bind && make install
RUN mkdir /usr/local/etc/bind
RUN mkdir /usr/local/etc/bind/zones
RUN mkdir /var/cache/bind
RUN mkdir /setup_files/
COPY install_trust_anchor.bash /setup_files/
COPY named.conf /usr/local/etc
COPY root.hints /usr/local/etc/bind/root/hints/root.hints

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV OPENSSL_MODULES=/oqs-provider/_build/lib
RUN openssl list -signature-algorithms -provider oqsprovider

COPY ./daemon/src /daemon/src
COPY ./daemon/include /daemon/include
COPY ./daemon/c-hashmap /daemon/c-hashmap
COPY ./daemon/makefile /daemon/makefile
WORKDIR /daemon
RUN make daemon
ENV LISTENIP=${LISTENIP}
WORKDIR /

