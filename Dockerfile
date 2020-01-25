FROM ubuntu:latest
RUN dpkg --add-architecture armel \
    && dpkg --add-architecture armhf \
    && dpkg --add-architecture arm64 \
    && dpkg --add-architecture ppc64el \
    && apt-get update && apt-get install -y \
    build-essential \
    curl \
    sudo \
    gawk \
    iptables \
    jq \
    pkg-config \
    libaio-dev \
    libcap-dev \
    libprotobuf-dev \
    libprotobuf-c0-dev \
    libnl-3-dev \
    libnet-dev \
    libseccomp2 \
    libseccomp-dev \
    protobuf-c-compiler \
    protobuf-compiler \
    python-minimal \
    uidmap \
    kmod \
    crossbuild-essential-armel crossbuild-essential-armhf crossbuild-essential-arm64 crossbuild-essential-ppc64el \
    libseccomp-dev:armel libseccomp-dev:armhf libseccomp-dev:arm64 libseccomp-dev:ppc64el \
    --no-install-recommends \
    && apt-get clean
RUN git clone https://github.com/opencontainers/runc.git