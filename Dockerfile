# Build the SDS server image

# Build the manager binary
FROM ubuntu:20.04 as builder

ARG GO_VERSION="1.18.1"
ARG SDK_VERSION="2.17.100.3"
ARG SGX_SDK_INSTALLER=sgx_linux_x64_sdk_${SDK_VERSION}.bin
# ARG DCAP_VERSION="1.12.100.3"
ENV DEBIAN_FRONTEND=noninteractive
# SGX prerequisites
# hadolint ignore=DL3005,DL3008
RUN export HTTP_PROXY=http://child-prc.intel.com:913 \
  && export HTTPS_PROXY=http://child-prc.intel.com:913 \
  && export http_proxy=http://child-prc.intel.com:913 \
  && export https_proxy=http://child-prc.intel.com:913 \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
    ca-certificates \
    curl \
    linux-tools-generic \
    wget \
    unzip \
    protobuf-compiler \
    libprotobuf-dev \
    build-essential \
    cmake \
    pkg-config \
    gdb \
    vim \
    python3 \
    git \
    gnupg \
  && update-ca-certificates \
# Add 01.org to apt for SGX packages
# hadolint ignore=DL4006
  && echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" >> /etc/apt/sources.list.d/intel-sgx.list \
  && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - \
# Install SGX PSW
  && apt-get update \
  && apt-get install --no-install-recommends -y \
    libsgx-enclave-common=${SDK_VERSION}-focal1 \
    libsgx-launch=${SDK_VERSION}-focal1 \
    libsgx-launch-dev=${SDK_VERSION}-focal1 \
    libsgx-epid=${SDK_VERSION}-focal1 \
    libsgx-epid-dev=${SDK_VERSION}-focal1 \
    libsgx-quote-ex=${SDK_VERSION}-focal1 \
    libsgx-quote-ex-dev=${SDK_VERSION}-focal1 \
    libsgx-urts=${SDK_VERSION}-focal1 \
    libsgx-uae-service=${SDK_VERSION}-focal1 \
    libsgx-ae-epid=${SDK_VERSION}-focal1 \
    libsgx-ae-le=${SDK_VERSION}-focal1 \
    libsgx-ae-pce=${SDK_VERSION}-focal1 \
    libsgx-ae-qe3 \
    libsgx-ae-qve \
    libsgx-dcap-ql \
    libsgx-dcap-ql-dev \
    libsgx-pce-logic \
    libsgx-qe3-logic \
    libsgx-dcap-default-qpl \
  && apt-get clean \
  && ln -s /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so

# SGX SDK is installed in /opt/intel directory.
WORKDIR /opt/intel

# Install SGX SDK
# hadolint ignore=DL4006
RUN export HTTP_PROXY=http://child-prc.intel.com:913 \
  && export HTTPS_PROXY=http://child-prc.intel.com:913 \
  && export http_proxy=http://child-prc.intel.com:913 \
  && export https_proxy=http://child-prc.intel.com:913 \
  && wget https://download.01.org/intel-sgx/sgx-linux/2.17/distro/ubuntu20.04-server/$SGX_SDK_INSTALLER \
  && chmod +x  $SGX_SDK_INSTALLER \
  && echo "yes" | ./$SGX_SDK_INSTALLER \
  && rm $SGX_SDK_INSTALLER \
  && ls -l /opt/intel/

# Tag/commit-id/branch to use for bulding CTK
ARG CTK_TAG="master"

# Intel crypto-api-toolkit prerequisites
#https://github.com/intel/crypto-api-toolkit#software-requirements
RUN export HTTP_PROXY=http://child-prc.intel.com:913 \
  && export HTTPS_PROXY=http://child-prc.intel.com:913 \
  && export http_proxy=http://child-prc.intel.com:913 \
  && export https_proxy=http://child-prc.intel.com:913 \
  && set -x && apt-get update \
  && apt-get install --no-install-recommends -y \
    dkms libprotobuf17 autoconf \
    autotools-dev libc6-dev \
    libtool build-essential \
    opensc sudo \
    automake \
  && apt-get clean \
  && git clone https://github.com/intel/crypto-api-toolkit.git \
  && cd /opt/intel/crypto-api-toolkit \
  && git checkout ${CTK_TAG} -b v${CTK_TAG} \
  # disable building tests
  && sed -i -e 's;test;;g' ./src/Makefile.am \
  # disable enclave signing inside CTK
  #   && sed -i -e '/libp11SgxEnclave.signed.so/d' ./src/p11/trusted/Makefile.am \
  && ./autogen.sh \
  && ./configure --enable-dcap --with-token-path=/home/tcs-issuer \
  && make && make install

RUN ls -l /opt/intel/

# Install golang
WORKDIR /workspace
RUN export HTTP_PROXY=http://child-prc.intel.com:913 \
  && export HTTPS_PROXY=http://child-prc.intel.com:913 \
  && export http_proxy=http://child-prc.intel.com:913 \
  && export https_proxy=http://child-prc.intel.com:913 \
  && curl -L https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -zxf - -C / \
  && mkdir -p /usr/local/bin/ \
  && for i in /go/bin/*; do ln -s $i /usr/local/bin/; done


###
# Clean runtime image which supposed to
# contain all runtime dependecy packages
###
FROM ubuntu:focal as runtime

ARG SDK_VERSION="2.17.100.3"
# ARG DCAP_VERSION="1.12.100.3"

RUN export HTTP_PROXY=http://child-prc.intel.com:913 \
  && export HTTPS_PROXY=http://child-prc.intel.com:913 \
  && export http_proxy=http://child-prc.intel.com:913 \
  && export https_proxy=http://child-prc.intel.com:913\
  && apt-get update \
  && apt-get install -y wget gnupg \
  && echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" >> /etc/apt/sources.list.d/intel-sgx.list \
  && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - \
  && sed -i '/deb-src/s/^# //' /etc/apt/sources.list \
  && apt-get update \
  && apt-get remove -y wget gnupg && apt-get autoremove -y \
  && bash -c 'set -o pipefail; apt-get install --no-install-recommends -y \
    libprotobuf17 \
    libsgx-enclave-common=${SDK_VERSION}-focal1 \
    libsgx-epid=${SDK_VERSION}-focal1 \
    libsgx-quote-ex=${SDK_VERSION}-focal1 \
    libsgx-urts=${SDK_VERSION}-focal1 \
    libsgx-ae-epid=${SDK_VERSION}-focal1 \
    libsgx-ae-qe3 \
    libsgx-dcap-ql \
    libsgx-pce-logic \
    libsgx-qe3-logic \
    libsgx-dcap-default-qpl \
    libsofthsm2 \
    # required for pkcs11-tool
    opensc | tee --append /usr/local/share/package-install.log' \
  && rm -rf /var/cache/* \
  && rm -rf  /var/log/*log /var/lib/apt/lists/* /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old \
  && ln -s /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so

###
# Final sds-server Image
###
FROM runtime as final

RUN mkdir /sds
WORKDIR /sds

ADD sds-server /sds/sds-server

WORKDIR /

COPY --from=builder /usr/local/lib/libp11* /usr/local/lib/
COPY --from=builder /opt/intel /opt/intel

ENV LD_LIBRARY_PATH="/usr/local/lib"

# ENTRYPOINT ["/sds/sds-server"]