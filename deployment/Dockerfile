# Build the SDS server image
FROM ubuntu:20.04

RUN export HTTP_PROXY=http://child-prc.intel.com:913 \
  && export HTTPS_PROXY=http://child-prc.intel.com:913 \
  && export http_proxy=http://child-prc.intel.com:913 \
  && export https_proxy=http://child-prc.intel.com:913 \
  && apt-get update && \
    apt-get install -y \
    wget \
    netcat \
    vim 
