# Build the SDS server image
FROM ubuntu:20.04

RUN mkdir /sds
WORKDIR /sds

ADD sds-server /sds/sds-server
ENTRYPOINT ["/sds/sds-server"]
