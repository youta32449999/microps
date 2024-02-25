FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y build-essential git iproute2 iputils-ping netcat-openbsd iptables locales-all vim
WORKDIR /microps
