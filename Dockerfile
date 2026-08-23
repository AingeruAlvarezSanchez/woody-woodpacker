FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    gdb \
    git \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace