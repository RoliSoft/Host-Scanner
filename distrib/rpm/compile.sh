#!/bin/bash

shopt -s extglob
set -x

cd /root && \
git clone https://github.com/RoliSoft/Host-Scanner && \
cd Host-Scanner/build && \
cmake .. && \
make HostScanner && \
rm -rf !(HostScanner) && \
cd .. && \
cpack -D CPACK_GENERATOR="${1^^}" && \
../upload.sh *."${1,,}"