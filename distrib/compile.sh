#!/bin/bash

shopt -s extglob

git clone https://github.com/RoliSoft/Host-Scanner && \
cd Host-Scanner/build && \
cmake .. && \
make && \
rm -rf !(HostScanner) && \
cd .. && \
cpack -D CPACK_GENERATOR="${1^^}" && \
../upload.sh *."${1,,}"