#!/bin/bash

set -e
set -x
shopt -s extglob

cd /root
git clone https://github.com/RoliSoft/Host-Scanner
cd Host-Scanner/build
cmake ..
make HostScanner
rm -rf !(HostScanner) .gitkeep
cd ..
cpack -D CPACK_GENERATOR="${1^^}"
../upload.sh *."${1,,}"