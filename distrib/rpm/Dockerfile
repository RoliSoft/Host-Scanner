FROM fedora
MAINTAINER RoliSoft

RUN dnf install -y git rpm-build gcc-c++ make cmake libcurl-devel boost-devel-static

COPY compile.sh /root/compile.sh
COPY upload.sh /root/upload.sh

ENTRYPOINT /root/compile.sh RPM