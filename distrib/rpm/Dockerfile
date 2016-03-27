FROM fedora
MAINTAINER RoliSoft

RUN grep -q "fastestmirror=true" /etc/dnf/dnf.conf || echo "fastestmirror=true" >> /etc/dnf/dnf.conf
RUN dnf install -y git curl rpm-build gcc-c++ make cmake libcurl-devel sqlite-devel boost-devel-static zlib-devel

COPY compile.sh /root/compile.sh
COPY upload.sh /root/upload.sh

ENTRYPOINT /root/compile.sh RPM