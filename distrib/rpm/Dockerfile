FROM fedora
MAINTAINER RoliSoft

RUN grep -q "fastestmirror=true" /etc/dnf/dnf.conf || echo "fastestmirror=true" >> /etc/dnf/dnf.conf
RUN dnf install -y git rpm-build gcc-c++ make cmake libcurl-devel boost-devel-static

COPY compile.sh /root/compile.sh
COPY upload.sh /root/upload.sh

ENTRYPOINT /root/compile.sh RPM