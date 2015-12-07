FROM debian
MAINTAINER RoliSoft

RUN apt-get update && apt-get install -y git build-essential cmake libcurl4-openssl-dev libboost-all-dev

COPY compile.sh /root/compile.sh
COPY upload.sh /root/upload.sh

ENTRYPOINT /root/compile.sh DEB