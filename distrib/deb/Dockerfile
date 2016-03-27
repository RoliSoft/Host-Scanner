FROM debian
MAINTAINER RoliSoft

RUN apt-get update && apt-get install -y git curl build-essential cmake libcurl4-openssl-dev libsqlite3-dev libboost-all-dev libz-dev

COPY compile.sh /root/compile.sh
COPY upload.sh /root/upload.sh

ENTRYPOINT /root/compile.sh DEB