#!/bin/bash
echo -e "\e[31mWARNING: \e[33mThese data files may not be the latest. See the README on how to compile them yourself.\e[39m"
echo -e "\e[32mDownloading CPE dictionary...\e[39m"
wget https://github.com/RoliSoft/Host-Scanner-Scripts/releases/download/v0.3.0/cpe-list.dat.gz
echo -e "\e[32mDownloading CPE aliases...\e[39m"
wget https://github.com/RoliSoft/Host-Scanner-Scripts/releases/download/v0.1.0/cpe-aliases.dat.gz
echo -e "\e[32mDownloading service banner database...\e[39m"
wget https://github.com/RoliSoft/Host-Scanner-Scripts/releases/download/v0.1.0/cpe-regex.dat.gz
echo -e "\e[32mDownloading UDP payloads...\e[39m"
wget https://github.com/RoliSoft/Host-Scanner-Scripts/releases/download/v0.1.0/payloads.dat.gz
echo -e "\e[32mDownloading CVE database...\e[39m"
wget https://github.com/RoliSoft/Host-Scanner-Scripts/releases/download/v0.3.0/cve-list.db3.bz2
echo -e "\e[32mDecompressing CVE database...\e[39m"
bzip2 -d cve-list.db3.bz2