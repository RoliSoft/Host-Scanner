#!/bin/bash

# file to upload is in $1, implement your own uploader

ls -lah "$1"
curl --upload-file "$1" https://transfer.sh/