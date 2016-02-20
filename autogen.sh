#!/bin/sh
mkdir -p ./build ./config ./m4
touch NEWS README AUTHORS ChangeLog
autoreconf --force --install -I config -I m4

