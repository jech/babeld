#!/bin/sh

set -e

if [ -d .git ] ; then
    version="$(git describe --dirty)"
elif [ -f version ] ; then
    version="$(cat version)"
else
    version="unknown"
fi

sed "s/@VCS_TAG@/$version/" version.h.in > version.h
