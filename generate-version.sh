#!/bin/sh

set -e

if [ "$(git rev-parse --is-inside-work-tree 2> /dev/null)" ] ; then
    version="$(git describe --dirty)"
elif [ -f version ] ; then
    version="$(cat version)"
else
    version="unknown"
fi

echo "#define BABELD_VERSION \"$version\""
