#!/bin/sh

set -e

if [ -d .git ] ; then
    version="$(git describe --dirty)"
elif [ -f version ] ; then
    version="$(cat version)"
else
    version="(unknown version)"
fi

echo "#define BABELD_VERSION \"$version\""
