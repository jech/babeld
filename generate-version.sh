#!/bin/sh

set -e

if [ -d .git ] ; then
    version="$(git describe --dirty)"
elif [ -f version ] ; then
    version="$(cat version)"
else
    version="unknown"
fi

echo "#ifndef BABELD_VERSION"
echo "#define BABELD_VERSION \"$version\""
echo "#endif"
