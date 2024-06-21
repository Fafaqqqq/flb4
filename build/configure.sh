#!/bin/bash

PROJECT=flb4
CMAKE=cmake
PROFILE=Debug

BLDDIR=.out/
[ ! -d "$BLDDIR" ] && mkdir -p $BLDDIR

$CMAKE -B $BLDDIR -G Ninja -DCMAKE_BUILD_TYPE=$PROFILE
