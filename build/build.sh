#!/bin/bash

PROJECT=flb4
CMAKE=cmake
PROFILE=Debug

BLDDIR=.out/

$CMAKE --build $BLDDIR -- -j8
