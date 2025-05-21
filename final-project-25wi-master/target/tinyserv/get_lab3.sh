#!/bin/bash

set -o noclobber
set -o errexit
set -o nounset
set -o pipefail

# This is a utility script for the Makefile to be able to read the
# port/secret, it is unrelated to any of the sploits.

mode=$1

gitroot=$(git rev-parse --show-toplevel)

if [[ $mode == "port" ]]; then
    cat $gitroot/lab3_port
    exit 0
fi
if [[ $mode == "secret" ]]; then
    cat $gitroot/lab3_group_secret
    exit 0
fi
echo ""

