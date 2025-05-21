#!/bin/bash
# shellcheck disable=SC3000-SC4000

set -o noclobber
set -o errexit
set -o nounset
set -o pipefail

gitroot=$(git rev-parse --show-toplevel)
portfile=$gitroot/lab3_port
secretfile=$gitroot/lab3_group_secret

curport=$(cat $portfile 2>/dev/null || true)

if [[ ! -z $curport ]]; then
    echo "It looks like you already ran setup, you don't need to run it again."
    exit 1
fi

# Make the turnins dir
mkdir $gitroot/turnins

# Choose a port number deterministically by hashing the username (#- gets rid of negatives, whoops)
baseval=$(( 16#$(echo $USER | shasum | cut -d ' ' -f 1) ))
newport=$(( 1024 + ${baseval#-} % 30000 ))

echo -n "GROUP_PORT_NO=$newport" > "$portfile"

# generate the group's secret key
SECRET=$(head -c 32 /dev/urandom | base64 --wrap=0)

echo -n "LAB_GROUP_SECRET_KEY=\"$SECRET\"" > "$secretfile"

chmod ogu-w $secretfile $portfile

echo -e "Done!\n\tYour port number is in $portfile ($newport)\n\tYour lab3 cookie is in $secretfile ($SECRET)\n"
