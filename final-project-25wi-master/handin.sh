#!/bin/bash

set -o noclobber
set -o errexit
set -o nounset
set -o pipefail

gitroot=$(git rev-parse --show-toplevel)

TINYSERV_DIR="$gitroot/target/tinyserv"
MAIN="$TINYSERV_DIR/tinyserv.c"

TIMESTAMP=$(date +%y_%m_%d_%H:%M:%S)
BASE_TURNIN=$gitroot/turnins

USAGE="Usage: $0 sploit<sploit-number>\n\t\te.g. $0 sploit3"

# Check that they ran make
if ! make -q -C $TINYSERV_DIR ; then
    echo -e "You should build and test your code before submitting!"
    exit 1
fi
# Check on the sploit number they gave us
if [[ $# -lt 1 || -z "$1" ]]; then
    echo -e $USAGE
    exit 1
fi
SPLOIT_NO=$(echo "$1" | sed -En "s/^sploit([[:digit:]]+)$/\1/p")
if [[ ! -n "$SPLOIT_NO" ]]; then
    echo -e $USAGE
    exit 1
fi

# Bad times checking
if [[ ! -e "$MAIN" ]]; then
    echo "It looks like $MAIN doesn't exist, we need your changes in there!"
    echo "Exiting..."
    exit 1
fi

# Double check the user meant to do this
echo "This script will make a copy/diff of your current tinyserv.c against the original we gave you."
echo -n "Proceed with creating patch for sploit$SPLOIT_NO? Enter \"y\" or \"n\" [y/n]: "
read -r ANSWER
if [[ "$ANSWER" != "y" ]]; then
    echo "Exiting..."
    exit 2
fi

# Setup turnin dir
TURNIN="$BASE_TURNIN/tinyserv_sploit${SPLOIT_NO}_$TIMESTAMP"
MAIN_BACKUP_FILE="$TURNIN/tinyserv.c"
chmod +w "$BASE_TURNIN"
mkdir -p "$TURNIN"
#echo $TURNIN
cp "$MAIN" "$MAIN_BACKUP_FILE"

# Remove any previous patch
HANDIN_NAME="$BASE_TURNIN/sploit${SPLOIT_NO}-patch.diff"
if [[ -e $HANDIN_NAME ]]; then
    chmod +w $HANDIN_NAME
    rm $HANDIN_NAME
fi

# generate the diff
echo -n "Making a diff for your patch for sploit${SPLOIT_NO}..."

git diff -b -U6 labsetup $MAIN > $HANDIN_NAME || true # 1 on differ
cp $HANDIN_NAME $TURNIN/
echo "done"

# Remove write permissions
chmod -R -w $BASE_TURNIN

echo "The diff has been put in file $HANDIN_NAME"
echo "Your tinyserv.c has been backed up as $MAIN_BACKUP_FILE"


echo -e "\nDone running handin.sh."
echo "Check that $HANDIN_NAME shows all the changes you've made to patch sploit${SPLOIT_NO}'s vulnerability and *no changes related to other sploits.*"
echo "To make grading faster, please make sure the diffs are as minimal as you can."
echo -e "\n\nIf you need it, you can checkout the original version of things with \"git checkout labsetup\""


exit 0
