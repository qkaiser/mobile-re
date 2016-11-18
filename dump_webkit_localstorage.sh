#!/bin/sh
#
# Dump HTML5 localStorage content from an iOS application WebKit cache database.
# You'll need xxd to unhex the content. Hex output is pretty much the reason why
# I wrote this in the first place.
#
# Sample output
# --------------------------------------------------------------------------------
# $ ./dump_webkit_localstorage.sh Library/WebKit/LocalStorage/file__0.localstorage
# localStorageKey0 | "localStorageValue0"
# localStorageKey1 | "localStorageValue1"
# --------------------------------------------------------------------------------
#
# @Author: Quentin Kaiser <kaiserquentin@gmail.com>
#
###############################################################################

if [ $# -ne 1 ]; then
    echo "Usage: $0 sqlite3db";
    exit -1;
fi
DB=$1
KEYS=`sqlite3 $DB "SELECT key FROM ItemTable"`;
for KEY in $KEYS; do
    VAL=`sqlite3 $DB "SELECT hex(value) from ItemTable WHERE key =
        \"$KEY\""  | xxd -r -p `;
        echo "$KEY | $VAL";
done
exit 0
