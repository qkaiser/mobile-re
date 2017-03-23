#!/usr/bin/env python
#
# Check if an Android application rely on Ogone mobile payment library by
# unzipping the APK in-memory and grepping for a specific marker in any dex
# file it can find.
#
# Author: Quentin Kaiser <kaiserquentin@gmail.com>
#
###############################################################################


from zipfile import ZipFile
import sys
import re

TAG = "OPCredentials"

if __name__ == "__main__":
    if len(sys.argv) < 1:
        print "[!] Usage: %s filename.apk" % (sys.argv[0])
        sys.exit(-1)
    else:
        filename = sys.argv[1]
        apk=ZipFile(filename)
        for name in apk.namelist():
            if name.endswith("dex"):
                content = apk.read(name)
                is_present = True if re.search(TAG, content) is not None else False
                break
        if is_present:
            print "[+] %s uses Ogone mobile library." % (filename)
            sys.exit(0)
        else:
            print "[+] %s does not use Ogone mobile library." % (filename)
            sys.exit(-1)
