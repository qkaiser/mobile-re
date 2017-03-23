#!/usr/bin/env python
#
# Checks if your Ogone API user credentials can be abused to access the
# transaction history or perform refunds and returns a list of privileges
# that should be removed on Ogone backend.
#
# Author: Quentin Kaiser <kaiserquentin@gmail.com>
#
###############################################################################
import requests
import sys
import re
from hashlib import sha1
from datetime import datetime, timedelta

def check_automatic_download(pspid, userid, pswd):

    now = datetime.today()
    then = now - timedelta(days=30)
    headers = {
        "User-Agent": "mTerminal/1.1 CFNetwork/758.0.2 Darwin/15.0.0"
    }
    data = {
        "format": "XML",
        "level": "ORDERLEVEL",
        "listlasttrns": 10,
        "ofd": then.day,
        "ofm": then.month,
        "ofy": then.year,
        "otd": now.day,
        "otm": now.month,
        "oty": now.year,
        "PSPID": pspid,
        "PSWD": pswd,
        "Sep": ";",
        "structure": "DYN",
        "USERID": userid
    }

    response = requests.post("https://secure.ogone.com/ncol/prod/payment_download_ncp.asp", headers=headers, data=data)
    if "SYSTEM_ERROR" in response.content:
        #fuck XML parsing, that's why
        error = re.findall("SYSTEM_ERROR>([^<]*)", response.content)[0]
        if "File Download is Not available for your profile":
            return False
        else:
            raise Exception(error)
    else:
        return True

def check_refund(pspid, userid, pswd, passphrase):
    """
        This is here as an example. I'm not planning on actually exploiting this shit and getting sued.
    """
    headers = {
        "User-Agent": "mTerminal/1.1 CFNetwork/758.0.2 Darwin/15.0.0"
    }
    data = {
        "AMOUNT": 0,
        "OPERATION": "RFD", #partial or full refund (on a paid order), closing the transaction after this refund
        "ORDERID": 0,
        "PSPID": pspid,
        "PSWD": pswd,
        "USERID": userid
    }
    shastring = ""
    for k in data:
        shastring += "%s=%s%s" % (k, data[k], passphrase)
    data["SHASIGN"] = sha1(shastring).hexdigest().upper()

    #response = requests.post("https://secure.ogone.com/ncol/prod/maintenancedirect.asp", headers=headers, data=data)
    return False


if __name__ == "__main__":

    try:
        if len(sys.argv) < 5:
            raise Exception("Usage: %s PSPID USERID PSWD PASSPHRASE" % sys.argv[0])
        else:
            if check_automatic_download(sys.argv[1], sys.argv[2], sys.argv[3]):
                print "\033[91m[!] Automatic download is enabled.\033[0m"
            else:
                print "\033[92m[*] Automatic download is disabled. All good.\033[0m"

            if check_refund(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]):
                print "\033[91m[!] Refund is enabled.\033[0m"
            else:
                print "\033[92m[*] Refund is disabled. All good.\033[0m"

        sys.exit(0)
    except Exception as e:
        print "[!] %s" % (e.message)
        sys.exit(-1)
