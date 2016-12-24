#!/usr/bin/env python
#
# Frida hook that dumps JS code getting eval'ed by Cordova apps.
#
# Instrumenting an Android app built with Cordova this way lets you see
# everything the application does without the need to hook "lower" level
# functions.
#
# Sample output:
#
# -----------------------------------------------------------------------------
# cordova.require('cordova/exec').nativeCallback('SQLitePlugin1136388855',1,
#  "Database opened"
#  ,0)
# -----------------------------------------------------------------------------
#
# @Author: Quentin Kaiser <kaiserquentin@gmail.com
#
###############################################################################
import frida
import sys


def on_message(message, data):
    print "%s" %(message['payload'])

jscode = """
Java.perform(function () {
    var CordovaBridge = Java.use('org.apache.cordova.CordovaBridge');

    CordovaBridge.jsExec.implementation = function (paramInt, paramString1, paramString2, paramString3, paramString4) {
        send(paramString1 + " : " + paramString2 + " : " + paramString3 + " : " + paramString4);
       	this.jsExec(paramInt, paramString1, paramString2, paramString3, paramString4);
    };

});
"""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: %s package" % (sys.argv[0])
        sys.exit(-1)

process = frida.get_usb_device().attach(sys.argv[1])
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
