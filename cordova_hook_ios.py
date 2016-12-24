#!/usr/bin/env python
#
# Frida hook that dumps JS code getting eval'ed by Cordova apps.
#
# Instrumenting an iOS app built with Cordova this way lets you see
# everything the application does without the need to hook "lower" level
# functions.
#
# Sample output:
#
# -----------------------------------------------------------------------------
# cordova.require('cordova/exec').nativeCallback('SecureStorage1136388852',1,
# --JSON SAVED TO KEYCHAIN--
#
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

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print "Usage: %s package" % (sys.argv[0])
        sys.exit(-1)

    device = frida.get_device_manager().enumerate_devices()[-1]
    pid = device.spawn([sys.argv[1]])
    session = device.attach(pid)
    ss = '''
    var setLocationInfo = ObjC.classes.CDVCommandDelegateImpl["- evalJsHelper2:"];
    Interceptor.attach(setLocationInfo.implementation, {
        onEnter: function(args) {
            var obj=new ObjC.Object(ptr(args[2]));
            send(obj.toString());
        }
    });
    '''
    script = session.create_script(ss)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
