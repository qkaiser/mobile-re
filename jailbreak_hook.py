#!/usr/bin/env python
#
# Frida hook to bypass jailbreak detection on iOS app relying on
# DTTJailbreakDetection library (https://github.com/thii/DTTJailbreakDetection)
#
# @Author: Quentin Kaiser <kaiserquentin@gmail.com>
#
###############################################################################
import frida
import sys

def on_message(message, data):
    print "[+] %s" % (message['payload'])

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print "Usage: %s package"
        sys.exit(-1)

    device = frida.get_device_manager().enumerate_devices()[-1]
    pid = device.spawn([sys.argv[1]])
    session = device.attach(pid)
    ss = '''
    var isJailbroken = ObjC.classes.DTTJailbreakDetection["+ isJailbroken"];
    Interceptor.attach(isJailbroken.implementation, {
        onLeave: function(retval) {
            send("%s - bypassing jailbreak detection...");
            retval.replace(0);
        }
    });
    ''' % (sys.argv[1])
    script = session.create_script(ss)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
