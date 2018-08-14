#!/usr/bin/env python
#
# Frida hook that dumps MQTT credentials used by hooked Android application.
#
# @Author: Quentin Kaiser <kaiserquentin@gmail.com
#
###############################################################################
import frida
import sys

def on_message(message, data):
    if "payload" in message:
        print "[+] {}".format(message["payload"])
    else:
        print "[!] {}".format(message["description"])

jscode = """
Java.perform(function() {
   var MqttConnectOptions = Java.use('org.eclipse.paho.client.mqttv3.MqttConnectOptions');
    MqttConnectOptions.setUserName.implementation = function(username) {
        send("Username: "+username);
        return this.setUserName(username);
    };
    MqttConnectOptions.setPassword.implementation = function(password) {
        send("Password: "+password);
        return this.setPassword(password);
    };
    send("All set !");
});
"""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: %s pkg" % (sys.argv[0])
        sys.exit(-1)

    process = frida.get_usb_device().attach(sys.argv[1])
    script = process.create_script(jscode)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
