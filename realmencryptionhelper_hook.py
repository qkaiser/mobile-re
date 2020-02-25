#!/usr/bin/env python3
#
# Hooks RealmConfiguration Builder to dump the Realm database encryption key.
# The key can be used as-is with Realm Studio to open the database.
#
# Reference: https://realm.io/docs/java/latest/api/io/realm/RealmConfiguration.Builder.html
# @Author: Quentin Kaiser <kaiserquentin@gmail.com
#
###############################################################################
import frida
import sys

def on_message(message, data):
    if "payload" in message:
        print("[+] {}".format(message["payload"]))
    else:
        print("[!] {}".format(message["description"]))

jscode = """
Java.perform(function() {
    String.prototype.hexEncode = function(){
        var hex, i;
        var result = "";
        for (i=0; i<this.length; i++) {
            hex = this.charCodeAt(i).toString(16);
            result += ("000"+hex).slice(-2);
        }
        return result;
    }

    var byte_array_to_string = function(value) {
        var buffer = Java.array('byte', value);
        var result = "";
        for(var i = 0; i < buffer.length; ++i){
            result += (String.fromCharCode(buffer[i] & 0xff));
        }
        return result;
    }

    var RealmConfigurationBuilder = Java.use('io.realm.RealmConfiguration$Builder');
    RealmConfigurationBuilder.encryptionKey.implementation = function(key) {
        send("RealmConfigurationBuilder.encryptionKey(key=" + byte_array_to_string(key).hexEncode() + ")");
        return this.encryptionKey(key);
    }
});
"""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s pkg" % (sys.argv[0]))
        sys.exit(-1)

    device = frida.get_usb_device()
    pid = device.spawn([sys.argv[1]])
    process = frida.get_usb_device().attach(pid)
    print("[+] Attached to {}".format(sys.argv[1]))
    script = process.create_script(jscode)
    script.on('message', on_message)
    script.load()
    print("[+] Script loaded.")
    device.resume(pid)
    try:
        sys.stdin.read()
    except KeyboardInterrupt as e:
        sys.exit(0)
