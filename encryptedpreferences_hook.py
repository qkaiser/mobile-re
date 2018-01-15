#!/usr/bin/env python
#
# Hooks EncryptedPreferences (https://github.com/PDDStudio/EncryptedPreferences)
# to dump AES encryption key and plaintext content when read and decrypted out
# of shared preferences.
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
    var EncryptedPreferencesBuilder = Java.use('com.pddstudio.preferences.encrypted.EncryptedPreferences$Builder');

    EncryptedPreferencesBuilder.build.implementation = function(encryptionPassword) {
        send("EncryptedPreferences key: "+this.encryptionPassword.value);
        return this.build();
    };

    var EncryptedPreferences = Java.use('com.pddstudio.preferences.encrypted.EncryptedPreferences');

    EncryptedPreferences.getInt.implementation = function(key, defaultValue) {
        var value = this.getInt(key, defaultValue);
        send("getInt: " + value);
        return value;
    };

    EncryptedPreferences.getLong.implementation = function(key, defaultValue) {
        var value = this.getLong(key, defaultValue);
        send("getLong: " + value);
        return value;
    };

    EncryptedPreferences.getBoolean.implementation = function(key, defaultValue) {
        var value = this.getBoolean(key, defaultValue);
        send("getBoolean: " + value);
        return value;
    };

    EncryptedPreferences.getFloat.implementation = function(key, defaultValue) {
        var value = this.getFloat(key, defaultValue);
        send("getFloat: " + value);
        return value;
    };

    EncryptedPreferences.getString.implementation = function(key, defaultValue) {
        var value = this.getString(key, defaultValue);
        send("getString: " + value);
        return value;
    };
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
