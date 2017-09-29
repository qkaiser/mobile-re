#!/usr/bin/env python
#
# Frida hook that dumps Android application KeyStore content.
#
# @Author: Quentin Kaiser <kaiserquentin@gmail.com
#
###############################################################################
import frida
import sys

done = False

def on_message(message, data):
    if "payload" in message:
        if not len(message["payload"]):
            global done
            done = True
        else:
            print "[+] {}".format(message["payload"])
    else:
        print "[!] {}".format(message["description"])

jscode = """
recv('list', function onMessage(message) {
    Java.perform(function () {
        var KeyStore = Java.use('java.security.KeyStore');
        send("Opening KeyStore '"+message.keystore_name+"'\\n");
        var ks = KeyStore.getInstance(message.keystore_name);
        ks.load(null);
        send("Entries: "+ks.size());
        var aliases = ks.aliases();
        while(aliases.hasMoreElements()){
            var alias = aliases.nextElement();
            var entry = ks.getEntry(alias, null);
            send("Alias: "+alias.toString()+" [creation date: "+\
                ks.getCreationDate(alias).toString()+"]");
            if(entry.toString().startsWith("PrivateKeyEntry")){
                send(entry.toString());
            }else if (entry.toString().startsWith("SecretKeyEntry")){
                send(entry.toString());
            }else if(entry.toString().startsWith("TrustedCertificateEntry")){
                send(entry.toString());
            }
        }
    });
    send("");
});
"""

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "Usage: %s package keystore_name" % (sys.argv[0])
        sys.exit(-1)

    process = frida.get_usb_device().attach(sys.argv[1])
    script = process.create_script(jscode)
    script.on('message', on_message)
    script.load()
    script.post({"type": "list", "keystore_name":sys.argv[2]})
    try:
        while not done:
            pass
    except KeyboardInterrupt as e:
        print "[+] Aborting"
    finally:
        script.unload()
        process.detach()
