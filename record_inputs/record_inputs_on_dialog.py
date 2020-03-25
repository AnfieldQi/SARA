# coding=utf8

from . import record_utils as ru

DIALOG_TAG = '[Dialog]'

"""
Record motion inputs and key inputs on Dialog
1. instrument the method `dispatchTouchEvent` of `android.app.Dialog` to record motion inputs
2. instrument the method `dispatchKeyEvent` of `android.app.Dialog` to record key inputs
"""

# Instrument Dialog
def instrument_dialog():
    hook_code = """
        Java.perform(function(){
            var dialog = Java.use('android.app.Dialog');
            dialog.dispatchTouchEvent.implementation = function(ev){
                var actionId = ev.getAction();
                var x = ev.getRawX();
                var y = ev.getRawY();
                var action = ev.actionToString(actionId);
                var timestamp = +new Date()/1000;
                send({
                    x: x,
                    y: y,
                    actionId: actionId,
                    action: action,
                    dialog: '' + this,
                    msgType: 'touchEvent',
                    target: 'dialog',
                    eventTime: ev.getEventTime(),
                    downTime: ev.getDownTime(),
                    deviceId: ev.getDeviceId(),
                    timestamp: timestamp
                });
                return this.dispatchTouchEvent(ev);
            };
            dialog.dispatchKeyEvent.implementation = function(keyEvent){
                var actionCode = keyEvent.getAction();
                var keyCode = keyEvent.getKeyCode();
                var deviceId = keyEvent.getDeviceId();
                var detail = keyEvent.toString();
                var timestamp = +new Date()/1000;
                send({
                    target: 'dialog',
                    msgType: 'keyEvent',
                    dialog: '' + this,
                    actionCode: actionCode,
                    keyCode: keyCode,
                    deviceId: deviceId,
                    detail: detail,
                    eventTime: keyEvent.getEventTime(),
                    downTime: keyEvent.getDownTime(),
                    deviceId: keyEvent.getDeviceId(),
                    timestamp: timestamp
                });
                return this.dispatchKeyEvent(keyEvent);
            };
        });
    """
    return hook_code

def get_instrument_dialog_message(plid, package, fd):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(DIALOG_TAG, message, fd, plid, package)
    return wrapper