# coding=utf8

from . import record_utils as ru

ACTIVITY_TAG = '[Activity]'

"""
Record motion inputs and key inputs on Activity
For each activity, 
1. instrument the method `dispatchTouchEvent` of `android.app.Activity` to record motion inputs
2. instrument the method `dispatchKeyEvent` of `android.app.Activity` to record key inputs
"""

# Instrument activity
def instrument_activity(activities_to_hook, activity_dispatchMethod_handle, activity_dispatchKeyEvent_handle, is_main=True):
    hook_template = """
        var activityName = '%s';
        var isMain = %s;
        var activity = Java.use(activityName);
        
        // dispatchTouchEvent
        var methodHandle = activity.dispatchTouchEvent.handle;
        send({
            activity: activityName,
            method: 'dispatchTouchEvent',
            msgType: 'handle',
            handle: methodHandle,
            isMain: isMain
        });
        var isInstrument = true;
        for(var i = 0; i < existsDispatchTouchHandles.length; i++){
            if(existsDispatchTouchHandles[i] === methodHandle.toString()){
                isInstrument = false;
                break;
            }
        }
        if(isInstrument){
            existsDispatchTouchHandles.push(methodHandle);
            activity.dispatchTouchEvent.implementation = function(ev){
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
                    activity: '' + this,
                    msgType: 'touchEvent',
                    target: 'activity',
                    eventTime: ev.getEventTime(),
                    downTime: ev.getDownTime(),
                    deviceId: ev.getDeviceId(),
                    timestamp: timestamp
                });
                return this.dispatchTouchEvent(ev);
            };
        }

        // dispatchKeyEvent
        methodHandle = activity.dispatchKeyEvent.handle;
        send({
            activity: activityName,
            method: 'dispatchKeyEvent',
            msgType: 'handle',
            handle: methodHandle,
            isMain: isMain
        });
        isInstrument = true;
        for(var i = 0; i < existsDispatchKeyEventHandles.length; i++){
            if(existsDispatchKeyEventHandles[i] === methodHandle.toString()){
                isInstrument = false;
                break;
            }
        }
        if(isInstrument){
            existsDispatchKeyEventHandles.push(methodHandle);
            activity.dispatchKeyEvent.implementation = function(keyEvent){
                var actionCode = keyEvent.getAction();
                var keyCode = keyEvent.getKeyCode();
                var deviceId = keyEvent.getDeviceId();
                var detail = keyEvent.toString();
                var timestamp = +new Date()/1000;
                send({
                    target: 'activity',
                    msgType: 'keyEvent',
                    activity: '' + this,
                    actionCode: actionCode,
                    keyCode: keyCode,
                    deviceId: deviceId,
                    detail: detail,
                    eventTime: keyEvent.getEventTime(),
                    downTime: keyEvent.getDownTime(),
                    timestamp: timestamp
                });
                return this.dispatchKeyEvent(keyEvent);
            };
        }
    """
    code = list()
    for activity in activities_to_hook:
        code.append(hook_template % (activity, 'true' if is_main else 'false',))
    code = '\n'.join(code)
    exists_dispatchTouchEvent_handles = ', '.join(['"' + h + '"' for h in activity_dispatchMethod_handle])
    exists_dispatchKeyEvent_handles = ', '.join(['"' + h + '"' for h in activity_dispatchKeyEvent_handle])
    # print('[Exists_dispatchTouchEvent_handles]: ', exists_dispatchTouchEvent_handles)
    # print('[Exists_dispatchKeyEvent_handles]: ', exists_dispatchKeyEvent_handles)
    hook_code = """
        Java.perform(function(){
            var existsDispatchTouchHandles = [%s];
            var existsDispatchKeyEventHandles = [%s];
            %s
        });
    """ % (exists_dispatchTouchEvent_handles, exists_dispatchKeyEvent_handles, code)
    return hook_code

def get_instrument_activity_message(plid, package, fd, exist_dispatchTouchEvent_handle, exist_dispatchKeyEvent_handle):
    @ru.error_handler
    def wrapper(message, data):
        msg_type = message['payload']['msgType']
        if msg_type == 'handle':
            method = message['payload']['method']
            handle = message['payload']['handle']
            if method == 'dispatchTouchEvent':
                exist_dispatchTouchEvent_handle.add(handle)
            elif method == 'dispatchKeyEvent':
                exist_dispatchKeyEvent_handle.add(handle)
        else:
            ru.log(ACTIVITY_TAG, message, fd, plid, package)
    return wrapper