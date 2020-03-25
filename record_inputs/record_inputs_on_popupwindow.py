# coding=utf8

from . import record_utils as ru

POPUPWINDOW_TAG = '[PopupWindow]'
VIEW_TAG = '[ViewOnTouchEvent]'

"""
Record motion inputs on Popup Menu; most of the menus are implemented with `android.widget.PopupWindow`
1. instrument the method `showAsDropDown` and `showAtLocation` of `android.widget.PopupWindow` to record the open of popup window and locate the instance of view in the popup window
2. instrument the method `onTouchEvent` of of the located view instance to record motion inputs
"""

# Instrument PopupWindow (Menu is implemented as PopupWindow)
def instrument_PopupWindow():
    hook_code = """
        Java.perform(function(){
            var PopupWindow = Java.use('android.widget.PopupWindow');
            PopupWindow.showAsDropDown.overload('android.view.View', 'int', 'int', 'int').implementation = function(view, xoff, yoff, gravity){
                var contentView = this.getContentView();
                var contentViewHandle = contentView.$handle;
                var contentViewClass = contentView.$className;
                var detail = ''+this;
                var width = this.getWidth();
                var height = this.getHeight();
                var timestamp = +new Date()/1000;
                setTimeout(function(){
                    send(
                        {
                            handle: this.$handle,
                            classname: this.$className,
                            target: 'PopupWindow', 
                            action: 'show',
                            method: 'showAsDropDown',
                            viewHandle: contentViewHandle,
                            viewClassName: contentViewClass,
                            msgType: 'action',
                            popupWindow: detail,
                            width: width,
                            height: height,
                            timestamp: timestamp
                        }
                    );
                }, 0);
                return this.showAsDropDown(view, xoff, yoff, gravity);;
            };
            PopupWindow.dismiss.overload().implementation = function(){
                var width = this.getWidth();
                var height = this.getHeight();
                var timestamp = +new Date()/1000;
                send({
                    handle: this.$handle,
                    classname: this.$className,
                    target: 'PopupWindow', 
                    action: 'hide',
                    msgType: 'action',
                    popupWindow: ''+this,
                    width: width,
                    height: height,
                    timestamp: timestamp
                });
                return this.dismiss();
            };
            PopupWindow.showAtLocation.overload('android.view.View', 'int', 'int', 'int').implementation = function(parent, gravity, x, y){
                var contentView = this.getContentView();
                var contentViewHandle = contentView.$handle;
                var contentViewClass = contentView.$className;
                var detail = ''+this;
                var width = this.getWidth();
                var height = this.getHeight();
                var timestamp = +new Date()/1000;
                setTimeout(function(){
                    send(
                        {
                            handle: this.$handle,
                            classname: this.$className,
                            target: 'PopupWindow', 
                            action: 'show',
                            method: 'showAtLocation',
                            viewHandle: contentViewHandle,
                            viewClassName: contentViewClass,
                            msgType: 'action',
                            popupWindow: detail,
                            width: width,
                            height: height,
                            timestamp: timestamp
                        }
                    );
                }, 0);
                return this.showAtLocation(parent, gravity, x, y);
            }
        });
    """
    return hook_code

def get_instrument_PopupWindow_message(plid, package, session, fd, exist_view_onTouchEvent_handle):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(POPUPWINDOW_TAG, message, fd, plid, package)
        action = message['payload']['action']
        if action == 'show':
            view_handle = message['payload']['viewHandle']
            view_classname = message['payload']['viewClassName']
            _code = instrument_PopupWindowView(view_handle, view_classname, exist_view_onTouchEvent_handle)
            _script = session.create_script(_code)
            _script.on('message', get_instrument_view_message(plid, package, fd, exist_view_onTouchEvent_handle))
            _script.load()
    return wrapper


def instrument_PopupWindowView(handle, classname, exist_view_onTouchEvent_handle):
    exists_view_onTouchEvent_handle = ', '.join(['"' + h + '"' for h in exist_view_onTouchEvent_handle])
    hook_code = """
        Java.perform(function(){
            var existsViewonTouchEventHandlers = [%s];
            var handle = %s;
            var className = Java.use('%s');
            var instance = Java.cast(ptr(handle), className);
            var methodHandle = instance.onTouchEvent.handle;
            var isInstrument = true;
            for(var i = 0; i < existsViewonTouchEventHandlers.length; i++){
                if(existsViewonTouchEventHandlers[i] === methodHandle.toString()){
                    isInstrument = false;
                    break;
                }
            }
            if(isInstrument){
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'handle',
                    handle: methodHandle,
                    timestamp: timestamp
                });
                instance.onTouchEvent.implementation = function(event){
                    var actionId = event.getAction();
                    var x = event.getRawX();
                    var y = event.getRawY();
                    var action = event.actionToString(actionId);
                    var timestamp = +new Date()/1000;
                    send({
                        msgType: 'touchEvent',
                        target: 'view',
                        // event: event,
                        x: x,
                        y: y,
                        actionId: actionId,
                        action: action,
                        view: '' + this,
                        viewId: this.getId(),
                        eventTime: event.getEventTime(),
                        downTime: event.getDownTime(),
                        deviceId: event.getDeviceId(),
                        timestamp: timestamp
                    });
                    return this.onTouchEvent(event);
                };
            }
        });
    """ % (exists_view_onTouchEvent_handle, handle, classname)
    return hook_code

def get_instrument_view_message(plid, package, fd, exist_view_onTouchEvent_handle):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(VIEW_TAG, message, fd, plid, package)
        msgType = message['payload']['msgType']
        if msgType == 'handle':
            exist_view_onTouchEvent_handle.add(message['payload']['handle'])
    return wrapper