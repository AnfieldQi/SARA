# coding=utf8

from . import record_utils as ru
from . import record_inputs_on_activity as activity

"""
Instrument the method `loadClass` of `java.lang.ClassLoader` to detect the loadings of an activity
"""

# Instrument ClassLoader
def instrument_ClassLoader(is_main=True):
    hook_code = """
        Java.perform(function(){
            var isMain = %s;
            var x = Java.use("java.lang.ClassLoader");
            x.loadClass.overloads[1].implementation = function(v){
                var ret=x.loadClass.overloads[1].apply(this, arguments);
                var timestamp = +new Date()/1000;
                send({name: v, isMain: isMain, timestamp: timestamp});
                return ret;
            };
        });
    """ % ('true' if is_main else 'false')
    return hook_code


def get_instrument_ClassLoader_message(plid, package, session, fd, 
                                       declared_activites, 
                                       loaded_activities, 
                                       exist_dispatchTouchEvent_handle, exist_dispatchKeyEvent_handle):
    @ru.error_handler
    def wrapper(message, data):
        className = message['payload']['name']
        if className in declared_activites and className not in loaded_activities:
            loaded_activities.add(className)
            print('[ClassLoadedFromClassLoader]: ', message)
            code = activity.instrument_activity([className], exist_dispatchTouchEvent_handle, exist_dispatchKeyEvent_handle, is_main=True)
            _script = session.create_script(code)
            _script.on('message', activity.get_instrument_activity_message(plid, package, fd, exist_dispatchTouchEvent_handle, exist_dispatchKeyEvent_handle))
            _script.load()
    return wrapper