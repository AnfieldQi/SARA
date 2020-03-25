# coding=utf8

from . import record_utils as ru

SENSOR_MANAGER_TAG = '[SensorManager]'
SENSOR_LISTENER_TAG = '[SensorListener]'

"""
Record low-level sensor inputs, e.g., Gravity, Accelerometer, Gyroscope, Light
Details:
1. Instrument the method `registerListener` of `android.hardware.SensorManager` to locate the instance of `android.hardware.SensorEventListener`
2. Instrument the method `onSensorChanged` of `android.hardware.SensorEventListener` to record the sensor inputs
"""

# Sensor Manager
def instrument_sensor_manager():
    hook_code = """
        Java.perform(function(){
            var sensorManager = Java.use('android.hardware.SensorManager');
            sensorManager.registerListener.overload('android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int').implementation = function(listener, sensor, period){
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'listener',
                    listenerHandle: listener.$handle,
                    listenerClassname: listener.$className,
                    sensorType: sensor.getStringType(),
                    sensorIntType: sensor.getType(),
                    period: period,
                    timestamp: timestamp,
                    target: '' + this
                });
                return this.registerListener(listener, sensor, period);
            }
        });
    """
    return hook_code

def get_instrument_sensor_manager_message(plid, package, session, fd, exist_sensorListener_handles):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(SENSOR_MANAGER_TAG, message, fd, plid, package)
        listener_handle = message['payload']['listenerHandle']
        listener_classname = message['payload']['listenerClassname']
        _code = instrument_sensor_listener(listener_handle, listener_classname, exist_sensorListener_handles)
        _script = session.create_script(_code)
        _script.on('message', get_instrument_sensor_listener_message(plid, package, fd, exist_sensorListener_handles))
        _script.load()
    return wrapper

# Sensor Event Listener
def instrument_sensor_listener(handle, classname, exist_sensorListener_handles):
    exists_sensorListener_onSensorChanged_handle = ', '.join(['"' + h + '"' for h in exist_sensorListener_handles])
    if handle is None:
        hook_code = """
            Java.perform(function(){
                var existsSensorListeneronSensorChangedHandlers = [%s];
                var _className = '%s';
                var className = Java.use(_className);
                var methodHandle = className.onSensorChanged.handle;
                var isInstrument = true;
                for(var i = 0; i < existsSensorListeneronSensorChangedHandlers.length; i++){
                    if(existsSensorListeneronSensorChangedHandlers[i] === methodHandle.toString()){
                        isInstrument = false;
                        break;
                    }
                }
                if(isInstrument){
                    var timestamp = +new Date()/1000;
                    send({
                        msgType: 'handle',
                        handle: methodHandle,
                        timestamp: timestamp,
                        target: ''+this
                    });
                    className.onSensorChanged.implementation = function(sensorEvent){
                        var values = sensorEvent.values;
                        var timestamp = +new Date()/1000;
                        send({
                            msgType: 'sensorEvent',
                            target: '' + this,
                            values: values.value,
                            timestamp: timestamp,
                            className: _className,
                            sensorType: sensorEvent.sensor.value.getStringType(),
                        });
                        return this.onSensorChanged(sensorEvent);
                    };
                }
            });
        """ % (exists_sensorListener_onSensorChanged_handle, classname)
    else:
        hook_code = """
            Java.perform(function(){
                var existsSensorListeneronSensorChangedHandlers = [%s];
                var handle = %s;
                var _className = '%s';
                var className = Java.use(_className);
                var instance = Java.cast(ptr(handle), className);
                var methodHandle = instance.onSensorChanged.handle;
                var isInstrument = true;
                for(var i = 0; i < existsSensorListeneronSensorChangedHandlers.length; i++){
                    if(existsSensorListeneronSensorChangedHandlers[i] === methodHandle.toString()){
                        isInstrument = false;
                        break;
                    }
                }
                if(isInstrument){
                    var timestamp = +new Date()/1000;
                    send({
                        msgType: 'handle',
                        handle: methodHandle,
                        timestamp: timestamp,
                        target: ''+this,
                    });
                    instance.onSensorChanged.implementation = function(sensorEvent){
                        var values = sensorEvent.values;
                        var timestamp = +new Date()/1000;
                        send({
                            msgType: 'sensorEvent',
                            target: '' + this,
                            values: values.value,
                            timestamp: timestamp,
                            className: _className,
                            sensorType: sensorEvent.sensor.value.getStringType(),
                        });
                        return this.onSensorChanged(sensorEvent);
                    };
                }
            });
        """ % (exists_sensorListener_onSensorChanged_handle, handle, classname)
    return hook_code

def get_instrument_sensor_listener_message(plid, package, fd, exist_sensorListener_handles):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(SENSOR_LISTENER_TAG, message, fd, plid, package)
        msgType = message['payload']['msgType']
        if msgType == 'handle':
            exist_sensorListener_handles.add(message['payload']['handle'])
    return wrapper
