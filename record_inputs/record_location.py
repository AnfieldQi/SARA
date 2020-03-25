# coding=utf8

from . import record_utils as ru

LOCATION_MANAGER_TAG = '[LocationManager]'
LOCATION_LISTENER_TAG = '[LocationListener]'

"""
Record location sensor inputs
Details:

- Active

1. Instrument the method `getLastKnownLocation` of `android.location.LocationManager` to actively record the location inputs 

- Passive

2. Instrument the method `requestLocationUpdates` of `android.location.LocationManager` to locate the instance of `android.location.LocationListener`
2. Instrument the method `onLocationChanged` of `android.location.LocationListener` to record the location sensor inputs
"""

# Location Manager
def instrument_location_manager():
    hook_code = """
        Java.perform(function(){
            var locationManager = Java.use('android.location.LocationManager');
            locationManager.getLastKnownLocation.implementation = function(provider){
                var location = this.getLastKnownLocation(provider)
                var timestamp = +new Date()/1000;
                if(location === null){
                    locationInfo = null
                }else{
                    locationInfo = {
                        longitude: location.getLongitude(),
                        latiutude: location.getLatitude(),
                        bearing: location.getBearing(),
                        speed: location.getSpeed(),
                        altitude: location.getAltitude(),
                        accuracy: location.getAccuracy(),
                    }
                }
                send({
                    timestamp: timestamp,
                    msgType: 'lastKnownLocation',
                    location: locationInfo,
                    target: '' + this,
                    className: 'android.location.LocationManager',
                    provider: provider
                });
                return location;
            }
            locationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener').implementation = function(provider, minTime, minDistance, listener){
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'locationListener',
                    listenerHandle: listener.$handle,
                    listenerClassname: listener.$className,
                    minTime: minTime,
                    minDistance: minDistance,
                    timestamp: timestamp,
                    target: ''+this,
                    provider: provider
                });
                return this.requestLocationUpdates(provider, min, length, listener);
            }
        });
    """
    return hook_code

def get_instrument_location_manager_message(plid, package, session, fd, exist_locationListener_handle):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(LOCATION_MANAGER_TAG, message, fd, plid, package)
        payload = message['payload']
        if payload['msgType'] == 'locationListener':
            listener_handle = payload['listenerHandle']
            listener_classname = payload['listenerClassname']
            provider = payload['provider']
            _code = instrument_location_listener(listener_handle, listener_classname, exist_locationListener_handle, provider=provider)
            _script = session.create_script(_code)
            _script.on('message', get_instrument_location_listener_message(plid, package, fd, exist_locationListener_handle))
            _script.load()
    return wrapper


# Location Listener
def instrument_location_listener(handle, classname, exist_locationListener_handle, provider=None):
    exists_locationListener_onLocationChanged_handle = ', '.join(['"' + h + '"' for h in exist_locationListener_handle])
    if handle is None:
        hook_code = """
            Java.perform(function(){
                var existsLocationListenerOnLocationChangedHandlers = [%s];
                var _className = '%s';
                var className = Java.use(_className);
                var methodHandle = className.onLocationChanged.handle;
                var isInstrument = true;
                for(var i = 0; i < existsLocationListenerOnLocationChangedHandlers.length; i++){
                    if(existsLocationListenerOnLocationChangedHandlers[i] === methodHandle.toString()){
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
                    className.onLocationChanged.implementation = function(location){
                        if(location === null){
                            locationInfo = null
                        }else{
                            locationInfo = {
                                longitude: location.getLongitude(),
                                latitude: location.getLatitude(),
                                bearing: location.getBearing(),
                                speed: location.getSpeed(),
                                altitude: location.getAltitude(),
                                accuracy: location.getAccuracy(),
                            }
                        }
                        send({
                            msgType: 'locationEvent',
                            target: '' + this,
                            location: locationInfo,
                            timestamp: timestamp,
                            className: _className,
                            provider: ''
                        });
                        return this.onLocationChanged(location);
                    };
                }
            });
        """ % (exists_locationListener_onLocationChanged_handle, classname)
    else:
        hook_code = """
            Java.perform(function(){
                var existsLocationListenerOnLocationChangedHandlers = [%s];
                var handle = %s;
                var _className = '%s';
                var provider = '%s';
                var className = Java.use(_className);
                var instance = Java.cast(ptr(handle), className);
                var methodHandle = instance.onLocationChanged.handle;
                var isInstrument = true;
                for(var i = 0; i < existsLocationListenerOnLocationChangedHandlers.length; i++){
                    if(existsLocationListenerOnLocationChangedHandlers[i] === methodHandle.toString()){
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
                    instance.onLocationChanged.implementation = function(location){
                        if(location === null){
                            locationInfo = null
                        }else{
                            locationInfo = {
                                longitude: location.getLongitude(),
                                latitude: location.getLatitude(),
                                bearing: location.getBearing(),
                                speed: location.getSpeed(),
                                altitude: location.getAltitude(),
                                accuracy: location.getAccuracy(),
                            }
                        }
                        send({
                            msgType: 'locationEvent',
                            target: ''+this,
                            location: locationInfo,
                            timestamp: timestamp,
                            className: _className,
                            provider: provder
                        });
                        return this.onLocationChanged(location);
                    };
                }
            });
        """ % (exists_locationListener_onLocationChanged_handle, handle, classname, provider)
    return hook_code


def get_instrument_location_listener_message(plid, package, fd, exist_locationListener_handle):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(LOCATION_LISTENER_TAG, message, fd, plid, package)
        msgType = message['payload']['msgType']
        if msgType == 'handle':
            exist_locationListener_handle.add(message['payload']['handle'])
    return wrapper