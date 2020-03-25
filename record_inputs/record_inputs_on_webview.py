# coding=utf8

import re
from . import record_utils as ru

WEBVIEW_CONSOLE_TAG = '[WebViewConsole]'
WEBVIEW_CLIENT_TAG = '[WebViewClient]'
WEBVIEW_TAG = '[WebView]'

"""
Record motion inputs and key inputs on webview
Details:
1. Instrument the method `setWebViewClient` of `android.webkit.WebView` to inject a snippet of JavaScript that is used to add listeners for motion input and key input, 
   and output the events on console
2. Instrument the method `setWebChromeClient` of `android.webkit.WebView` to collect the output of the injected snippet
"""

# WebView
def instrument_WebView():
    hook_code = """
        Java.perform(function(){
            var WebView = Java.use('android.webkit.WebView');
            WebView.setWebViewClient.implementation = function(client){
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'webViewSetWebViewClient',
                    target: 'WebView',
                    event: 'setWebViewClient',
                    WebView: ''+this,
                    WebViewClassname: this.$className,
                    WebViewClient: ''+client,
                    clientClassname: client.$className,
                    WebViewId: this.getId(),
                    timestamp: timestamp
                });
                return this.setWebViewClient(client);
            };
            WebView.setWebChromeClient.implementation = function(client){
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'webViewSetWebChromeClient',
                    target: 'WebView',
                    event: 'setWebChromeClient',
                    WebView: ''+this,
                    WebViewClassname: this.$className,
                    WebChromeClient: ''+client,
                    chromeClientClassname: client.$className,
                    WebViewId: this.getId(),
                    timestamp: timestamp
                });
                return this.setWebChromeClient(client);
            };
            WebView.onCreateInputConnection.implementation = function(outAttrs){
                console.log('[onCreateInputConnection]...');
                return this.onCreateInputConnection(outAttrs);
            }
        });
    """
    return hook_code

def get_instrument_WebView_message(plid, package, session, fd, webclient_classes, chromeclient_classes):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(WEBVIEW_TAG, message, fd, plid, package)
        if 'WebViewClient'in message['payload']:
            client_classname = message['payload']['clientClassname']
            if client_classname in webclient_classes:
                return
            webclient_classes.add(client_classname)
            _scirpt = session.create_script(instrument_WebViewClient(client_classname))
            _scirpt.on('message', get_instrument_WebClient_message(plid, package, fd))
            _scirpt.load()
        elif 'WebChromeClient' in message['payload']:
            client_classname = message['payload']['chromeClientClassname']
            if client_classname in chromeclient_classes:
                return
            chromeclient_classes.add(client_classname)
            _scirpt = session.create_script(instrument_WebChromeClient(client_classname))
            _scirpt.on('message', get_instrument_WebChromeClient_message(plid, package, fd))
            _scirpt.load()
    return wrapper


def instrument_WebChromeClient(client_classname):
    hook_code = """
        Java.perform(function(){
            var className = '%s';
            var Client = Java.use(className);
            Client.onConsoleMessage.overload('android.webkit.ConsoleMessage').implementation = function(console){
                var msgFromConsole = console.message();
                var timestamp = +new Date()/1000;
                send({
                    target: 'webview',
                    event: 'console',
                    message: msgFromConsole,
                    timestamp: timestamp
                });
                return this.onConsoleMessage(console);
            };
            Client.onCloseWindow.implementation = function(webview){
                var timestamp = +new Date()/1000;
                send({
                    target: 'webview',
                    event: 'onCloseWebView',
                    timestamp: timestamp
                });
                return this.onCloseWindow();
            };
        });
    """ % client_classname
    return hook_code


def get_instrument_WebChromeClient_message(plid, package, fd):
    @ru.error_handler
    def wrapper(message, data):
        event = message['payload']['event']
        if event == 'console':
            payload = message['payload']['message']
            if payload.startswith('[Frida]-'):
                ru.log(WEBVIEW_CONSOLE_TAG, message, fd, plid, package)
        else:
            ru.log(WEBVIEW_CONSOLE_TAG, message, fd, plid, package)
    return wrapper


def instrument_WebViewClient(client_classname):
    inject_js = """
        var __frida_inject = function(webViewInfo){
            console.log("Frida inject....");
            window.addEventListener("click", function(ev){
                var target = ev.toElement;
                console.log("[Frida]-" + JSON.stringify({
                    msgType: "webViewTouchEvent",
                    target: "webview",
                    x: ev.screenX,
                    y: ev.screenY,
                    targetTag: ev.target.tagName,
                    targetId: ev.target.id,
                    targetClassList: ev.target.classList,
                    text: ev.target.text,
                    herf: ev.target.href,
                    webview: webViewInfo,
                }));
            }, true);
            window.addEventListener("keyup", function(ev){
                console.log("[Frida]-" + JSON.stringify({
                    msgType: "webViewKeyEvent",
                    target: "webview",
                    key: ev.key,
                    keyCode: ev.keyCode,
                    targetTag: ev.target.tagName,
                    targetId: ev.target.id,
                    targetClassList: ev.target.classList,
                    text: ev.target.value,
                    inputType: ev.target.type,
                    inputName: ev.target.name,
                    webview: webViewInfo,
                }));
            }, true);
        };
    """
    inject_js = re.sub(r'\s{2,}', '', inject_js)

    hook_code = """
        Java.perform(function(){
            var className = '%s';
            var Client = Java.use(className);
            var fetchScript = '%s';
            Client.onPageFinished.implementation = function(webview, url){
                // Inject js
                var webviewInfo = webview.toString();
                webview.loadUrl('javascript:'+fetchScript);
                var jsUrl = 'javascript:__frida_inject("' + webviewInfo + '")';
                webview.loadUrl(jsUrl);
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'webViewPageLoaded',
                    target: 'webview',
                    event: 'onPageFinished',
                    webview: ''+webview,
                    url: ''+url,
                    clientClassname: className,
                    timestamp: timestamp
                });
                return this.onPageFinished(webview, url);
            }
        });
    """ % (client_classname, inject_js)
    return hook_code

def get_instrument_WebClient_message(plid, package, fd):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(WEBVIEW_CLIENT_TAG, message, fd, plid, package)
    return wrapper