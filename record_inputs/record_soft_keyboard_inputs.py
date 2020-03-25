# coding=utf8

from . import record_utils as ru

EDITABLE_INPUT_CONNECTION_TAG = '[EditableInputConnection]'
SPANNER_STRING_BUILDER_TAG = '[SpannerStringBuilder]'
TEXT_VIEW_KEY_TAG = '[TextViewKeyboard]'

# Keyboard Action
def instrument_EditableInputConnection():
    hook_code = """
        Java.perform(function(){
            var BaseInputConnection = Java.use('android.view.inputmethod.BaseInputConnection');
            BaseInputConnection.$init.overload('android.view.View', 'boolean').implementation = function(view, fullEditor){
                console.log('[BaseInputConnection]...');
                console.log(this.$className);
                console.log(this.mBeginBatchEdit);
                return this.$init(view, fullEditor);
            };
            var EditableInputConnection = Java.use('com.android.internal.widget.EditableInputConnection');
            EditableInputConnection.beginBatchEdit.implementation = function(){
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'type',
                    target: 'EditableInputConnection',
                    event: 'beginBatchEdit',
                    mBatchEditNesting: this.mBatchEditNesting.value,
                    editableInputConnection: ''+this,
                    TextView: ''+this.mTextView.value,
                    TextViewHandle: this.mTextView.value.$handle,
                    TextViewClassname: this.mTextView.value.$className,
                    TextViewPositionInScreen: this.mTextView.value.getLocationOnScreen(),
                    TextViewWidth: this.mTextView.value.getWidth(),
                    TextViewHeight: this.mTextView.value.getHeight(),
                    TextViewX: this.mTextView.value.getX(),
                    TextViewY: this.mTextView.value.getY(),
                    TextViewId: this.mTextView.value.getId(),
                    timestamp: timestamp
                });
                return this.beginBatchEdit();
            };
            EditableInputConnection.performEditorAction.implementation = function(actionCode){
                var timestamp = +new Date()/1000;
                send({
                    msgType: 'type',
                    target: 'EditableInputConnection',
                    event: 'performEditorAction',
                    editableInputConnection: ''+this,
                    msgType: 'keyEvent',
                    mBatchEditNesting: this.mBatchEditNesting.value,
                    actionCode: actionCode,
                    TextView: ''+this.mTextView.value,
                    TextViewHandle: this.mTextView.value.$handle,
                    TextViewClassname: this.mTextView.value.$className,
                    TextViewPositionInScreen: this.mTextView.value.getLocationOnScreen(),
                    TextViewWidth: this.mTextView.value.getWidth(),
                    TextViewHeight: this.mTextView.value.getHeight(),
                    TextViewX: this.mTextView.value.getX(),
                    TextViewY: this.mTextView.value.getY(),
                    TextViewId: this.mTextView.value.getId(),
                    timestamp: timestamp
                });
                return this.performEditorAction(actionCode);
            };
        });
    """
    return hook_code

def get_instrument_EditableInputConnection_message(plid, package, fd):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(EDITABLE_INPUT_CONNECTION_TAG, message, fd, plid, package)
    return wrapper


def instrument_onKeyPreIme():
    hook_code = """
        Java.perform(function(){
            var TextView = Java.use('android.widget.TextView');
            TextView.onKeyPreIme.implementation = function(keyCode, keyEvent){
                var actionCode = keyEvent.getAction();
                var deviceId = keyEvent.getDeviceId();
                var detail = keyEvent.toString();
                var timestamp = +new Date()/1000;
                send({
                    keyCode: keyCode,
                    downTime: keyEvent.getDownTime(),
                    actionCode: actionCode,
                    detail: detail,
                    deviceId: deviceId,
                    target: 'TextView',
                    msgType: 'keyEvent',
                    viewId: this.getId(),
                    timestamp: timestamp
                });
                return this.onKeyPreIme(keyCode, keyEvent);
            };
            var AutoCompleteTextView = Java.use('android.widget.AutoCompleteTextView');
            AutoCompleteTextView.onKeyPreIme.implementation = function(keyCode, keyEvent){
                var actionCode = keyEvent.getAction();
                var deviceId = keyEvent.getDeviceId();
                var detail = keyEvent.toString();
                var timestamp = +new Date()/1000;
                send({
                    keyCode: keyCode,
                    downTime: keyEvent.getDownTime(),
                    actionCode: actionCode,
                    detail: detail,
                    deviceId: deviceId,
                    target: 'AutoCompleteTextView',
                    msgType: 'keyEvent',
                    viewId: this.getId(),
                    timestamp: timestamp
                });
                return this.onKeyPreIme(keyCode, keyEvent);
            };
        });
    """
    return hook_code

def get_instrument_onKeyPreIme_message(plid, package, fd):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(TEXT_VIEW_KEY_TAG, message, fd, plid, package)
    return wrapper

# Editable String
def instrument_SpannableStringBuilder():
    hook_code = """
        Java.perform(function(){
            var spannerString = Java.use('android.text.SpannableStringBuilder');
            spannerString.toString.implementation = function(){
                var timestamp = +new Date()/1000;
                var string = this.toString();
                var mIndexOfSpan = this.mIndexOfSpan.value;
                var address = null;
                if(mIndexOfSpan !== null){
                    address = this.mIndexOfSpan.value.hashCode();
                }
                send({
                    target: 'Editable',
                    msgType: 'text',
                    text: string,
                    classname: this.$className, 
                    handle: this.$handle,
                    address: address,
                    timestamp: timestamp
                });
                return string;
            };
        });
    """
    return hook_code

def get_instrument_SpannableStringBuilder_message(plid, package, fd):
    @ru.error_handler
    def wrapper(message, data):
        ru.log(SPANNER_STRING_BUILDER_TAG, message, fd, plid, package)
    return wrapper