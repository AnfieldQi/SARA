# coding=utf8

import json


def get_current_ts(message):
    return message['payload']['timestamp']


def log(tag, message, file_descriptor, plidx, package):
    if isinstance(message, str):
        l = '-'.join([tag, message, str(get_current_ts(message)), str(plidx), package])
        print(l)
        file_descriptor.write(l+'\n')
    else:
        l = '-'.join([tag, json.dumps(message), str(get_current_ts(message)), str(plidx), package])
        print(l)
        file_descriptor.write(l+'\n')


def error_handler(func):
    def wrapper(message, data):
        if message['type'] == 'error':
            print('[Func]: %s, [Error-msg]: %s' % (func.__name__, message))
            print('[Func]: %s, [Error-des]: %s' % (func.__name__, message['description']))
            print('[Func]: %s, [Error-sta]: %s' % (func.__name__, message['stack']))
            print('[Func]: %s, [Error-dat]: %s' % (func.__name__, data))
            return None
        else:
            return func(message, data)
    return wrapper