# -*- coding: utf-8 -*-
import sys

__author__ = 'E_Bwill'
__time__ = '2018/3/6 17:32'

STYLE = {
    'fore': {  # 前景色
        'black': 30,  # 黑色
        'red': 31,  # 红色
        'green': 32,  # 绿色
        'yellow': 33,  # 黄色
        'blue': 34,  # 蓝色
        'purple': 35,  # 紫红色
        'cyan': 36,  # 青蓝色
        'white': 37,  # 白色
    },

    'back': {  # 背景
        'black': 40,  # 黑色
        'red': 41,  # 红色
        'green': 42,  # 绿色
        'yellow': 43,  # 黄色
        'blue': 44,  # 蓝色
        'purple': 45,  # 紫红色
        'cyan': 46,  # 青蓝色
        'white': 47,  # 白色
    },

    'mode': {  # 显示模式
        'mormal': 0,  # 终端默认设置
        'bold': 1,  # 高亮显示
        'underline': 4,  # 使用下划线
        'blink': 5,  # 闪烁
        'invert': 7,  # 反白显示
        'hide': 8,  # 不可见
    },

    'default': {
        'end': 0,
    },
}


def _cprint(string, ln, mode='', fore='', back=''):
    mode = '%s' % STYLE['mode'][mode] if mode in STYLE['mode'] else ''
    fore = '%s' % STYLE['fore'][fore] if fore in STYLE['fore'] else ''
    back = '%s' % STYLE['back'][back] if back in STYLE['back'] else ''
    style = ';'.join([s for s in [mode, fore, back] if s])
    style = '\033[%sm' % style if style else ''
    end = '\033[%sm' % STYLE['default']['end'] if style else ''
    if ln:
        print(('%s%s%s' % (style, string, end)))
    else:
        sys.stdout.write((('%s%s%s' % (style, string, end))))


def cprintln(string, mode='', fore='', back=''):
    _cprint(string, True, mode=mode, fore=fore, back=back)


def cprint(string, mode='', fore='', back=''):
    _cprint(string, False, mode=mode, fore=fore, back=back)
