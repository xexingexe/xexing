# -*- coding: utf-8 -*-
"""ConfigManager 类型收敛与字典合并测试 (不导入 orchestrator)。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_manager():
    from config import ConfigManager
    return ConfigManager()


def test_coerce_value_bool():
    from config import ConfigManager

    assert ConfigManager._coerce_value(True, True) is True
    assert ConfigManager._coerce_value(False, 1) is True
    assert ConfigManager._coerce_value(True, 0) is False
    assert ConfigManager._coerce_value(False, 'yes') is True
    assert ConfigManager._coerce_value(True, 'off') is False
    # 无法安全转换的字符串应返回 None
    assert ConfigManager._coerce_value(True, 'not-a-bool') is None


def test_coerce_value_int():
    from config import ConfigManager

    assert ConfigManager._coerce_value(0, '42') == 42
    assert ConfigManager._coerce_value(0, 3.9) == 3
    assert ConfigManager._coerce_value(0, 'not-int') is None
    assert ConfigManager._coerce_value(0, [1, 2]) is None


def test_coerce_value_str_rejects_bad():
    from config import ConfigManager

    assert ConfigManager._coerce_value('', 'abc') == 'abc'
    assert ConfigManager._coerce_value('', 123) == '123'
    assert ConfigManager._coerce_value('', True) == 'True'
    assert ConfigManager._coerce_value('', ['a']) is None
    assert ConfigManager._coerce_value('', {'a': 1}) is None


def test_merge_dict_accepts_right_types_and_ignores_bad_keys():
    mgr = _make_manager()

    mgr._merge_dict({
        'threads': 7,
        'debug': True,
        'report': {
            'output_dir': 'reports_test',
            'max_keep_reports': 5,
        },
        'sandbox': {
            'cpu_limit_sec': 60,
        },
        'unknown_field': 1,
    })

    assert mgr.config.threads == 7
    assert mgr.config.debug is True
    assert mgr.config.report.output_dir == 'reports_test'
    assert mgr.config.report.max_keep_reports == 5
    assert mgr.config.sandbox.cpu_limit_sec == 60
    # 顶层未知 key 应被忽略
    assert not hasattr(mgr.config, 'unknown_field')


def test_merge_dict_ignores_wrong_types():
    mgr = _make_manager()
    mgr._merge_dict({
        'threads': 7,
        'debug': True,
        'sandbox': {'cpu_limit_sec': 60},
    })

    mgr._merge_dict({
        'threads': 'not-int',
        'debug': 'not-bool',
        'sandbox': {'cpu_limit_sec': 'abc'},
    })

    # 坏类型值必须被跳过, 保留原值
    assert mgr.config.threads == 7
    assert mgr.config.debug is True
    assert mgr.config.sandbox.cpu_limit_sec == 60
