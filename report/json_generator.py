#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSON Report Generator"""
import json
import os
from logger import get_logger

logger = get_logger('report.json')

# 关注叾嗣exe谢谢喵

class JSONReportGenerator:
    def generate(self, report, output_path):
        logger.info(f"[+] Generating JSON: {output_path}")
        data = self._report_to_dict(report)
        dirname = os.path.dirname(output_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    def _report_to_dict(self, report):
        data = {}
        for key, value in report.__dict__.items():
            if value is None:
                data[key] = None
            elif hasattr(value, '__dataclass_fields__'):
                data[key] = self._dataclass_to_dict(value, set())
            elif isinstance(value, list):
                data[key] = [self._dataclass_to_dict(item, set()) if hasattr(item, '__dataclass_fields__') else item for item in value]
            elif isinstance(value, dict):
                data[key] = value
            else:
                data[key] = value
        return data

    def _dataclass_to_dict(self, obj, seen=None):
        if seen is None:
            seen = set()
        obj_id = id(obj)
        if obj_id in seen:
            return '<circular>'
        # 使用"当前递归栈"而非全局集合: 同一对象在兄弟位置重复出现时
        # 仍应正常序列化, 只有真正成环才回退为占位符。
        seen.add(obj_id)
        try:
            result = {}
            for key, value in obj.__dict__.items():
                if hasattr(value, '__dataclass_fields__'):
                    result[key] = self._dataclass_to_dict(value, seen)
                elif isinstance(value, list):
                    result[key] = [
                        self._dataclass_to_dict(item, seen)
                        if hasattr(item, '__dataclass_fields__') else item
                        for item in value
                    ]
                else:
                    result[key] = value
            return result
        finally:
            seen.discard(obj_id)
