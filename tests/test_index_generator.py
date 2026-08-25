# -*- coding: utf-8 -*-
"""report.index_generator 输出测试 (不运行, 仅编写)。"""
import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _newest_html(out_dir):
    matches = [os.path.join(out_dir, f) for f in os.listdir(out_dir)
               if f.endswith(('.html', '.htm'))]
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


def test_generate_batch_index_escapes_snippet():
    from report.index_generator import generate_batch_index

    with tempfile.TemporaryDirectory() as td:
        sample_name = 'sample<script>alert(1)</script>.exe'
        result1 = SimpleNamespace(
            scan_id='SCAN0001',
            risk_level='high',
            risk_score=88,
            file_info=SimpleNamespace(name=sample_name),
            malware_family=SimpleNamespace(primary_family='TestFam', primary_confidence=95),
        )
        results = [
            (os.path.join(td, sample_name), result1),
            (os.path.join(td, 'broken.exe'), None),
        ]

        idx = generate_batch_index(td, results)
        if idx:
            assert os.path.isfile(idx)
            html_path = idx
        else:
            html_path = _newest_html(td)
            assert html_path

        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # HTML 转义后的样本名必须出现在索引中
        assert '&lt;script&gt;alert(1)&lt;/script&gt;.exe' in content


def test_generate_url_index_output():
    from report.index_generator import generate_url_index

    with tempfile.TemporaryDirectory() as td:
        r = SimpleNamespace(
            url='http://evil.example.com/path?x=1',
            risk_level='high',
            risk_score=85,
            summary='Suspicious payload detected',
        )

        idx = generate_url_index(td, [r])
        if idx:
            assert os.path.isfile(idx)
            html_path = idx
        else:
            html_path = _newest_html(td)
            assert html_path

        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()
        assert 'evil.example.com' in content
