# -*- coding: utf-8 -*-
"""ArchiveAnalyzer 安全单元测试 — 纯本地函数测试, 不执行任何样本"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.archive import ArchiveAnalyzer, _ExtractBudget, MAX_EXTRACT_FILES, MAX_TOTAL_UNCOMPRESSED


def test_is_safe_member_name_rejects_unsafe():
    for bad in ['../evil.exe', '..\\evil.exe', '/abs/path', 'C:/evil.exe',
                'a:evil', 'x\x00y']:
        assert ArchiveAnalyzer._is_safe_member_name(bad) is False, bad


def test_is_safe_member_name_accepts_safe():
    for good in ['folder/payload.exe', 'folder\\payload.exe', 'payload.exe']:
        assert ArchiveAnalyzer._is_safe_member_name(good) is True, good


def test_resolve_entry_rejects_parent_traversal():
    extract_dir = tempfile.mkdtemp(prefix='archive_safety_')
    assert ArchiveAnalyzer.resolve_entry(extract_dir, '../x') is None


def test_resolve_entry_returns_path_inside_extract_dir():
    extract_dir = tempfile.mkdtemp(prefix='archive_safety_')
    resolved = ArchiveAnalyzer.resolve_entry(extract_dir, 'folder/payload.exe')
    base = os.path.realpath(extract_dir)
    assert resolved is not None
    assert os.path.commonpath([base, resolved]) == base
    assert resolved == os.path.join(base, 'folder', 'payload.exe')


def test_budget_allows_up_to_file_cap():
    budget = _ExtractBudget()
    for _ in range(MAX_EXTRACT_FILES):
        assert budget.reserve(1) is True
    assert budget.file_count == MAX_EXTRACT_FILES
    assert budget.total_size == MAX_EXTRACT_FILES
    # 超过文件数上限后拒绝, 且计数器不再增长
    assert budget.reserve(1) is False
    assert budget.file_count == MAX_EXTRACT_FILES
    assert budget.total_size == MAX_EXTRACT_FILES


def test_budget_rejects_total_uncompressed_exceeding_limit():
    budget = _ExtractBudget()
    assert budget.reserve(MAX_TOTAL_UNCOMPRESSED) is True
    assert budget.total_size == MAX_TOTAL_UNCOMPRESSED
    assert budget.file_count == 1
    # 再小一个字节也超总量上限, 拒绝且计数器不变
    assert budget.reserve(1) is False
    assert budget.total_size == MAX_TOTAL_UNCOMPRESSED
    assert budget.file_count == 1
