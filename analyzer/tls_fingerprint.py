#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS 指纹 — JA3/JA3S 计算 + SNI 提取 (纯解析, 无网络副作用)

用于识别恶意 C2 的 TLS 客户端指纹 (JA3 广泛用于威胁情报关联)。
解析 TLS Record/Handshake 结构, 从 ClientHello/ServerHello 提取字段并计算 JA3/JA3S。
"""
import hashlib
import struct
from typing import Dict, List, Optional, Tuple

# 扩展类型 → 名字 (常用, 用于报告可读性)
EXTENSION_NAMES = {
    0: 'server_name', 5: 'status_request', 10: 'supported_groups',
    11: 'ec_point_formats', 13: 'signature_algorithms', 16: 'ALPN',
    18: 'signed_cert_timestamp', 21: 'padding', 23: 'extended_master_secret',
    27: 'compress_certificate', 28: 'record_size_limit', 35: 'session_ticket',
    43: 'supported_versions', 45: 'psk_key_exchange_modes', 51: 'key_share',
}


def _read_handshake_length(data: bytes, offset: int) -> Optional[int]:
    if offset + 3 > len(data):
        return None
    return int.from_bytes(data[offset:offset + 3], 'big')


def _parse_extensions(data: bytes) -> List[Tuple[int, bytes]]:
    """解析扩展列表 → [(ext_type, ext_data)]"""
    exts = []
    i = 0
    while i + 4 <= len(data):
        ext_type = int.from_bytes(data[i:i + 2], 'big')
        ext_len = int.from_bytes(data[i + 2:i + 4], 'big')
        if i + 4 + ext_len > len(data):
            break
        exts.append((ext_type, data[i + 4:i + 4 + ext_len]))
        i += 4 + ext_len
    return exts


def _ja3_client_hello(body: bytes) -> Dict:
    """从 ClientHello body (handshake 之后) 计算 JA3 + 提取 SNI"""
    result = {'ja3': '', 'sni': '', 'version': 0}
    if len(body) < 2 + 32 + 1:
        return result
    off = 0
    version = int.from_bytes(body[off:off + 2], 'big')
    result['version'] = version
    off += 2 + 32  # legacy_version + random
    sess_id_len = body[off]
    off += 1 + sess_id_len
    if off + 2 > len(body):
        return result
    cs_len = int.from_bytes(body[off:off + 2], 'big')
    off += 2
    if off + cs_len > len(body):
        return result
    ciphers_raw = body[off:off + cs_len]
    off += cs_len
    ciphers = [int.from_bytes(ciphers_raw[j:j + 2], 'big') for j in range(0, cs_len, 2)]
    if off + 1 > len(body):
        return result
    comp_len = body[off]
    off += 1 + comp_len
    exts_list = []
    curves = []
    point_formats = []
    sni = ''
    if off + 2 <= len(body):
        ext_total = int.from_bytes(body[off:off + 2], 'big')
        off += 2
        if off + ext_total <= len(body):
            for ext_type, ext_data in _parse_extensions(body[off:off + ext_total]):
                exts_list.append(ext_type)
                if ext_type == 0:  # server_name (SNI)
                    if len(ext_data) >= 5:
                        name_len = int.from_bytes(ext_data[3:5], 'big')
                        try:
                            sni = ext_data[5:5 + name_len].decode('utf-8', errors='ignore')
                        except Exception:
                            sni = ''
                elif ext_type == 10:  # supported_groups
                    if len(ext_data) >= 2:
                        glen = int.from_bytes(ext_data[0:2], 'big')
                        curves = [int.from_bytes(ext_data[2 + j:2 + j + 2], 'big')
                                  for j in range(0, glen, 2) if 2 + j + 2 <= len(ext_data)]
                elif ext_type == 11:  # ec_point_formats
                    if len(ext_data) >= 1:
                        flen = ext_data[0]
                        point_formats = list(ext_data[1:1 + flen])
    result['sni'] = sni
    result['ciphers'] = [f'{c:04x}' for c in ciphers]
    result['extensions'] = exts_list
    result['curves'] = curves
    result['point_formats'] = point_formats
    # JA3 = MD5(version, ciphers, extensions, curves, point_formats)
    parts = [
        str(version),
        '-'.join(f'{c}' for c in ciphers),
        '-'.join(f'{e}' for e in exts_list),
        '-'.join(f'{c}' for c in curves),
        '-'.join(f'{p}' for p in point_formats),
    ]
    result['ja3'] = hashlib.md5(','.join(parts).encode('ascii', errors='ignore')).hexdigest()
    return result


def _ja3s_server_hello(body: bytes) -> Dict:
    """从 ServerHello body 计算 JA3S"""
    result = {'ja3s': '', 'version': 0}
    if len(body) < 2 + 32 + 1:
        return result
    off = 0
    version = int.from_bytes(body[off:off + 2], 'big')
    result['version'] = version
    off += 2 + 32
    sess_id_len = body[off]
    off += 1 + sess_id_len
    if off + 2 > len(body):
        return result
    cipher = int.from_bytes(body[off:off + 2], 'big')
    off += 2
    comp = body[off] if off < len(body) else 0
    off += 1
    exts_list = []
    if off + 2 <= len(body):
        ext_total = int.from_bytes(body[off:off + 2], 'big')
        off += 2
        if off + ext_total <= len(body):
            exts_list = [t for t, _ in _parse_extensions(body[off:off + ext_total])]
    result['cipher'] = f'{cipher:04x}'
    result['extensions'] = exts_list
    result['ja3s'] = hashlib.md5(
        f"{version},{cipher},{'-'.join(str(e) for e in exts_list)}".encode('ascii', errors='ignore')
    ).hexdigest()
    return result


def extract_tls_fingerprints(raw: bytes) -> Optional[Dict]:
    """从 TCP payload 提取 TLS 指纹。返回 {'ja3','ja3s','sni','version'} 或 None。

    一个 payload 可能含多个 record, 循环解析; 首个 ClientHello/ServerHello 即返回。
    """
    if not raw or len(raw) < 6:
        return None
    result = {}
    i = 0
    while i + 5 <= len(raw):
        content_type = raw[i]
        if content_type == 0x16:  # handshake
            if i + 5 > len(raw):
                break
            rec_len = int.from_bytes(raw[i + 3:i + 5], 'big')
            hs = raw[i + 5:i + 5 + rec_len]
            # 可能多个 handshake 消息挤在一个 record
            j = 0
            while j + 4 <= len(hs):
                msg_type = hs[j]
                msg_len = _read_handshake_length(hs, j + 1)
                if msg_len is None:
                    break
                body = hs[j + 4:j + 4 + msg_len]
                if msg_type == 0x01 and 'ja3' not in result:  # ClientHello
                    ch = _ja3_client_hello(body)
                    if ch.get('ja3'):
                        result['ja3'] = ch['ja3']
                        result['sni'] = ch.get('sni', '')
                        result['version'] = ch.get('version', 0)
                elif msg_type == 0x02 and 'ja3s' not in result:  # ServerHello
                    sh = _ja3s_server_hello(body)
                    if sh.get('ja3s'):
                        result['ja3s'] = sh['ja3s']
                j += 4 + msg_len
            break  # 只解析第一个 handshake record
        elif content_type in (0x14, 0x15, 0x17):  # 非 handshake, 跳过
            i += 5
            continue
        else:
            break
    if not result:
        return None
    return result
