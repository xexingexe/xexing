#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磁盘取证引擎 — MBR/BootKit/BootSector/磁盘破坏检测
"""
import re
import struct
from typing import List, Dict, Optional

from logger import get_logger

logger = get_logger('analyzer.disk_forensics')


class DiskForensics:
    """磁盘取证分析器"""

    MBR_SIGNATURE = b'\x55\xaa'
    NTFS_SIGNATURE = b'NTFS    '
    FAT32_SIGNATURE = b'FAT32   '
    BOOTKIT_PATTERNS = [
        (rb'\xbb\x00\x7c', 'MBR 加载器异常（BB 00 7C）'),
        (rb'TLDR|BootMgr|BOOTMGR|winload', '替换的引导管理器'),
        (rb'MZ.{30,}PE\x00\x00', 'MBR 中的 PE 映像'),
        (rb'GAPZ|TDL4|TDL3|ZeroAccess|MAXSS', '已知 BootKit 签名'),
        (rb'\xe9[\x00-\xff]{3}', 'MBR 中的 JMP 跳转（多阶段加载）'),
    ]

    @staticmethod
    def read_disk_sectors(physical_drive: int = 0, sector_count: int = 1) -> Optional[bytes]:
        """读取物理磁盘扇区（需管理员权限）"""
        try:
            drive_path = f'\\\\.\\PhysicalDrive{physical_drive}'
            with open(drive_path, 'rb') as f:
                return f.read(sector_count * 512)
        except PermissionError:
            logger.warning("[DiskForensics] 无管理员权限，无法读取物理磁盘")
            return None
        except FileNotFoundError:
            logger.debug(f"[DiskForensics] 磁盘不存在: PhysicalDrive{physical_drive}")
            return None
        except Exception as e:
            logger.debug(f"[DiskForensics] 读取磁盘失败: {e}")
            return None

    @staticmethod
    def analyze_mbr(mbr_data: bytes = None) -> Dict:
        """分析 MBR 扇区"""
        result = {
            'has_valid_signature': False,
            'partition_count': 0,
            'partitions': [],
            'bootkits': [],
            'anomalies': [],
            'bootloader_type': 'Unknown',
        }

        if not mbr_data or len(mbr_data) < 512:
            if mbr_data is None:
                mbr_data = DiskForensics.read_disk_sectors(0, 1)
            if not mbr_data:
                result['anomalies'].append('无法读取 MBR')
                return result

        # 检查 MBR 签名（最后2字节）
        if mbr_data[-2:] == DiskForensics.MBR_SIGNATURE:
            result['has_valid_signature'] = True
        else:
            result['anomalies'].append('MBR 签名缺失 (缺少 0x55AA)')

        # 检查引导代码
        boot_code = mbr_data[:440]
        if boot_code.count(0) > 400:
            result['anomalies'].append('MBR 引导代码几乎为空（可能被覆盖）')

        # 检查分区表（偏移 446-510，共4条16字节记录）
        for i in range(4):
            offset = 446 + i * 16
            entry = mbr_data[offset:offset + 16]
            if entry[4] != 0x00:
                result['partition_count'] += 1
                part_type = entry[4]
                lba_start = struct.unpack('<I', entry[8:12])[0]
                size = struct.unpack('<I', entry[12:16])[0]
                part_types = {
                    0x07: 'NTFS/exFAT', 0x0B: 'FAT32', 0x0C: 'FAT32 LBA',
                    0x83: 'Linux', 0x82: 'Linux Swap', 0x05: 'Extended',
                    0x0F: 'Extended LBA', 0xEE: 'GPT Protective',
                }
                result['partitions'].append({
                    'index': i + 1,
                    'type': part_types.get(part_type, f'Unknown(0x{part_type:02X})'),
                    'type_hex': f'0x{part_type:02X}',
                    'lba_start': lba_start,
                    'size_sectors': size,
                    'size_mb': round(size * 512 / 1024 / 1024, 1),
                })

        # BootKit 检测
        for pattern, desc in DiskForensics.BOOTKIT_PATTERNS:
            if re.search(pattern, mbr_data[:512], re.DOTALL):
                result['bootkits'].append(desc)

        # 引导器类型
        boot_text = mbr_data[:440].decode('latin-1', errors='replace')
        bootloader_keywords = {
            'Invalid partition table': 'DOS/Win9x',
            'Missing operating system': 'DOS/Win9x',
            'Error loading operating system': 'Windows NT',
            'BOOTMGR': 'Windows NT6+',
            'NTLDR': 'Windows XP/2003',
            'GRUB': 'GRUB (Linux)',
            'LILO': 'LILO (Linux)',
        }
        for keyword, bt in bootloader_keywords.items():
            if keyword in boot_text:
                result['bootloader_type'] = bt
                break

        if result['bootkits']:
            logger.warning(f"[DiskForensics] MBR BootKit 检测: {len(result['bootkits'])} 项")
            for bk in result['bootkits']:
                logger.warning(f"  {bk}")
        if result['anomalies']:
            for a in result['anomalies']:
                logger.info(f"[DiskForensics] MBR 异常: {a}")

        return result

    @staticmethod
    def analyze_vbr(volume: str = 'C:\\') -> Optional[Dict]:
        """分析卷引导记录 (VBR)"""
        result = {
            'valid': False,
            'filesystem': 'Unknown',
            'anomalies': [],
        }

        try:
            stripped = volume.rstrip("\\")
            drive_path = '\\\\.\\' + stripped
            with open(drive_path, 'rb') as f:
                vbr = f.read(512)
        except PermissionError:
            result['anomalies'].append('无权限读取')
            return result
        except Exception as e:
            result['anomalies'].append(f'读取失败: {e}')
            return result

        if len(vbr) < 512:
            return result

        if vbr[-2:] != DiskForensics.MBR_SIGNATURE:
            result['anomalies'].append('引导扇区签名缺失')
            return result

        result['valid'] = True
        oem_name = vbr[3:11].decode('latin-1', errors='replace').strip()
        result['oem_name'] = oem_name

        if vbr[3:11] == DiskForensics.NTFS_SIGNATURE:
            result['filesystem'] = 'NTFS'
            bytes_per_sector = struct.unpack('<H', vbr[11:13])[0]
            sectors_per_cluster = vbr[13]
            total_sectors = struct.unpack('<Q', vbr[40:48])[0]
            mft_start = struct.unpack('<Q', vbr[48:56])[0]
            result['details'] = {
                'bytes_per_sector': bytes_per_sector,
                'sectors_per_cluster': sectors_per_cluster,
                'total_sectors': total_sectors,
                'total_size_gb': round(total_sectors * bytes_per_sector / 1024**3, 1),
                'mft_start': mft_start,
            }
        elif vbr[82:90] == DiskForensics.FAT32_SIGNATURE:
            result['filesystem'] = 'FAT32'
        elif b'FAT16' in vbr[54:62]:
            result['filesystem'] = 'FAT16'
        else:
            result['filesystem'] = f'Unknown (OEM:{oem_name})'

        # VBR 异常检测
        if b'MZ' in vbr[:2]:
            result['anomalies'].append('VBR 中包含 MZ 签名（可能被恶意覆盖）')
        if b'PE\x00\x00' in vbr[:512]:
            result['anomalies'].append('VBR 中包含 PE 签名（BootKit 感染）')

        return result

    @staticmethod
    def check_disk_integrity(physical_drive: int = 0) -> Dict:
        """检查磁盘完整性（MBR+VBR）"""
        result = {
            'physical_drive': physical_drive,
            'mbr': None,
            'vbr_c': None,
            'total_anomalies': 0,
            'suspected_bootkit': False,
        }

        mbr_data = DiskForensics.read_disk_sectors(physical_drive, 1)
        result['mbr'] = DiskForensics.analyze_mbr(mbr_data)
        result['vbr_c'] = DiskForensics.analyze_vbr('C:\\')

        if result['mbr']:
            result['total_anomalies'] += len(result['mbr'].get('anomalies', [])) + \
                                         len(result['mbr'].get('bootkits', []))
        if result['vbr_c']:
            result['total_anomalies'] += len(result['vbr_c'].get('anomalies', []))

        if result['mbr'] and result['mbr'].get('bootkits'):
            result['suspected_bootkit'] = True

        return result

    @staticmethod
    def detect_disk_destruction_indicators(strings: List[str], api_calls: List[str]) -> Dict:
        """从字符串/API调用中检测磁盘破坏行为"""
        indicators = {
            'mbr_access': [],
            'physical_disk_access': [],
            'bootkit_behavior': [],
            'raw_write': [],
        }

        all_text = '\n'.join(strings + api_calls).lower()

        patterns = {
            'mbr_access': [
                (r'\\\\\\.\\physicaldrive\d', '直接访问物理磁盘'),
                (r'CreateFile.*\\\\\\.\\PhysicalDrive', '打开物理磁盘句柄'),
                (r'WriteFile.*\\\\\\.\\PhysicalDrive', '写入物理磁盘'),
                (r'DeviceIoControl.*IOCTL_DISK', '磁盘 IOCTL 操作'),
            ],
            'physical_disk_access': [
                (r'MASTER BOOT RECORD', 'MBR 引用'),
                (r'setupldr|bootmgr|ntldr', '引导管理器引用'),
                (r'\.\\\\.\\PhysicalDrive|\.\\\\.\\BootPartition', '物理磁盘直接访问'),
            ],
            'bootkit_behavior': [
                (r'hook.*boot|boot.*hook|bootkit', 'BootKit 行为关键词'),
                (r'VBR|MBR.*write|MBR.*overwrite', 'MBR/VBR 修改'),
                (r'UEFI.*boot|SecureBoot.*bypass', 'UEFI/SecureBoot 绕过'),
            ],
            'raw_write': [
                (r'ZwWriteFile.*PhysicalDrive|NtWriteFile.*PhysicalDrive', 'NT API 写入物理磁盘'),
                (r'raw.*write|direct.*write.*disk', '磁盘直接写入'),
                (r'FSCTL_LOCK_VOLUME|FSCTL_DISMOUNT_VOLUME', '卷锁定/卸载（写前准备）'),
            ],
        }

        for category, pats in patterns.items():
            for pattern, desc in pats:
                if re.search(pattern, all_text):
                    indicators[category].append(desc)

        total = sum(len(v) for v in indicators.values())
        if total > 0:
            logger.warning(f"[DiskForensics] 磁盘破坏指示器: {total} 项")
            if indicators['mbr_access']:
                logger.warning(f"  MBR访问: {indicators['mbr_access']}")
            if indicators['raw_write']:
                logger.warning(f"  直接写入: {indicators['raw_write']}")

        return indicators

    @staticmethod
    def check_volume_shadow_copy() -> Dict:
        """检测卷影副本是否被删除（勒索软件常见行为）"""
        result = {
            'vssadmin_present': False,
            'shadow_copies_exist': True,
            'commands_found': [],
        }
        try:
            import subprocess
            proc = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True, text=True, timeout=5, errors='ignore'
            )
            if proc.returncode == 0 and 'No items found' in proc.stdout:
                result['shadow_copies_exist'] = False
                result['commands_found'].append('卷影副本已全部删除')
            result['vssadmin_present'] = True
        except FileNotFoundError:
            result['vssadmin_present'] = False
        except Exception:
            pass
        return result
