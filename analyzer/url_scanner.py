#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL 扫描引擎 — 网页源码分析 / 挂马检测 / 命令执行(WebShell)检测
功能:
  1. 抓取目标网页 (跟随重定向, 忽略证书错误, 大小上限)
  2. 网页代码静态分析:
     - WebShell / 命令执行特征 (PHP eval/system/shell_exec, JSP getRuntime, ASP wscript.shell ...)
     - 挂马特征 (隐藏 iframe, document.write 注入, 页面篡改标记, 跳转)
     - 恶意脚本 (eval 链, String.fromCharCode/unescape 混淆, 打包器, base64 载荷, mshta/powershell)
     - 免杀下载 (exe/scr/data: URI, certutil/bitsadmin 等 LOLBin 命令)
     - 钓鱼 (登录表单, 可疑 TLD, punycode, 伪装域名)
  3. 抓取页面引用的外部 JS 脚本并逐一分析
  4. 本地 IoC 情报命中 (复用 ThreatIntelEngine)
  5. 风险评分与结论
"""
import os
import re
import time
import socket
import ssl
import hashlib
import ipaddress
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlparse, urljoin

from logger import get_logger
from config import CONFIG
from analyzer.models import URLScanResult

logger = get_logger('analyzer.url_scanner')

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class URLScanner:
    """URL 挂马 / 命令执行扫描器"""

    # 常见 WebShell 文件名特征
    WEBSHELL_NAME_PATTERNS = [
        r'(?i)(?:shell|webshell|cmd|c99|r57|b374k|wso|kaixin|hack|eval|phpspy|cgi|bypass|safe|xise|cutekit|updo|jspmap|ma)\d*\.(?:php|asp|aspx|jsp|jspx|cgi)',
        r'(?i)(?:index|info|test|upload|img)\.(?:php|jsp|asp)',
    ]
    # PHP 命令执行/敏感函数
    PHP_EXEC_FUNCS = [
        'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru', 'popen',
        'proc_open', 'pcntl_exec', 'create_function', 'preg_replace',
        'call_user_func', 'call_user_func_array', 'array_map', 'usort', 'assert',
        'include', 'include_once', 'require', 'require_once',
        'curl_exec', 'file_get_contents', 'readfile', 'fopen', 'unlink',
        'chmod', 'file_put_contents', 'fwrite', 'move_uploaded_file', 'rename',
        'chdir', 'putenv', 'mail', 'proc_close', 'exec_command',
    ]
    # 编码/混淆函数 (WebShell 常用)
    ENCODE_FUNCS = [
        'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13',
        'pack("h*"', "pack('h*'", 'pack("H*"', "pack('H*'", 'hex2bin', 'bin2hex',
        'unserialize', 'gzdeflate', 'rawurldecode', 'urldecode',
    ]
    # JSP / ASP / ASPX 命令执行
    JSP_EXEC_PATTERNS = [
        r'Runtime\.getRuntime\(\)\.exec',
        r'ProcessBuilder',
        r'getRuntime\(\).*exec\s*\(',
        r'java\.lang\.Runtime',
        r'javax\.script',
        r'new\s+FileOutputStream',
    ]
    ASP_EXEC_PATTERNS = [
        r'(?i)CreateObject\s*\(\s*["\']WScript\.Shell["\']\s*\)',
        r'(?i)CreateObject\s*\(\s*["\']Shell\.Application["\']\s*\)',
        r'(?i)\.Run\s*\(\s*["\']cmd',
        r'(?i)Shell\s*\(\s*["\']cmd',
        r'(?i)%execute',
        r'(?i)Process\.Start',
        r'(?i)System\.Diagnostics\.Process',
    ]
    # 挂马: 隐藏/注入 iframe
    IFRAME_HIDDEN_PATTERNS = [
        r'(?is)<iframe[^>]*?(?:width|height)\s*=\s*["\']?\s*0\s*["\']?',
        r'(?is)<iframe[^>]*?(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)',
        r'(?is)<iframe[^>]*?position\s*:\s*absolute',
        r'(?is)<iframe[^>]*?(?:top|left)\s*:\s*-?\d+',
    ]
    # JS 创建 iframe (挂马常见手法)
    JS_IFRAME_PATTERNS = [
        r'(?i)document\.write\s*\(\s*["\'][^"\']*iframe',
        r'(?i)createElement\s*\(\s*["\']iframe["\']',
        r'(?i)innerHTML\s*=\s*["\'][^"\']*<iframe',
        r'(?is)document\.write\s*\(\s*unescape\s*\([^)]{0,200}iframe',
        r'(?i)setAttribute\s*\(\s*["\'](?:width|height)["\']\s*,\s*["\']?0["\']?\s*\)',
    ]
    # 跳转/篡改
    REDIRECT_PATTERNS = [
        r'(?is)<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=',
        r'(?i)(?:window|document|self|top)\.location(?:\s*=\s*|\.(?:href|replace|assign)\s*\(\s*["\'])',
        r'(?i)location\.href\s*=',
        r'(?i)document\.location\s*=',
        r'(?i)setTimeout\s*\(\s*["\'][^"\']*(?:location|window\.open)',
    ]
    # 脚本混淆
    OBFUSCATION_PATTERNS = [
        (r'(?i)eval\s*\(\s*unescape\s*\(', 'eval(unescape()) 混淆'),
        (r'(?i)eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)', 'Dean Edwards 打包器 (packer)'),
        (r'(?i)String\.fromCharCode\s*\(\s*[^)]{100,}', '超长 fromCharCode 链 (字符编码载荷)'),
        (r'(?is)(?:eval|Function)\s*\(\s*[^)]{0,80}\b(?:atob|base64_decode|btoa)\b', 'eval(base64) 载荷'),
        (r'(?i)\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}', r'大量 \xNN 十六进制转义'),
        (r'(?i)(?:eval|Function)\s*\(\s*["\'][^"\']{100,}', '超长 eval 字符串'),
        (r'(?i)(?:_0x|0x)[0-9a-f]{4,6}\s*(?:=|\[)', '混淆变量名 (_0x 前缀)'),
        (r'(?i)\beval\s*\([^)]*charCodeAt\s*\(', 'charCodeAt 编码解码'),
        (r'(?i)\batob\s*\(\s*["\'][A-Za-z0-9+/=]{50,}', '内嵌 base64 数据块'),
        (r'(?is)unescape\s*\(\s*["\'][^"\']{80,}', '长 unescape 字符串'),
        (r'(?i)String\.fromCharCode\s*\(\s*\d+\s*\)\s*\.replace', 'fromCharCode 替换编码'),
        (r'(?i)\bconcat\s*\(\s*String\.fromCharCode', 'fromCharCode concat 链'),
    ]
    # 免杀下载 / LOLBin 载荷
    DRIVEBY_PATTERNS = [
        r'(?i)mshta\s+["\']?(?:javascript:|vbscript:|file:)',
        r'(?i)mshta\.exe',
        r'(?i)powershell\s+(?:-enc|-e|\.-encodedcommand)',
        r'(?i)powershell\s+[^"\']{20,}(?:downloadstring|iwr|invoke-webrequest|wget|frombase64string)',
        r'(?i)certutil\s+-\s*urlcache',
        r'(?i)certutil\s+-\s*decode',
        r'(?i)bitsadmin\s+/transfer',
        r'(?i)regsvr32\s+/s\s+/i:?http',
        r'(?i)rundll32\.exe\s+\S+,\s*(?:url\.dll|jsproxy)',
        r'(?i)wscript\.shell\s*[.\s]run',
        r'(?i)new\s+ActiveXObject\s*\(\s*["\']WScript\.Shell["\']',
        r'(?i)cmd\s*\.?\s*/\s*c\s+start',
        r'(?i)data\s*:\s*text/html\s*;?\s*base64',
        # 下载型链接: href/src 指向可执行/压缩文件 (需扩展名在 URL 结尾; .js/.com 不算 — 域名 TLD 和正常脚本引用)
        r'(?i)(?:href|src)\s*=\s*["\'][^"\'>]*\.(?:exe|scr|pif|bat|cmd|msi|vbs|vbe|hta|jar|dll|zip|rar)(?:["\']|$)',
        r'(?i)\b(?:exploit|payload|shellcode)\b|(?:^|[^a-z])\bbeacon\b',
        r'(?i)CVE-\d{4}-\d{4,}',
        # 2024-2026 新 LOLBin / 投放手法
        r'(?i)\bfinger\s+[\w.@-]{3,}',                      # finger 命令数据外传 (Kongtuke)
        r'(?i)wmic\s+process\s+call\s+create',              # WMIC 远程执行
        r'(?i)schtasks\s+/(?:create|run)',                  # 计划任务持久化
        r'(?i)forfiles\s+/p\s+/c',                          # forfiles 命令执行
        r'(?i)msedge\.exe\s+--headless|msiexec\.exe\s+/i\s+https?:',  # 无头浏览器/远程 MSI
        r'(?i)\?track=\w{3,}["\'\s&)]',                     # NetSupport/StealC 载荷下载参数
        r'(?i)(?:chrome|edge|firefox)[\s_-]*(?:setup|update|installer)[\s_\-.0-9]*\.(?:js|exe|msi)',  # 假浏览器更新载荷
        r'(?i)(?:wscript|cscript)\.exe\s+["\']?[a-z]:\\',   # 本地脚本执行
        r'(?i)start\s+(?:""|cmd)\s*/d\s*\w:\\\\',           # 隐蔽启动
        r'(?i)download\s+https?://\S+\s+\$env:temp',         # PowerShell 下载执行
        r'(?i)iex\s*\(\s*(?:new-object|iwr|invoke-webrequest)',  # PS IEX 远程脚本
    ]
    # 钓鱼
    PHISHING_PATTERNS = [
        r'(?i)<form[^>]*?(?:login|signin|sign-in|logon|auth|password|passwd|verify|secure)',
        r'(?i)<input[^>]*type\s*=\s*["\']password["\']',
        r'(?i)(?:account|confirm|bank|paypal|ebay|apple|microsoft|outlook|office365|icbc|工行|中国银行|淘宝|支付宝|微信|qq安全中心)',
        r'(?i)xn--',
        r'(?i)(?:verify|secure|update|confirm|unlock)\s*[-_]?\s*(?:account|login|signin|identity|payment)',
        r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}',
    ]
    # ClickFix 假验证码 / 假浏览器更新 (2024-2026 主流挂马投放: Kongtuke/SmartApeSG/socGholish/ClearFake)
    CLICKFIX_PATTERNS = [
        (r'(?i)verify\s+you\s+are\s+(?:a\s+)?(?:human|not\s+a\s+robot|real)', '假验证码文本 (verify you are a human)'),
        (r'(?i)(?:i[\'’]m\s+not\s+a\s+robot|im\s+not\s+a\s+robot|not\s+a\s+robot)', '假 reCAPTCHA 文本'),
        (r'(?i)(?:click|press|copy).{0,40}(?:verify|verify\s+you\s+are)', '引导点击/复制验证 (ClickFix 引导)'),
        (r'(?i)(?:win\s*\+\s*r|windows\s+key\s*\+\s*r|run\s+dialog|press\s+win)', '诱导打开 Win+R 运行对话框 (ClickFix)'),
        (r'(?i)(?:paste|copy)\s+(?:the\s+)?(?:command|code|script)', '诱导复制命令 (ClickFix)'),
        (r'(?i)navigator\.clipboard\.writeText\s*\(', '剪贴板写入命令 (ClickFix 载荷传递)'),
        (r'(?i)document\.execCommand\s*\(\s*["\']copy["\']', 'execCommand 复制 (剪贴板劫持/ClickFix)'),
        (r'(?i)(?:oncopy|onpaste|oncut|onmousedown|onmouseup|onclick)\s*=\s*[^>]{0,60}(?:execCommand|clipboard|copy|mshta|powershell)', '事件劫持剪贴板/执行'),
        (r'(?i)__cf_chl|captcha\.js|cf-turnstile|hcaptcha[^"]*\.js', '伪装 Cloudflare/hCaptcha 组件'),
    ]
    FAKE_UPDATE_PATTERNS = [
        (r'(?i)(?:update|install)\s+(?:your\s+)?(?:google\s+)?chrome', '假浏览器更新 (Chrome)'),
        (r'(?i)(?:update|install)\s+(?:your\s+)?(?:microsoft\s+)?edge', '假浏览器更新 (Edge)'),
        (r'(?i)(?:update|install)\s+(?:your\s+)?firefox', '假浏览器更新 (Firefox)'),
        (r'(?i)your\s+(?:browser|chrome|edge|firefox)\s+is\s+(?:out\s+of\s+date|not\s+supported|obsolete)', '浏览器过期提示 (假更新投放)'),
        (r'(?i)(?:chrome|edge|firefox)[\s_-]*(?:setup|installer|update)[\s_\-.0-9]*\.(?:exe|msi|js|zip)', '伪安装包下载 (假更新)'),
        (r'(?i)(?:browser[\s_-]*update|chrome[\s_-]*update|edge[\s_-]*update)\s*\.js', '伪更新 JS 脚本'),
    ]
    # 剪贴板劫持 (加密货币地址替换) / 键盘记录
    CLIPBOARD_HIJACK_PATTERNS = [
        (r'(?i)(?:navigator\.clipboard\.writeText|document\.execCommand\s*\(\s*["\']copy["\'])\s*\(?\s*["\']?[A-Za-z1-9]{26,44}', '剪贴板写入长字符串 (地址替换/命令注入)'),
        (r'(?i)(?:btc|bitcoin|eth|ethereum|usdt|trx|trc20|erc20|wallet|address)[\s\S]{0,80}(?:writeText|execCommand\s*\(\s*["\']copy)', '加密货币地址劫持'),
        (r'(?i)(?:document|window)\.addEventListener\s*\(\s*["\'](?:keydown|keyup|keypress|input)["\']', '键盘记录器 (keydown/keypress 监听)'),
        (r'(?i)addEventListener\s*\(\s*["\'](?:copy|paste|cut|select)["\']\s*,\s*function\s*\(', '复制/粘贴事件劫持'),
    ]
    # Magecart / 表单数据窃取
    MAGECART_PATTERNS = [
        (r'(?i)querySelector\s*\(\s*["\'][^"\']*(?:card|cc|cardnumber|cvv|expiry|pan|card-data)', '窃取信用卡字段 (Magecart)'),
        (r'(?i)(?:name|id)\s*=\s*["\'][^"\']*(?:card_number|cardnumber|card-cvv|cvv2|card-exp|expiry|ccnum|cc-number)', '信用卡表单字段'),
        (r'(?i)(?:getElementsByName|querySelectorAll)\s*\(\s*["\'][^"\']*(?:card|cc|pay|checkout)', '枚举支付字段 (Magecart)'),
        (r'(?i)(?:fetch|XMLHttpRequest|sendBeacon)\s*\([^)]{0,120}?(?:card|cvv|ccn|pay|checkout)[^)]{0,40}', '支付数据外传'),
        (r'(?is)addEventListener\s*\(\s*["\']submit["\'].{0,300}?(?:fetch|XMLHttpRequest|sendBeacon)', '拦截表单提交并外传'),
    ]
    # 挖矿脚本 (Coinhive 后继: CoinImp/WebLocker/wasm 挖矿)
    CRYPTOMINER_PATTERNS = [
        (r'(?i)\b(?:coinhive|coinimp|authedmine|cryptonight|webminerpool|minecore|webwoker)\b', '挖矿服务商标识'),
        (r'(?i)\bminer\.(?:start|init|setThrottle)\b', '挖矿启动 API (miner.start)'),
        (r'(?i)(?:Monero|XMR|XMRig|cryptonight|randomx|RandomX)\.?\w{0,20}', '门罗币挖矿特征'),
        (r'(?i)(?:wasm|wasm\.js|wasm-web)\S{0,30}\.wasm\b', 'WebAssembly 挖矿模块'),
        (r'(?i)(?:site-key|siteKey|throttle|autoThreads|forceASMJS)\s*[=:]\s*["\'][^"\']{10,}', '挖矿配置参数'),
    ]
    # WebSocket 外联 C2 / 服务持久化 / 数据外泄
    WEBSOCKET_C2_PATTERNS = [
        r'(?i)new\s+WebSocket\s*\(\s*["\']ws(?:s)?://',
        r'(?i)WebSocket\s*\(\s*["\'](?:wss?://)?(?:[a-z0-9.-]+\.)?(?:top|xyz|tk|ml|ga|cf|gq|ru|cn)\s*[/"\']',
    ]
    PERSISTENCE_PATTERNS = [
        (r'(?i)navigator\.serviceWorker\.register\s*\(', 'Service Worker 注册 (持久化)'),
        (r'(?i)(?:window|document)\.onbeforeunload\s*=.*(?:sendBeacon|fetch|XMLHttpRequest)', '页面关闭时外泄数据'),
        (r'(?i)navigator\.sendBeacon\s*\(\s*["\'](?!https?://(?:self|same|current|document\.location))', 'sendBeacon 数据外泄'),
    ]
    # SSTI / 模板注入探测
    SSTI_PATTERNS = [
        (r'\{\{\s*(?:7\s*\*?\s*7|7\*7|config|self|request|app|cycler|joiner)\s*[}|}]', 'SSTI 探测 ({{7*7}}/config)'),
        (r'(?i)\$\{\s*(?:7\s*\*?\s*7|jndi|env|sys|class|runtime)', 'SSTI/表达式注入 (${7*7}/jndi)'),
        (r'(?i)#\{\s*(?:7\s*\*?\s*7|request|bean)', 'SSTI 探测 (#{...})'),
        (r'(?i)<%\s*(?:=|\s*)[^>]{0,80}(?:Runtime|Process|exec|cmd)\b', 'JSP 模板注入特征'),
    ]
    # PHP 8 新特性后门 / 花式调用
    PHP8_WEBSHELL_PATTERNS = [
        (r'(?i)(?:new\s+class|class\s*\{[^}]{0,200}?function\s+__construct)', 'PHP8 匿名类后门 (构造器执行)'),
        (r'(?i)ReflectionFunction\s*\(\s*["\'](?:system|exec|shell_exec|passthru|eval|assert)', 'ReflectionFunction 动态调用命令函数'),
        (r'(?i)Closure\s*::\s*fromCallable\s*\(\s*["\'](?:system|exec|shell_exec|passthru|eval)', 'Closure::fromCallable 命令执行'),
        (r'(?is)\[\s*["\'](?:system|exec|shell_exec|passthru|pcntl_exec)["\']\s*\]\s*\(', 'PHP8 first-class callable 数组调用'),
        (r'(?i)array_filter\s*\(\s*\$_(?:POST|GET|REQUEST)', 'array_filter($_POST) 命令执行后门'),
        (r'(?i)array_map\s*\(\s*["\'](?:system|exec|shell_exec|passthru|eval|assert)', 'array_map 命令执行后门'),
        (r'(?i)usort\s*\(\s*\$_(?:POST|GET|REQUEST)', 'usort($_POST) 命令执行后门'),
        (r'(?i)mb_ereg_replace\s*\(\s*["\'][^"\']*["\']\s*,\s*["\'][^"\']*(?:system|exec|shell_exec)', 'mb_ereg_replace 命令执行'),
        (r'(?i)extract\s*\(\s*\$_(?:POST|GET|REQUEST|FILES)', 'extract 变量覆盖后门'),
        (r'(?i)(?:preg_replace_callback|array_walk|array_walk_recursive|register_shutdown_function|register_tick_function|set_error_handler|set_exception_handler)\s*\(\s*["\']?(?:system|exec|shell_exec|passthru|eval|assert)', '回调函数命令执行'),
        (r'(?i)file_put_contents\s*\(\s*[^,]{1,60},\s*base64_decode\s*\(', 'base64 解码写文件后门'),
        (r'(?i)include\s*\(\s*\$_(?:FILES|POST|GET|REQUEST)\[', '文件包含后门 (include $_FILES)'),
        (r'(?i)move_uploaded_file\s*\(\s*\$_(?:FILES|POST)', '上传即执行后门'),
        (r'(?i)\b(?:assert|eval)\s*\(\s*(?:str_rot13|base64_decode|gzinflate|gzuncompress)\s*\(', 'eval(编码) 变体'),
    ]
    # 命令输出泄漏 (WebShell 页面/被黑页面特征)
    COMMAND_OUTPUT_PATTERNS = [
        (r'(?im)^\s*uid=\d+\([\w.-]+\)\s*gid=', '命令输出: uid=... gid=... (whoami/id)'),
        (r'(?i)nt\s+authority\\system|nt\s+authority\\network\s+service|secretsdump', '命令输出: Windows 权限'),
        (r'(?i)^\s*root:x:0:0:', '命令输出: /etc/passwd 内容'),
        (r'(?i)linux\s+\w+\s+\d+\.\d+\.\d+.*\d{4}.*(?:x86_64|amd64|i686)', '命令输出: uname -a'),
        (r'(?i)windows\s+ip\s+configuration|ethernet\s+adapter|ipv4\s+address', '命令输出: ipconfig'),
        (r'(?i)total\s+\d+\s+drwx|drwxr-xr-x\s+\d+\s+root', '命令输出: ls -la'),
        (r'(?i)<pre[^>]*>[\s\S]{0,200}(?:uid=|root:x:|drwxr)', '命令输出被渲染到页面'),
        (r'(?i)(?:command|命令)\s*[:\s]*(?:executed|执行|output|输出|result|结果)', '命令执行结果页面'),
    ]
    # 可疑 TLD
    SUSPICIOUS_TLDS = ('.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.icu',
                       '.bid', '.loan', '.click', '.link', '.download', '.stream',
                       '.review', '.work', '.country', '.science', '.party', '.date')
    # 敏感路径 (探测)
    SENSITIVE_PATHS = ['phpmyadmin', 'admin', 'login.php', 'wp-login.php', 'manager',
                       'shell', 'cmd', 'upload', 'phpinfo.php', 'info.php', 'test.php']

    def __init__(self, timeout: int = None, fetch_external_scripts: bool = None,
                 max_external_scripts: int = None):
        cfg = CONFIG.url_scan if CONFIG.url_scan else None
        self.timeout = timeout or getattr(cfg, 'timeout', 15)
        self.fetch_external = fetch_external_scripts if fetch_external_scripts is not None \
            else getattr(cfg, 'fetch_external_scripts', True)
        self.max_external = max_external_scripts or getattr(cfg, 'max_external_scripts', 5)
        self.max_body = getattr(cfg, 'max_body_size', 2 * 1024 * 1024)
        self.verify = not getattr(cfg, 'ignore_https_errors', True)
        self.ua = getattr(cfg, 'user_agent', 'Mozilla/5.0')

    # ================= 网络获取 =================

    def _make_session(self):
        session = None
        if REQUESTS_AVAILABLE:
            try:
                session = requests.Session()
                session.verify = self.verify
                session.headers.update({
                    'User-Agent': self.ua,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                })
            except Exception:
                session = None
        return session

    def _fetch(self, session, url: str, timeout: int = None) -> Dict:
        """抓取 URL 内容, 返回 {ok, status, reason, headers, url(final), history, body, error}

        手动跟随重定向并逐跳做 SSRF 校验 (requests 自动 redirect 会绕过校验)。
        """
        t = timeout or self.timeout
        if session is not None:
            current = url
            history = []
            try:
                for _hop in range(5):
                    self._assert_public_url(current)
                    resp = session.get(current, timeout=t, allow_redirects=False,
                                       stream=True)
                    if resp.is_redirect and resp.headers.get('location'):
                        current = urljoin(current, resp.headers['location'])
                        history.append(current)
                        resp.close()
                        continue
                    chunks = []
                    total = 0
                    for chunk in resp.iter_content(65536):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > self.max_body:
                            chunks.append(b'\n[TRUNCATED]')
                            break
                    body = b''.join(chunks)
                    final_url = resp.url
                    history = (history or []) + ([final_url] if final_url != url else [])
                    return {
                        'ok': True, 'status': resp.status_code, 'reason': resp.reason or '',
                        'headers': dict(resp.headers), 'url': final_url, 'history': history,
                        'body': body,
                    }
            except Exception as e:
                return {'ok': False, 'status': 0, 'reason': '', 'headers': {},
                        'url': url, 'history': history or [url], 'body': b'',
                        'error': str(e)[:300]}
        # urllib 降级
        try:
            self._assert_public_url(url)
            req = __import__('urllib.request', fromlist=['Request'])
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            opener = req.build_opener(req.HTTPSHandler(context=ctx))
            r = opener.open(url, timeout=t)
            body = r.read(self.max_body + 1)
            truncated = len(body) > self.max_body
            body = body[:self.max_body]
            headers = {k: v for k, v in r.headers.items()}
            return {'ok': True, 'status': r.status, 'reason': r.reason or '',
                    'headers': headers, 'url': r.url, 'history': [r.url],
                    'body': body, 'truncated': truncated}
        except Exception as e:
            return {'ok': False, 'status': 0, 'reason': '', 'headers': {},
                    'url': url, 'history': [url], 'body': b'', 'error': str(e)[:300]}

    @staticmethod
    def _decode(body: bytes) -> str:
        """尽力解码网页正文"""
        if not body:
            return ''
        for enc in ('utf-8', 'gb18030', 'gbk', 'big5', 'latin-1'):
            try:
                return body.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return body.decode('utf-8', errors='replace')

    @staticmethod
    def _extract_ip(url: str) -> str:
        m = re.search(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
        return m.group(1) if m else ''

    @staticmethod
    def _extract_domain(url: str) -> str:
        m = re.search(r'https?://([^/:\s]+)', url)
        return (m.group(1).lower().rstrip('.')) if m else ''

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            return urlparse(url).netloc.lower()
        except Exception:
            return url

    @staticmethod
    def _assert_public_url(url: str) -> None:
        """SSRF 防线: 只允许访问公网地址, 拦截回环/内网/链路本地/云元数据。"""
        host = urlparse(url).hostname
        if not host:
            raise ValueError(f'无法解析主机名: {url}')
        infos = socket.getaddrinfo(host, None)
        if not infos:
            raise ValueError(f'域名无法解析: {host}')
        for info in infos:
            ip = info[4][0]
            try:
                if not ipaddress.ip_address(ip).is_global:
                    raise ValueError(f'SSRF blocked: {host} -> {ip}')
            except ValueError as e:
                if 'SSRF blocked' in str(e):
                    raise
                continue

    # ================= 检测规则 =================

    def _detect_webshell(self, url: str, path: str, html: str) -> List[Dict]:
        """命令执行 / WebShell 检测"""
        finds = []
        low_url = url.lower()
        # ⚠ index.php/info.php/test.php 这类文件名不能单独定罪 (正常 PHP 站几乎都有),
        # 文件名只作为辅助上下文, 必须与命令执行/木马代码证据同现。
        # PHP
        is_php = bool(re.search(r'(?i)\.(?:php|phtml|php\d)(?:[?#]|$)', url)) or \
                 bool(re.search(r'(?is)<\?php|phpinfo\s*\(', html)) or \
                 bool(re.search(r'(?i)\$_POST|\$_GET|\$_REQUEST|\$_COOKIE', html))
        if is_php:
            if re.search(r'(?i)\bphpinfo\s*\(\s*\)', html):
                finds.append({'severity': 'medium', 'type': 'phpinfo',
                              'evidence': 'phpinfo() 信息泄露函数', 'line': 0})
            # eval 系
            for func in ('eval', 'assert'):
                for m in re.finditer(r'(?i)\b' + func + r'\s*\(\s*\$_[GPRC]', html):
                    finds.append({'severity': 'critical', 'type': 'php_webshell',
                                  'evidence': f'{func}($_GET/$_POST/$_REQUEST) 直接执行用户输入 — 典型一句话木马',
                                  'line': html.count('\n', 0, m.start()) + 1})
            # eval/assert 已在上面用 $_ 超全局变量判定; 此处仅抓命令执行类函数
            for func in ('system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
                         'pcntl_exec', 'create_function'):
                for m in re.finditer(r'(?i)\b' + func + r'\s*\(', html):
                    line = html.count('\n', 0, m.start()) + 1
                    ctx = html[max(0, m.start() - 60): m.end() + 120]
                    ctx = re.sub(r'\s+', ' ', ctx).strip()
                    finds.append({'severity': 'high' if func in ('system', 'exec', 'shell_exec', 'passthru', 'popen') else 'critical',
                                  'type': 'php_command_exec',
                                  'evidence': f'{func}() 命令执行函数: {ctx[:160]}', 'line': line})
            for func in self.ENCODE_FUNCS:
                for m in re.finditer(r'(?i)\b' + re.escape(func) + r'\s*\(', html):
                    if 'base64_decode' in func.lower() and '$_' in html[max(0, m.start()-40):m.end()+40]:
                        finds.append({'severity': 'high', 'type': 'php_obfuscated_shell',
                                      'evidence': f'{func}() + 超全局变量 ($_GET/$_POST) 组合', 'line': 0})
                    elif func in ('base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13') and \
                            re.search(r'(?is)(?:eval|assert|system|exec)\s*\([^)]{0,60}' + re.escape(func), html):
                        finds.append({'severity': 'high', 'type': 'php_obfuscated_shell',
                                      'evidence': f'eval( {func}() ) 解码后执行 — 混淆木马', 'line': 0})
            # 后门参数
            for m in re.finditer(r'(?i)\b(?:cmd|command|exec|run|execute|shell|body|action)\s*=\s*\$_(?:GET|POST|REQUEST)\[', html):
                finds.append({'severity': 'high', 'type': 'php_backdoor_param',
                              'evidence': f'命令参数后门: {m.group(0)[:80]}', 'line': 0})
        # JSP
        if re.search(r'(?i)\.jsp[?#]?$', url) or 'jsp' in html.lower()[:1000]:
            for pat in self.JSP_EXEC_PATTERNS:
                for m in re.finditer(pat, html):
                    finds.append({'severity': 'critical', 'type': 'jsp_webshell',
                                  'evidence': f'JSP 命令执行: {m.group(0)[:80]}', 'line': 0})
        # ASP
        if re.search(r'(?i)\.(?:asp|aspx)[?#]?$', url):
            for pat in self.ASP_EXEC_PATTERNS:
                for m in re.finditer(pat, html):
                    finds.append({'severity': 'critical', 'type': 'asp_webshell',
                                  'evidence': f'ASP 命令执行: {m.group(0)[:80]}', 'line': 0})
        # 通用: 危险文件操作
        for m in re.finditer(r'(?i)\b(?:file_put_contents|fwrite|move_uploaded_file|unlink|chmod)\s*\(', html):
            finds.append({'severity': 'medium', 'type': 'php_file_ops',
                          'evidence': f'危险文件操作: {m.group(0)[:60]}', 'line': 0})
        # 去重
        return self._dedup(finds)

    def _detect_hijack(self, html: str, base_url: str, domain: str) -> List[Dict]:
        """挂马: iframe 注入 / 隐藏加载 / 页面篡改"""
        finds = []
        # 隐藏 iframe
        for pat, desc in [(p, '隐藏 iframe (0 尺寸/隐藏样式)') for p in self.IFRAME_HIDDEN_PATTERNS]:
            for m in re.finditer(pat, html):
                snippet = html[max(0, m.start() - 20): m.end() + 200]
                src = re.search(r'(?i)src\s*=\s*["\']?([^"\'>\s]+)', snippet)
                target = src.group(1) if src else '(内联)'
                full = target if target.startswith('http') else urljoin(base_url, target) if target.startswith('//') else urljoin(base_url, target)
                # 同一域名的 iframe 低关注
                t_host = self._host_of(full)
                sev = 'medium' if t_host == domain or not target else 'high'
                finds.append({'severity': sev, 'type': 'hidden_iframe',
                              'evidence': f'{desc} → {target}', 'line': html.count('\n', 0, m.start()) + 1})
        # document.write iframe
        for pat, desc in [(p, d) for p, d in
                          zip(self.JS_IFRAME_PATTERNS, ['document.write 注入 iframe', 'createElement iframe',
                                                        'innerHTML iframe 注入', 'document.write(unescape) iframe',
                                                        '动态隐藏尺寸 iframe'])]:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'high', 'type': 'js_iframe_injection',
                              'evidence': f'{desc}: {m.group(0)[:100]}', 'line': html.count('\n', 0, m.start()) + 1})
        # 页面篡改: </head> 后插入 / </body> 后插入 script
        for m in re.finditer(r'(?is)</(?:head|body|html)\s*>\s*<\s*script', html):
            finds.append({'severity': 'high', 'type': 'page_tamper',
                          'evidence': '页面尾部/头部被注入 <script> — 挂马篡改特征',
                          'line': html.count('\n', 0, m.start()) + 1})
        # object/embed/ActiveX
        for m in re.finditer(r'(?is)<(?:object|embed|applet)[^>]*(?:clsid|data|src)\s*=', html):
            finds.append({'severity': 'high', 'type': 'activex_object',
                          'evidence': f'嵌入 OLE/ActiveX 对象: {re.sub(r"\\s+", " ", m.group(0))[:120]}',
                          'line': html.count('\n', 0, m.start()) + 1})
        # 跳转 (全页重定向到外部)
        for pat, desc in [(p, d) for p, d in zip(
            self.REDIRECT_PATTERNS,
            ['meta refresh 跳转', 'location 跳转', 'location.href 跳转', 'document.location 跳转', '定时跳转'])]:
            for m in re.finditer(pat, html):
                ctx = html[max(0, m.start() - 30): m.end() + 160]
                mm = re.search(r'(?:url\s*=\s*|href\s*=|location\s*=|\.href\s*=\s*|\()\s*["\']?([^"\'>\s]+)', ctx, re.I)
                target = mm.group(1) if mm else ''
                if target:
                    t_host = self._host_of(target)
                    if t_host and t_host != domain and t_host not in ('self', 'top', 'window', 'document'):
                        finds.append({'severity': 'high', 'type': 'external_redirect',
                                      'evidence': f'{desc} → 外部地址 {target}', 'line': html.count('\n', 0, m.start()) + 1})
        return self._dedup(finds)

    def _detect_obfuscation(self, html: str) -> List[Dict]:
        finds = []
        for pat, desc in self.OBFUSCATION_PATTERNS:
            for m in re.finditer(pat, html):
                line = html.count('\n', 0, m.start()) + 1
                ctx = re.sub(r'\s+', ' ', html[max(0, m.start() - 40): m.end() + 160]).strip()
                finds.append({'severity': 'high' if 'eval' in desc.lower() or 'packer' in desc.lower() else 'medium',
                              'type': 'js_obfuscation',
                              'evidence': f'{desc}: {ctx[:180]}', 'line': line})
        return self._dedup(finds)

    def _detect_driveby(self, html: str) -> List[Dict]:
        finds = []
        descs = ['mshta 载荷', 'mshta.exe', 'powershell -enc', 'powershell 下载执行',
                 'certutil urlcache', 'certutil decode', 'bitsadmin transfer',
                 'regsvr32 scrobj', 'rundll32 url.dll', 'wscript.shell run',
                 'ActiveX WScript.Shell', 'cmd /c start', 'data: URI', '可执行文件链接',
                 'exploit/payload/shellcode 关键词', 'CVE 编号',
                 'finger 命令数据外传', 'WMIC 远程执行', '计划任务持久化', 'forfiles 命令执行',
                 '无头浏览器/远程 MSI', 'NetSupport/StealC 载荷下载参数', '假浏览器更新载荷',
                 'wscript/cscript 本地脚本', '隐蔽启动', 'PowerShell 下载执行', 'PS IEX 远程脚本']
        for pat, desc in [(p, d) for p, d in zip(self.DRIVEBY_PATTERNS, descs)]:
            for m in re.finditer(pat, html):
                critical_types = ('mshta 载荷', 'powershell -enc', 'ActiveX WScript.Shell',
                                  'data: URI', 'finger 命令数据外传', 'NetSupport/StealC 载荷下载参数')
                finds.append({'severity': 'critical' if desc in critical_types else (
                    'low' if desc == '可执行文件链接' else 'high'),
                              'type': 'drive_by_download',
                              'evidence': f'{desc}: {m.group(0)[:120]}', 'line': html.count('\n', 0, m.start()) + 1})
        return self._dedup(finds)

    def _detect_clickfix(self, html: str) -> List[Dict]:
        """ClickFix 假验证码 / 假浏览器更新 / 剪贴板劫持 (2024-2026 主流投放)"""
        finds = []
        for pat, desc in self.CLICKFIX_PATTERNS:
            for m in re.finditer(pat, html):
                ctx = re.sub(r'\s+', ' ', html[max(0, m.start() - 40): m.end() + 160]).strip()
                sev = 'critical' if any(k in desc for k in ('剪贴板写入', 'execCommand', '事件劫持')) else 'high'
                finds.append({'severity': sev, 'type': 'clickfix',
                              'evidence': f'{desc}: {ctx[:170]}', 'line': html.count('\n', 0, m.start()) + 1})
                break  # 每模式一条
        for pat, desc in self.FAKE_UPDATE_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'high', 'type': 'fake_update',
                              'evidence': f'{desc}: {m.group(0)[:100]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        signals = []
        if re.search(r'(?i)(?:verify|robot|captcha)', html):
            signals.append('verify')
        if re.search(r'(?i)(?:clipboard|execCommand|copy)', html):
            signals.append('clipboard')
        if re.search(r'(?i)(?:mshta|powershell|rundll32|cmd|wmic|schtasks|finger)', html):
            signals.append('payload')
        if len(signals) >= 3 and not any(f['type'] == 'clickfix' for f in finds):
            finds.append({'severity': 'critical', 'type': 'clickfix_combo',
                          'evidence': f'ClickFix 组合特征: 验证框+剪贴板+载荷命令 ({", ".join(signals)})',
                          'line': 0})
        return self._dedup(finds)

    def _detect_data_theft(self, html: str) -> List[Dict]:
        """Magecart 表单注入 / 键盘记录 / 数据外泄"""
        finds = []
        for pat, desc in self.MAGECART_PATTERNS:
            for m in re.finditer(pat, html):
                # 仅"信用卡表单字段"出现 → 正常电商也有, 判 medium; 配合窃取/外传才是 critical
                sev = 'medium' if '信用卡表单字段' in desc else 'critical'
                finds.append({'severity': sev, 'type': 'magecart',
                              'evidence': f'{desc}: {m.group(0)[:130]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        for pat, desc in self.CLIPBOARD_HIJACK_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'high', 'type': 'keylogger' if '键盘' in desc else 'clipboard_hijack',
                              'evidence': f'{desc}: {m.group(0)[:130]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        for pat, desc in self.PERSISTENCE_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'medium', 'type': 'data_exfil',
                              'evidence': f'{desc}: {m.group(0)[:130]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        return self._dedup(finds)

    def _detect_cryptominer(self, html: str) -> List[Dict]:
        finds = []
        for pat, desc in self.CRYPTOMINER_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'high', 'type': 'crypto_mining',
                              'evidence': f'{desc}: {m.group(0)[:120]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        return self._dedup(finds)

    def _detect_websocket_c2(self, html: str) -> List[Dict]:
        finds = []
        for pat in self.WEBSOCKET_C2_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'high', 'type': 'websocket_c2',
                              'evidence': f'WebSocket 外联: {m.group(0)[:120]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        return finds

    def _detect_php8_webshell(self, html: str) -> List[Dict]:
        finds = []
        for pat, desc in self.PHP8_WEBSHELL_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'critical' if desc not in ('extract 变量覆盖后门',) else 'high',
                              'type': 'php8_webshell',
                              'evidence': f'{desc}: {m.group(0)[:130]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        return self._dedup(finds)

    def _detect_command_output(self, html: str) -> List[Dict]:
        finds = []
        for pat, desc in self.COMMAND_OUTPUT_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'high', 'type': 'command_output',
                              'evidence': f'{desc}: {m.group(0)[:120]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        return self._dedup(finds)

    def _detect_ssti(self, html: str) -> List[Dict]:
        finds = []
        for pat, desc in self.SSTI_PATTERNS:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'medium', 'type': 'ssti_probe',
                              'evidence': f'{desc}: {m.group(0)[:120]}', 'line': html.count('\n', 0, m.start()) + 1})
                break
        return self._dedup(finds)

    def _detect_phishing(self, html: str, url: str, domain: str) -> List[Dict]:
        finds = []
        for pat, desc in [(p, d) for p, d in zip(
            self.PHISHING_PATTERNS,
            ['登录/认证表单', '密码输入框', '金融/品牌关键词', 'punycode 域名', '账户验证类 URL 关键词', '硬编码密码'])]:
            for m in re.finditer(pat, html):
                finds.append({'severity': 'medium', 'type': 'phishing',
                              'evidence': f'{desc}: {re.sub(r"\\s+", " ", m.group(0))[:120]}',
                              'line': html.count('\n', 0, m.start()) + 1})
                break  # 每个模式一条
        # 伪装: 域名相似度
        for m in re.finditer(r'(?i)href\s*=\s*["\'](https?://[^"\'>]+)["\']', html):
            link = m.group(1)
            l_host = self._host_of(link)
            if l_host and l_host != domain and any(dom in l_host for dom in
                                                   ('paypal', 'apple', 'microsoft', 'bank', 'ebay', 'outlook', 'office', 'icbc', 'alipay')):
                finds.append({'severity': 'medium', 'type': 'phishing_spoof',
                              'evidence': f'疑似仿冒链接: {link[:120]}', 'line': html.count('\n', 0, m.start()) + 1})
        # @ 伪装
        for m in re.finditer(r'(?i)https?://[^"\'>\s]*@', html):
            finds.append({'severity': 'high', 'type': 'phishing_url_at',
                          'evidence': f'URL 含 @ 伪装: {m.group(0)[:120]}', 'line': 0})
        # 密码表单 + 非https
        if url.lower().startswith('http://') and re.search(r'(?i)<input[^>]*type\s*=\s*["\']?password', html):
            finds.append({'severity': 'high', 'type': 'phishing_insecure',
                          'evidence': 'HTTP 明文传输密码表单', 'line': 0})
        return self._dedup(finds)

    def _collect_external_scripts(self, html: str, base_url: str) -> List[str]:
        """提取页面引用的外部 JS URL"""
        scripts = []
        seen = set()
        for m in re.finditer(r'(?is)<script[^>]*?src\s*=\s*["\']([^"\'>\s]+)["\']', html):
            src = m.group(1)
            if src.lower().startswith('data:'):
                continue
            full = src if src.startswith('http') else urljoin(base_url, src)
            if full.startswith('//'):
                full = 'https:' + full
            if full in seen:
                continue
            seen.add(full)
            scripts.append(full)
        return scripts

    @staticmethod
    def _dedup(finds: List[Dict]) -> List[Dict]:
        """按 evidence 去重, 限制数量"""
        out, seen = [], set()
        for f in finds:
            key = (f.get('type', ''), f.get('evidence', '')[:100])
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out[:60]

    @staticmethod
    def _severity_score(sev: str) -> int:
        return {'critical': 40, 'high': 25, 'medium': 12, 'low': 4}.get(sev, 5)

    # ================= 主入口 =================

    def scan(self, url: str, fetch_external: bool = None, max_external: int = None,
             enable_dynamic: bool = None, browser_engines: list = None,
             stop_event=None) -> URLScanResult:
        """扫描单个 URL
        enable_dynamic: 是否启用浏览器动态行为监控 (默认取配置 url_scan.dynamic_analysis)
        browser_engines: 动态监控使用的浏览器引擎列表 (chrome/msedge/chromium/firefox/webkit)
        """
        start = time.time()
        fetch_external = self.fetch_external if fetch_external is None else fetch_external
        max_external = self.max_external if max_external is None else max_external
        if enable_dynamic is None:
            cfg_d = CONFIG.url_scan if CONFIG.url_scan else None
            enable_dynamic = bool(getattr(cfg_d, 'dynamic_analysis', True))

        result = URLScanResult(url=url, scanned_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        logger.info(f"[URLScan] 扫描目标: {url}")

        if not re.match(r'^https?://', url, re.I):
            url = 'http://' + url
            result.url = url

        session = self._make_session()
        resp = self._fetch(session, url)
        result.status_code = resp.get('status', 0)
        result.reason = resp.get('reason', '')
        result.server_headers = resp.get('headers', {})
        result.final_url = resp.get('url', url) or url
        result.redirect_chain = resp.get('history', []) or []

        # 跳转到外部域名?
        base_domain = self._extract_domain(url)
        final_domain = self._extract_domain(result.final_url)
        if base_domain and final_domain and base_domain != final_domain:
            result.redirect_to_external = True

        # IP 解析 (带超时, 防止无响应 DNS 长时间阻塞扫描)
        host = self._host_of(result.final_url)
        ip = self._extract_ip(result.final_url)
        if not ip:
            try:
                import concurrent.futures as _cf
                _hostname = urlparse(result.final_url).hostname or ''
                if _hostname:
                    _pool = _cf.ThreadPoolExecutor(max_workers=1)
                    try:
                        _fut = _pool.submit(
                            socket.getaddrinfo, _hostname, 80, 0,
                            socket.SOCK_STREAM, socket.IPPROTO_TCP)
                        for info in _fut.result(timeout=4):
                            if info[4][0] and info[4][0] not in result.resolved_ips:
                                result.resolved_ips.append(info[4][0])
                    finally:
                        # 超时后不等待卡死的 DNS 查询线程
                        _pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        else:
            result.resolved_ips.append(ip)

        if not resp.get('ok'):
            result.fetch_error = resp.get('error', '')
            result.summary = f'连接失败: {result.fetch_error}'
            # DNS失败/超时/拒绝连接不是"风险", 不能给 medium/30 分
            result.risk_level = 'unknown' if result.status_code == 0 else 'low'
            result.risk_score = 0 if result.status_code == 0 else 5
            result.scan_duration = time.time() - start
            logger.warning(f"[URLScan] 连接失败: {url} — {result.fetch_error}")
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
            return result

        body = resp.get('body', b'')
        html = self._decode(body)
        result.page_size = len(body)
        result.content_type = (result.server_headers.get('Content-Type', '') or '').split(';')[0].strip()

        # 标题
        tm = re.search(r'(?is)<title[^>]*>(.*?)</title>', html)
        result.page_title = re.sub(r'\s+', ' ', tm.group(1)).strip()[:200] if tm else ''

        path = urlparse(result.final_url).path or '/'
        result.is_php = bool(re.search(r'(?i)\.php', path))

        # IoC 情报
        try:
            from analyzer.threat_intel import ThreatIntelEngine
            ti = ThreatIntelEngine()
            for check_url in (url, result.final_url):
                hit = ti.check_url(check_url)
                if hit:
                    result.ioc_hits.append(hit)
                for ip in result.resolved_ips:
                    ip_hit = ti.check_ip(ip)
                    if ip_hit:
                        result.ioc_hits.append(ip_hit)
                d_hit = ti.check_domain(self._extract_domain(check_url))
                if d_hit:
                    result.ioc_hits.append(d_hit)
        except Exception as e:
            logger.debug(f"[URLScan] IoC 检查失败: {e}")

        # 网页代码检测
        finds = []
        finds += self._detect_webshell(result.final_url, path, html)
        finds += self._detect_php8_webshell(html)
        finds += self._detect_hijack(html, result.final_url, base_domain or final_domain)
        finds += self._detect_obfuscation(html)
        finds += self._detect_driveby(html)
        finds += self._detect_clickfix(html)
        finds += self._detect_data_theft(html)
        finds += self._detect_cryptominer(html)
        finds += self._detect_websocket_c2(html)
        finds += self._detect_phishing(html, result.final_url, final_domain or base_domain)
        finds += self._detect_command_output(html)
        finds += self._detect_ssti(html)
        result.webshell_indicators = [f for f in finds if f['type'] in ('php_webshell', 'php_command_exec', 'php_obfuscated_shell', 'php_backdoor_param', 'jsp_webshell', 'asp_webshell', 'webshell_filename')]
        result.php8_webshell = [f for f in finds if f['type'] == 'php8_webshell']
        result.malicious_iframes = [f for f in finds if f['type'] in ('hidden_iframe', 'js_iframe_injection', 'page_tamper', 'activex_object', 'external_redirect')]
        result.obfuscated_scripts = [f for f in finds if f['type'] == 'js_obfuscation']
        result.drive_by_downloads = [f for f in finds if f['type'] == 'drive_by_download']
        result.phishing_indicators = [f for f in finds if f['type'].startswith('phishing')]
        result.social_engineering = [f for f in finds if f['type'] in ('clickfix', 'clickfix_combo', 'fake_update')]
        result.data_theft = [f for f in finds if f['type'] in ('magecart', 'keylogger', 'clipboard_hijack', 'data_exfil')]
        result.crypto_mining = [f for f in finds if f['type'] == 'crypto_mining']
        result.command_output_leak = [f for f in finds if f['type'] == 'command_output']
        result.phpinfo_exposed = any(f['type'] == 'phpinfo' for f in finds)

        # 可疑外链
        for m in re.finditer(r'(?i)(?:href|src)\s*=\s*["\'](https?://[^"\'>]+)["\']', html):
            link = m.group(1)
            l_host = self._host_of(link)
            if not l_host or l_host == final_domain or l_host == base_domain:
                continue
            low = link.lower()
            if any(t in low for t in ('.exe', '.scr', '.pif', '.com', '.bat', '.msi', '.hta')) or \
               any(low.endswith(t) for t in self.SUSPICIOUS_TLDS) or \
               re.search(r'\.php\?[^"\']*(cmd|exec|shell|pass|body|id)\s*=', low, re.I):
                result.suspicious_links.append(link)
        result.suspicious_links = list(dict.fromkeys(result.suspicious_links))[:20]

        # 外部脚本抓取分析
        if fetch_external and result.status_code < 400:
            try:
                ext_scripts = self._collect_external_scripts(html, result.final_url)[:max_external]
                for s_url in ext_scripts:
                    s_host = self._host_of(s_url)
                    s_resp = self._fetch(session, s_url, timeout=min(self.timeout, 8))
                    s_item = {'url': s_url, 'status': s_resp.get('status', 0),
                              'size': len(s_resp.get('body', b'')), 'findings': [], 'error': ''}
                    if s_resp.get('ok') and s_resp.get('body'):
                        s_code = self._decode(s_resp['body'])
                        s_findings = []
                        s_findings += self._detect_obfuscation(s_code)
                        s_findings += self._detect_driveby(s_code)
                        s_findings += self._detect_webshell(s_url, urlparse(s_url).path or '/', s_code)
                        s_findings += self._detect_php8_webshell(s_code)
                        s_findings += self._detect_clickfix(s_code)
                        s_findings += self._detect_data_theft(s_code)
                        s_findings += self._detect_cryptominer(s_code)
                        s_findings += self._detect_websocket_c2(s_code)
                        s_findings = self._dedup(s_findings)
                        if s_host != final_domain and any(f['severity'] in ('critical', 'high') for f in s_findings):
                            s_findings.append({'severity': 'medium', 'type': 'external_script',
                                               'evidence': f'跨域脚本 {s_host} 含恶意代码', 'line': 0})
                        s_item['findings'] = s_findings
                        finds += s_findings
                    else:
                        s_item['error'] = s_resp.get('error', '')
                    result.external_scripts.append(s_item)
            except Exception as e:
                logger.debug(f"[URLScan] 外部脚本分析失败: {e}")

        # ===== 动态行为监控 (浏览器沙箱: 执行页面 JS, 捕获网络/控制台/下载/DOM注入) =====
        if enable_dynamic:
            try:
                from analyzer.url_dynamic import URLDynamicMonitor
                if browser_engines is None:
                    cfg_be = CONFIG.url_scan if CONFIG.url_scan else None
                    browser_engines = URLDynamicMonitor.parse_engines(
                        getattr(cfg_be, 'browser_engines', 'chrome'))
                else:
                    browser_engines = URLDynamicMonitor.parse_engines(browser_engines)
                mon = URLDynamicMonitor()
                dyn = mon.monitor_all(result.final_url, engines=browser_engines,
                                      scanner=self, stop_event=stop_event)
                try:
                    mon.cleanup()
                except Exception:
                    pass
                result.dynamic_used = True
                result.dynamic_engine = dyn.get('engine', '')
                result.dynamic_error = dyn.get('error', '')
                result.dynamic_events = dyn.get('events', [])
                result.dynamic_requests = dyn.get('requests', [])
                result.dynamic_console = dyn.get('console', [])
                result.dynamic_downloads = dyn.get('downloads', [])
                result.dynamic_screenshots = dyn.get('screenshots', [])
                result.dynamic_resources = dyn.get('resources', [])
                result.dom_injected = dyn.get('dom_injected', [])
                if dyn.get('dom_html'):
                    result.dom_html = dyn['dom_html'][:200000]
                # 动态最终地址与跳转链 (含 meta-refresh/JS 跳转 — 静态 requests 看不到)
                if dyn.get('final_url') and dyn['final_url'] != result.final_url:
                    if not result.redirect_chain or result.redirect_chain[-1] != result.final_url:
                        result.redirect_chain.append(result.final_url)
                    result.redirect_chain.append(dyn['final_url'])
                    result.redirect_to_external = True
                    result.final_url = dyn['final_url']
                # DOM 注入 + 资源发现 → 并入总发现
                for f in result.dom_injected:
                    f['source'] = 'dom'
                    finds.append(f)
                for res in result.dynamic_resources:
                    for f in res.get('findings', []):
                        f['source'] = 'resource'
                        finds.append(f)
                for dl in result.dynamic_downloads:
                    if dl.get('suspicious'):
                        finds.append({'severity': 'critical', 'type': 'dynamic_download',
                                      'evidence': f"浏览器触发下载: {dl.get('filename', '')} ← {dl.get('url', '')[:120]}"
                                                  + (f" (YARA: {', '.join(dl.get('yara', []))})" if dl.get('yara') else ''),
                                      'line': 0})
            except Exception as e:
                logger.warning(f"[URLScan] 动态行为监控失败: {e}")
                result.dynamic_error = f'动态监控异常: {str(e)[:200]}'

        # 汇总排序
        result.all_findings = sorted(finds, key=lambda f: -self._severity_score(f.get('severity', 'low')))

        # ===== 风险评分 =====
        score = 0
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0}
        for f in finds:
            sev = f.get('severity', 'low')
            if sev in sev_counts:
                sev_counts[sev] += 1
        score += sev_counts['critical'] * 40
        score += sev_counts['high'] * 25
        score += sev_counts['medium'] * 12
        # IoC 命中
        if result.ioc_hits:
            score += min(len(result.ioc_hits) * 20, 40)
        # 直接 IP 托管 + 非常规端口 (内网/回环 IP 不算)
        import ipaddress as _ip
        is_public_ip = False
        try:
            is_public_ip = bool(ip) and _ip.ip_address(ip).is_global
        except Exception:
            pass
        if ip and is_public_ip:
            score += 8
            try:
                port = urlparse(result.final_url).port
                if port and port not in (80, 443):
                    score += 6
            except Exception:
                pass
        # http 明文 + 敏感路径
        if result.final_url.lower().startswith('http://'):
            score += 3
        low_path = path.lower()
        if any(sp in low_path for sp in self.SENSITIVE_PATHS):
            score += 6
        # 敏感路径中的 'login' 在 SENSITIVE_PATHS 里; 但纯信息页不算
        # 外部跳转
        if result.redirect_to_external:
            score += 8
        # ===== 动态行为监控风险 =====
        if result.dynamic_used:
            if result.dynamic_downloads:
                score += min(len(result.dynamic_downloads) * 15, 30)
                for dl in result.dynamic_downloads:
                    if dl.get('suspicious'):
                        score += 15
            if result.dom_injected:
                score += min(len(result.dom_injected) * 10, 30)
            for res in result.dynamic_resources:
                if any(f['severity'] in ('critical', 'high') for f in res.get('findings', [])):
                    score += 10
            suspicious_console = [m for m in result.dynamic_console
                                  if re.search(r'(?i)(eval|miner|cryptonight|mshta|powershell|WebSocket|clipboard)', m.get('text', ''))]
            if suspicious_console:
                score += min(len(suspicious_console) * 3, 10)
            if result.dynamic_error:
                score += 3
        # 证书错误/无法验证不计分, 但无法解析主机的 IP 加分
        if not result.resolved_ips and not ip:
            score += 5
        # phpinfo 不计 webshell, 单独
        if result.phpinfo_exposed:
            score += 10
        result.risk_score = min(score, 100)
        result.risk_level = ('critical' if score >= 60 else 'high' if score >= 35
                             else 'medium' if score >= 15 else 'low')

        # 摘要
        parts = []
        if sev_counts['critical']:
            parts.append(f"命令执行/免杀载荷 {sev_counts['critical']} 处")
        if sev_counts['high']:
            parts.append(f"高危挂马/混淆 {sev_counts['high']} 处")
        if sev_counts['medium']:
            parts.append(f"可疑特征 {sev_counts['medium']} 处")
        if result.ioc_hits:
            fams = set(h.get('family', '') for h in result.ioc_hits if h.get('family'))
            parts.append(f"IoC命中({','.join(fams) if fams else len(result.ioc_hits)})")
        if result.social_engineering:
            se_types = set(f['type'] for f in result.social_engineering)
            labels = {'clickfix': 'ClickFix', 'clickfix_combo': 'ClickFix组合', 'fake_update': '假浏览器更新'}
            parts.append('社会工程(' + ','.join(labels.get(t, t) for t in se_types) + ')')
        if result.data_theft:
            dt_types = set(f['type'] for f in result.data_theft)
            labels = {'magecart': 'Magecart', 'keylogger': '键盘记录', 'clipboard_hijack': '剪贴板劫持', 'data_exfil': '数据外泄'}
            parts.append('数据窃取(' + ','.join(labels.get(t, t) for t in dt_types) + ')')
        if result.crypto_mining:
            parts.append('挖矿脚本')
        if result.command_output_leak:
            parts.append('命令输出泄漏')
        if result.dynamic_used:
            dl_susp = sum(1 for d in result.dynamic_downloads if d.get('suspicious'))
            if result.dom_injected:
                parts.append(f'DOM注入({len(result.dom_injected)})')
            if dl_susp:
                parts.append(f'危险下载({dl_susp})')
            if result.dynamic_resources:
                parts.append(f'资源命中({len(result.dynamic_resources)})')
            if result.dynamic_engine:
                parts.append(f'动态监控({result.dynamic_engine})')
        if result.phpinfo_exposed:
            parts.append('phpinfo暴露')
        if not parts:
            parts.append('未发现明显恶意特征')
        result.summary = '; '.join(parts)
        result.scan_duration = time.time() - start

        logger.info(f"[URLScan] {url} → [{result.risk_level.upper()}] score={result.risk_score} "
                    f"critical={sev_counts['critical']} high={sev_counts['high']} "
                    f"medium={sev_counts['medium']} ioc={len(result.ioc_hits)} ({result.scan_duration:.1f}s)")
        for f in result.all_findings[:12]:
            logger.warning(f"  [{f['severity']}] {f['evidence'][:140]}")
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        return result


def scan_urls(urls: List[str], fetch_external_scripts: bool = None, stop_event=None,
              enable_dynamic: bool = None, browser_engines: list = None,
              max_workers: int = None, **kwargs) -> List[URLScanResult]:
    """批量扫描 URL — 多线程并行 (每 URL 独立线程)
    max_workers: 并发数, 默认取配置 url_scan.max_parallel
    """
    import concurrent.futures as _cf
    if max_workers is None:
        cfg_p = CONFIG.url_scan if CONFIG.url_scan else None
        max_workers = getattr(cfg_p, 'max_parallel', 3) or 1
    max_workers = max(1, min(int(max_workers), 8))

    def _scan_one(u: str) -> URLScanResult:
        if stop_event is not None and stop_event.is_set():
            return URLScanResult(url=u, fetch_error='用户停止', risk_level='unknown',
                                 risk_score=0, summary='已停止',
                                 scanned_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        try:
            scanner = URLScanner()
            return scanner.scan(u, fetch_external=fetch_external_scripts,
                                enable_dynamic=enable_dynamic,
                                browser_engines=browser_engines,
                                stop_event=stop_event, **kwargs)
        except Exception as e:
            logger.error(f"[URLScan] {u} 扫描失败: {e}")
            return URLScanResult(url=u, fetch_error=str(e)[:200],
                                 risk_level='unknown', risk_score=0,
                                 summary=f'扫描异常: {e}',
                                 scanned_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    results = []
    if len(urls) == 1:
        results.append(_scan_one(urls[0]))
    else:
        logger.info(f"[URLScan] 并行扫描 {len(urls)} 个 URL (并发 {max_workers})")
        with _cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {pool.submit(_scan_one, u): u for u in urls}
            for fut in _cf.as_completed(futs):
                if stop_event is not None and stop_event.is_set():
                    break
                try:
                    results.append(fut.result())
                except Exception as e:
                    logger.debug(f"[URLScan] 任务异常: {e}")
    return results
