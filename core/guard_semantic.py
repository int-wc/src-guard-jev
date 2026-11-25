#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
guard_semantic.py —— HTTP 请求作用解析引擎（2026-10-25 重构）

【为什么重构】
    旧实现靠「URL/body 里出现了什么词」来猜意图，天生有两个缺陷：
      · 误拦：edith 含 edit、dropdown 含 drop、poster 含 post、列表筛选 status=deleted …
      · 漏拦：shutdown?cid=1 因 '?' 不匹配、加个 .js 后缀绕过敏感文件检查 …
    根因是把【词法】当成了【语义】。

【新架构】三层，先解析再判断
    1) parse()    : HTTP 报文 → Facts（方法 / 归一化路径 / 结构化 query / 解析后的 body）
    2) classify() : Facts → Effect（这个请求到底要对什么资源做什么操作）
    3) policy()   : Effect → 是否命中《测试注意事项和禁止行为》某一条

【关键判据：全部是结构性的，不依赖关键词出现在哪】
    · 操作类型      ← HTTP 方法语义 + 路径【末段】动词 + body 动作字段（不是全路径扫描）
    · 新建 vs 修改  ← 请求是否携带「目标资源自己的标识」
                       （/order/123 的 123、或 {orderId:123} 且资源名=order；
                          {userId:1} 建消息属外键引用，不算修改目标资源）
    · 读 vs 写      ← 分页/过滤字段占比 + 查询类动词
    · 批量/拖库     ← 数量（分页值、数组长度），不是词
    · 敏感文件      ← 先把路径归一化（多轮解码、消解 ..、转义反斜杠）再比对
    · 静态资源      ← 归一化后确实无敏感特征，且后缀属静态，且没有文件类参数

【保留用模式匹配的部分】
    SQLi / SSTI / RCE / SSRF 的 **检测 payload** 本身就是内容特征，这类必须做内容匹配 ——
    但那是「识别攻击载荷」，不是「猜业务意图」，两者不能混为一谈。
"""
import json
import os
import re
import threading
import time
import unicodedata
import urllib.parse

# ======================================================================
# 一、词表：仅用于【结构位置】判定（末段动词 / 动作字段值），不做全文子串匹配
# ======================================================================
READ_VERBS = frozenset('''
list query search page pagequery detail info get select find view status check count
exist exists download export preview tree options dict lookup stat sum balance history
log logs records report reports chart dashboard home index init config settings menu
permission permissions role roles userinfo profile me current health ping version
detailinfo listbyid querybyid searchby getby findby
'''.split())

CREATE_VERBS = frozenset('''
create add insert new register signup apply submit save publish upload import generate
init start copy clone
'''.split())

UPDATE_VERBS = frozenset('''
update modify edit change set replace rename patch upsert move sort
enable disable restore revoke approve reject audit confirm commit apply transfer
reset resetpwd changepwd setpwd modifypwd
'''.split())

DELETE_VERBS = frozenset('''
delete del remove destroy purge wipe truncate drop erase unlink clear cancel refund
kick ban terminate
'''.split())

ALL_VERBS = READ_VERBS | CREATE_VERBS | UPDATE_VERBS | DELETE_VERBS

# 分页类字段（token 级）
PAGE_TOKENS = frozenset('''
page pagesize pagenum pageindex page_no limit size offset rows count num total length
top perpage per_page maxresults recordcount
'''.split())

# 过滤类字段：出现即提示「这是一次查询」
FILTER_TOKENS = frozenset('''
keyword keywords search query filter sort orderby orderbyfield direction asc desc
status state type category tag begin end starttime endtime begintime date from to
code token sign signature ticket nonce timestamp ts lang locale version platform
'''.split())

# 动作字段：值才是动作
ACTION_KEYS = frozenset('''
action op operation cmd command method _method __method act event eventtarget do
'''.split())

# 文件类参数名（值当作路径解析）
FILE_KEYS = frozenset('''
file filename filepath path pathname doc document download read src source template
tpl load attach attachment include fileUrl fileName
'''.split())

def _norm_set(words):
    """把参数名集合归一成小写无分隔形式（与 _nkey 保持一致）。"""
    return frozenset(re.sub(r'[^a-z0-9]', '', w.lower()) for w in words)


FILE_KEYS_N = _norm_set(FILE_KEYS)

# URL 类参数名（值当作地址解析，用于 SSRF）
URL_KEYS_N = _norm_set('''
url uri target dest destination redirect redirect_uri callback next return href link
src source host hostname domain site fetch proxy address addr ip
'''.split())
# 单字母/短参数名（f、p、u、q、d、fn、fp…）在渗透测试 payload 里常被用作文件路径或 URL 载体，
# 仅凭名字无法排除，因此对「值本身像绝对路径」的情况单独判定（见 _looks_like_filepath）。
SHORT_KEYS = frozenset('f p u q d fn fp n s'.split())

# body 里的「删除标记」字段（键名需精确等于，值需为真）
DELETE_FLAG_KEYS = frozenset('''
isdeleted isdel deleted deleteaccount delaccount isremoved isremove removed
'''.split())

STATUS_KEYS = frozenset('status state'.split())
DELETED_VALUES = frozenset('deleted removed destroyed purged wiped'.split())

EXEC_EXT = ('.php', '.php3', '.php4', '.php5', '.phtml', '.pht', '.jsp', '.jspx', '.jspf',
            '.asp', '.aspx', '.ashx', '.asmx', '.cer', '.exe', '.dll', '.so', '.war',
            '.jar', '.cgi', '.ser', '.dtd', '.hta', '.vbs', '.ps1', '.class', '.phar')

STATIC_EXT = ('.js', '.mjs', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp',
              '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webmanifest',
              '.wasm', '.br', '.gz', '.avif', '.bmp', '.otf')

# 2026-11-02（用户要求）：读方法末段为「文件型资源」时，文件名不承载动作语义。
# 实测误拦：GET https://raw.githubusercontent.com/.../SetValForbiddenException.php
# 被末段 set 判成「读方法但路径末段为修改动作=set」；get_file_info.json 同类。
# 与 STATIC_EXT 的区别：这里覆盖可下载的源码/文档/数据文件，且只用于「读方法判定」；
# query 里的显式动作（?action=delete）由 _explicit_action 先行判定，不受影响。
FILE_LIKE_EXT = (
    '.php', '.php3', '.php4', '.php5', '.phtml', '.pht', '.phar',
    '.jsp', '.jspx', '.jspf', '.asp', '.aspx', '.ashx', '.asmx',
    '.cs', '.java', '.py', '.rb', '.go', '.rs', '.c', '.h', '.cc', '.cpp', '.hpp',
    '.ts', '.tsx', '.jsx', '.vue', '.kt', '.swift', '.scala', '.pl', '.pm', '.lua',
    '.sh', '.bash', '.ps1', '.sql', '.xml', '.yaml', '.yml', '.md', '.txt', '.log',
    '.conf', '.ini', '.toml', '.properties', '.gradle', '.lock', '.json', '.html',
    '.htm', '.csv', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.tgz', '.7z', '.rar', '.jar', '.war', '.apk', '.ipa',
    '.pem', '.crt', '.cer', '.key', '.der', '.p12', '.pfx',
)

# 文件读取取证白名单：规则第 7 条允许的「无害 PoC」，与敏感文件区分
ALLOWED_READ = (
    '/etc/hostname', '/etc/issue', '/etc/os-release', '/etc/host.conf',
    '/etc/hosts', '/etc/resolv.conf', '/proc/sys/kernel/hostname',
    '/proc/version', '/etc/machine-id',
    'win.ini', 'windows/win.ini', 'windows/system32/drivers/etc/hosts',
)

# ===== 可解析文件上传：按【内容】判定，不按后缀 =====
# 用户口径（2026-10-25）：上传 php/jsp 等可解析文件时只允许投放【安全验证载荷】，
# 例如 <?php print("safetest_pwn!"); ?> —— 目的是证明文件被解析执行，不是留后门。
# 规则 7 明确禁止上传病毒/木马/保留后门。
#
# 判定：内容只做固定标记输出 → 放行；含命令执行/反弹/写入/反连/混淆 → 拦截。
# 只认固定标记串，不接受任意拼接（防止 print($_GET[1]) 这类真后门混入）。
SAFE_MARKERS = ('safetest_pwn', 'safetest', 'security_test', 'vuln_poc_test',
                'poc_test', 'safetest_ok')

DANGEROUS_UPLOAD_NAMES = ('.htaccess', '.user.ini', '.htpasswd',
                          'web.config', 'appsettings.json', '.env')

# 2026-10-26 新增：提权 / 内网横向命令（规则 7）
# 实测漏拦：POST /api/exec {"cmd":"chmod u+s /bin/sh"}、{"cmd":"sudo -s"}
PRIVESC_PATTERNS = [
    # 注意：_content_blob 会做 code_noise 清洗，会把 '+' 去掉变成 "chmod u s"，
    # 所以这里必须允许 u、+、s 之间出现空格。
    (r'chmod\s+(?:[ugoa]*\s*[+-]?\s*[sS](?=[\s;&|"\']|$)|[0-7]?\s*[4-7][0-7]{2})', 'SUID 提权(chmod)'),
    (r'\bsetcap\s+', '能力位提权(setcap)'),
    (r'\bsudo\s+(?:-s\b|-i\b|-u\s+root|su\b|bash\b|sh\b|/bin/)', 'sudo 提权'),
    (r'\bsu\s+-\s*(?:root)?(?=[\s;&|"\']|$)', 'su 提权'),
    (r'/etc/shadow', '读取 shadow 凭据'),
    (r'(?:\.ssh/id_(?:rsa|dsa|ecdsa)|/root/\.ssh|\.ssh/authorized_keys)', '读取/写入 SSH 凭据'),
    (r'\b(?:nc|ncat|netcat)\s+(?:-[a-z]+\s+)*-[a-z]*e\b', '反弹 shell(nc -e)'),
    (r'crontab\s+-[el]|/etc/cron\.', '计划任务持久化'),
]

# 2026-10-26 新增：群发/广播类接口（规则 8：禁止批量操作影响厂商业务）
BULK_ACTION_TOKENS = frozenset('''
sendall sendbatch batchsend masssend pushall broadcast notifyall sendmass
massmessage batchmessage sendmessageall alluserpush groupmessage sendnotice
batchnotice massnotice
'''.split())

# 2026-10-26 新增：可写字段段（识别 /资源/<id>/<字段> 的修改）
WRITABLE_FIELD_SEGS = frozenset('''
status state stage role roles permission permissions enable disable audit approve
verify pass fail finish close open publish bind assign grant revoke reset pwd
password mobile phone email amount price score level vip owner
'''.split())

# 角色/权限相关的 body 字段（规则 7 提权）
PRIV_CHANGE_KEYS = frozenset('''
role roles roleid rolecode rolekey permission permissions permid menuid
admin isadmin superuser ismanager managerid
'''.split())

# 2026-10-26 新增：读名词后缀。末段含这类词说明是「查询结果/列表」，不是动作。
# 实测误拦：GET  /galen/external/audit/auditResult  → 被当成「执行审核」
#           POST /galen/external/audit/auditResult  → 同理（POST 做查询在前端很常见）
READ_NOUN_TOKENS = frozenset('''
result results record records list page info detail details data
count total summary overview statistic statistics
'''.split())

_ID_SEG_RE = re.compile(
    r'^(?:\d{1,15}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$', re.I)



DANGEROUS_CODE = [
    (r'[$]\s*(?:_GET|_POST|_REQUEST|_COOKIE|_SERVER)\s*[\[]', '读取外部可控参数'),
    (r'\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(', '命令执行函数'),
    (r'\b(?:eval|assert|create_function)\s*\(', '代码执行函数'),
    (r'\b(?:include|require)(?:_once)?\s*\(?\s*[$]', '动态文件包含'),
    (r'\b(?:file_put_contents|fwrite|fputs|move_uploaded_file)\s*\(', '文件写入'),
    (r'\b(?:unlink|rename|chmod|chown|rmdir)\s*\(', '文件破坏/权限修改'),
    (r'\b(?:base64_decode|str_rot13|gzinflate|gzuncompress)\s*\(', '编码混淆载荷'),
    (r'\b(?:fsockopen|curl_exec)\s*\(', '网络请求/反连'),
    (r'/dev/(?:tcp|udp)/', '反弹 shell'),
    (r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec', 'Java 命令执行'),
    (r'\bProcessBuilder\s*\(', 'Java 命令执行'),
    (r'\bScriptEngine', '脚本引擎执行'),
    (r'\b(?:subprocess|os\.system|os\.popen)\s*\(', 'Python 命令执行'),
    (r'\bProcess\.Start|Assembly\.Load|Invoke-Expression', 'Windows 代码执行'),
]


def _strip_code_noise(body):
    """multipart 里只取文件内容部分（去掉边界与头部），用于内容判定。"""
    b = body or ''
    if 'content-disposition' not in b.lower():
        return b
    parts = []
    for m in re.finditer(r'\r?\n\r?\n(.*?)(?=\r?\n--|\Z)', b, re.S):
        parts.append(m.group(1))
    return '\n'.join(parts) if parts else b


def check_upload_content(body):
    """判定上传内容是否属「安全验证载荷」。返回 (ok, reason)。

    策略取向（2026-10-25）：但凡上传的是【可解析文件】（php/jsp/asp…），
    就必须能确认内容是安全验证载荷，否则一律拦。宁可误拦空内容的上传，
    也不放行一个「留白待填」的可执行文件——那是后门最常见的形态。
    """
    raw = _strip_code_noise(body)
    low = raw.lower()
    if not low.strip():
        return False, '可解析文件但内容为空，无法确认无害'
    for pat, name in DANGEROUS_CODE:
        if re.search(pat, raw, re.I):
            return False, name
    if any(mk in low for mk in SAFE_MARKERS):
        return True, '安全验证载荷'
    # 没有固定标记但看起来是可执行代码 → 不能确认无害，按危险处理
    if re.search(r'<\?php|<%|\$\{|<script', low):
        return False, '可执行代码但未使用安全验证标记'
    # 关键：调用方已确认「文件名是可解析扩展名」，此时内容却不是可执行代码，
    # 说明要么内容为空、要么只提交了文件名（留白待填的后门形态）。
    # 两种情况都无法证明是安全验证载荷 —— 一律拦。
    return False, '可解析文件但内容不含验证标记'

# 敏感文件/源码（规则 7：禁止下载和读取服务器上任何源代码文件和敏感文件）
SENSITIVE_MARKERS = (
    '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/crontab', '/etc/group',
    '.ssh/', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys',
    '.bash_history', '.zsh_history', '.git/config', '.git/HEAD', '/.git/',
    # 目录名不带斜杠也要命中：/WEB-INF、/META-INF 同样是源码目录访问
    'web-inf', 'meta-inf', '/.env', '.env.', 'application.yml',
    'application.properties', 'bootstrap.yml', 'bootstrap.properties',
    'tomcat-users.xml', '.htpasswd', 'wp-config.php', 'database.php',
    'settings.py', '/proc/self/', '/proc/1/', '.aws/', '.docker/config',
    '.kube/config', '.npmrc', '.pypirc', '.netrc', 'server.key', 'private.key',
    'web.config', 'appsettings.json', 'dump.sql', 'backup.sql',
)

SQLI_PATTERNS = [
    (r'\bdelete\s+from\b', 'SQL DELETE'),
    (r'\bdrop\s+(?:table|database|schema|index|view|user)\b', 'SQL DROP'),
    (r'\btruncate\s+table\b', 'SQL TRUNCATE'),
    (r'\bupdate\s+[\w\.\`\[\]"]+\s+set\b', 'SQL UPDATE'),
    (r'\balter\s+table\b', 'SQL ALTER'),
]
RCE_PATTERNS = [
    # 2026-10-26 修漏拦：JSON 载荷里 "/" 后面紧跟的是引号，原 lookahead 没覆盖 → rm -rf / 漏掉
    # 2026-10-26：rm -rf 指向任意绝对路径都属破坏性利用（含 /var/www 这类站点根目录）
    (r'\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/', 'rm -rf 破坏性删除'),
    (r'\bmkfs(?:\.\w+)?\b', 'mkfs 格式化磁盘'),
    (r'\bdd\s+[^|;]{0,60}of\s*=\s*/dev/', 'dd 写块设备'),
    (r'\b(?:shutdown|poweroff|halt|reboot)(?=\s|$|[?&;/#])', '关机/重启主机'),
    (r'/(?:restart|reload)(?=\s|$|[?&;/#])', '重启/重载服务'),
    (r'\bcrontab\s+-(?:r|e)\b', '篡改定时任务'),
    (r'/dev/(?:tcp|udp)/', '反弹 shell(/dev/tcp)'),
    (r'\b(?:bash|sh|zsh)\s+-i\b', '交互式反弹 shell'),
    (r'>\s*/etc/(?:passwd|shadow|crontab|sudoers)', '覆盖系统关键文件'),
    (r'\bchmod\s+(?:-R\s+)?777\s+/(?:\s|$|\*|;)', '全局 777 权限篡改'),
    (r'\bkill\s+-9\s+1\b', '杀 init 进程'),
    (r'\buserdel\b', '删除系统账号'),
]
SLEEP_RE = re.compile(r'\b(?:sleep|pg_sleep|waitfor\s+delay)\s*\(\s*(\d+)', re.I)
INTERNAL_IP_RE = re.compile(
    r'(?:^|[^0-9])(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|169\.254\.\d{1,3}\.\d{1,3}|100\.100\.100\.200|0\.0\.0\.0)(?![0-9])')
INTERNAL_HOST_RE = re.compile(r'^(?:localhost|metadata\.google\.internal|.*\.internal|.*\.local)$', re.I)

# ======================================================================
# 二、配置（由 guard.py 在导入后注入，避免范围清单两处维护）
# ======================================================================
CFG = {
    'scope_suffix': (),    # 历史白名单：全站模式下仅用于审计标注，不再作为拦截依据
    'out_of_scope': (),
    # 2026-10-26 用户要求「加入所有网站的审计，不止限定某个网站」：
    #   scope_mode='all'  → 所有主机都走同一套语义审计与拦截（默认）
    #   scope_mode='list' → 恢复旧行为：仅白名单内的主机受审计，名单外直接拦
    'scope_mode': 'all',
    # 2026-10-26 用户口径（第三次收窄）：
    #   policy='dml'    → 只拦「删除/修改」+「RCE 利用」；
    #                     上传、基础 RCE 命令(id/whoami/读文件)、拖库、范围外、限速 全部只审计
    #   policy='strict' → 恢复按 9 条禁止事项全面拦截
    'policy': 'strict',
    'bulk_max': 1000,      # 单次拉取条数上限（超过=拖库/大规模遍历）
    'bulk_write_max': 50,  # 单次批量提交对象数上限（规则第 8 条）
    'max_body': 1024 * 1024,
    # ===== 2026-10-29 新增：DoS/DDoS 防护阈值 =====
    # 用户要求拦截「可能影响业务导致 DDoS」的请求。阈值取 100 KB：
    # 正常 API 请求远小于此，安全测试也极少需要 >100KB 载荷。
    'dos_body_max': 100 * 1024,
    'dos_slow_max': 8,
    # ===== 高并发/自动化扫描限速（规则 2 影响稳定性 / 规则 4 禁止高并发扫描）=====
    # 2026-10-26 新增：原先的令牌桶只写在 guard.py 的旧判定分支里，而语义层成功时
    # decide() 直接返回，旧分支永不执行 → 限速形同虚设（实测 40 连发全部放行）。
    # 现搬到语义层，全站模式下一律生效。
    # 2026-10-26 按真实流量标定（统计历史日志每主机每秒请求数）：
    #   真实安全测试的峰值达 12~13 req/s（customer-a.example 12、customer-a.example 13），
    #   p95 普遍 2~8 req/s。原定 2 req/s 会把正常测试误限（实测 customer-a.example 被限 14 次），
    #   属「误拦截＝正常安全测试被拦」，必须放宽。
    #   现取 15 req/s 持续 + 60 突发：覆盖真实测试峰值，同时能把 100+ req/s 的
    #   目录爆破/自动化扫描压下来（规则 2/4）。
    'rate_enabled': True,
    'rate_cap': 60,        # 突发容量：覆盖 4 条战线并发 + 页面 XHR 突发
    'rate_per_sec': 15.0,  # 长期平均 15 req/s（实测峰值 13，留 15% 余量）
    'rate_max_hosts': 5000,  # 状态表上限，防止被打满内存
}

# ===== 2026-10-26 Lead 修复：支持按实例覆盖范围模式 =====
# 背景：全站审计模式（scope_mode='all'）会让范围外主机也放行，违反SRC 战役
#      「仅测试规定测试范围内的系统」要求。为不影响其它战役实例，改为环境变量覆盖：
#        GUARD_SCOPE_MODE=list        → 启用白名单拦截
#        GUARD_SCOPE_SUFFIX=.customer-a.example,.customer-a.example,...  → 白名单后缀（逗号分隔）
#        GUARD_OUT_OF_SCOPE=host1,host2                  → 明确不收的主机
_env_mode = os.environ.get('GUARD_SCOPE_MODE', '').strip()
if _env_mode:
    CFG['scope_mode'] = _env_mode
_env_suffix = os.environ.get('GUARD_SCOPE_SUFFIX', '').strip()
if _env_suffix:
    CFG['scope_suffix'] = tuple(x.strip() for x in _env_suffix.split(',') if x.strip())
_env_oos = os.environ.get('GUARD_OUT_OF_SCOPE', '').strip()
if _env_oos:
    CFG['out_of_scope'] = tuple(x.strip() for x in _env_oos.split(',') if x.strip())
print('[guard_semantic] scope_mode=%s suffix_count=%d oos=%s' % (
    CFG.get('scope_mode'), len(CFG.get('scope_suffix') or ()), CFG.get('out_of_scope')), flush=True)



def configure(**kw):
    CFG.update({k: v for k, v in kw.items() if v is not None})


# ======================================================================
# 限速器：按主机令牌桶（规则 2 / 规则 4）
# ======================================================================
_RATE_STATE = {}
_RATE_LOCK = threading.Lock()
_RATE_STATIC = ('.js', '.mjs', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                '.webp', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
                '.webmanifest', '.avif', '.bmp', '.otf', '.wasm', '.br', '.gz')


def _is_loopback(host):
    h = (host or '').lower().split(':')[0]
    return (not h) or h in ('127.0.0.1', 'localhost', '::1') or h.startswith('127.')


def rate_check(host, path, method='GET'):
    """按主机令牌桶限速。返回 RATE_LIMIT 原因串或 None。

    设计要点（避免误拦正常安全测试）：
      · 静态资源完全豁免 —— 页面加载大量 js/css/图片不计入
      · 桶容量 24：允许浏览器一次并发几十个 XHR 的突发
      · 长期平均 2 req/s：持续扫描才会触顶（规则 4 禁止高并发扫描）
      · 触发后由 mitm_guard 返回 429 + Retry-After，语义是「降速重试」而非「违规」
    """
    if not CFG.get('rate_enabled', True):
        return None
    h = (host or '').lower().split(':')[0]
    if _is_loopback(h):
        return None
    if (path or '').lower().rsplit('/', 1)[-1].endswith(_RATE_STATIC):
        return None
    cap = float(CFG.get('rate_cap', 24))
    per = float(CFG.get('rate_per_sec', 2.0))
    if cap <= 0 or per <= 0:
        return None
    try:
        with _RATE_LOCK:
            now = time.monotonic()
            st = _RATE_STATE.get(h)
            if st is None:
                if len(_RATE_STATE) > int(CFG.get('rate_max_hosts', 5000)):
                    _RATE_STATE.clear()
                st = {'tokens': cap, 'last': now}
                _RATE_STATE[h] = st
            st['tokens'] = min(cap, st['tokens'] + (now - st['last']) * per)
            st['last'] = now
            if st['tokens'] < 1.0:
                return 'RATE_LIMIT 触发限速(>%.0f req/s，请降速重试)' % per
            st['tokens'] -= 1.0
    except Exception:
        return None
    return None


# ======================================================================
# 三、基础工具
# ======================================================================
def _decode_deep(s, rounds=3):
    """多轮 URL 解码：%252e%252e 这类双重编码常用来绕过检查。"""
    for _ in range(rounds):
        try:
            d = urllib.parse.unquote(s)
        except Exception:
            break
        if d == s:
            break
        s = d
    return s


def normalize_path(p):
    """路径归一化：解码 → NFKC → 反斜杠转 / → 去 NUL → 消解 . 与 ..

    这一步是「结构性」的关键：先把路径还原成它真正指向的资源，
    再判断是不是敏感文件。/WEB-INF/web.xml;.js 归一化后仍含 web-inf/，必然命中。
    """
    p = _decode_deep(p or '')
    p = unicodedata.normalize('NFKC', p)
    p = p.replace('\\', '/').replace('\x00', '')
    parts = []
    for seg in p.split('/'):
        # 矩阵参数（;jsessionid=xxx）要【逐段】剥离，不能对整条路径 split(';')[0]，
        # 否则 /static/..;/..;/.git/config 会被截成 '/static/..' 后整条作废（实测可绕过敏感文件检查）。
        seg = seg.split(';', 1)[0]
        if seg in ('', '.'):
            continue
        if seg == '..':
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return '/' + '/'.join(parts)


def _ntokens(s):
    """切词：非字母数字分隔 + camelCase 拆分，全小写。

    2026-10-26 修漏拦：camelCase 拆分会把「混合大小写」的单词切碎。
        dElEtE  → ['d','el','et','e']   ← delete 完全消失，动词判定失效
        DeLeTe  → ['de','le','te']
    因此额外补一个「整段小写」token，让 dElEtE 也能得到 'delete'。
    （错误的大小写本来就是绕过关键词检查的经典手法）
    """
    out = []
    for seg in re.split(r'[^A-Za-z0-9]+', str(s or '')):
        if not seg:
            continue
        for x in re.split(r'(?<=[a-z0-9])(?=[A-Z])', seg):
            if x:
                out.append(x.lower())
        _w = seg.lower()
        if _w not in out:
            out.append(_w)
    return out


def _nkey(k):
    # 必须先转小写再过滤：否则 'isDeleted' 会被 [^a-z0-9] 吃掉大写 D，
    # 变成 'iseleted'，永远匹配不上 'isdeleted'。这是 2026-10-25 测试发现的真实 bug。
    return re.sub(r'[^a-z0-9]', '', str(k or '').lower())


def _truthy_ref(v):
    """判断一个 id 字段是否是「指向已存在资源」的真值。"""
    if v is None or isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return v > 0
    s = str(v).strip().lower()
    return s not in ('', '0', '-1', 'null', 'none', 'undefined', 'false', 'new', 'nil')


def _iter_pairs(obj, depth=0, key=''):
    """遍历 body/query 里的 (键, 值)，深度有限，产出叶子与容器。"""
    if depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kk = str(k)
            yield kk, v
            for p in _iter_pairs(v, depth + 1, kk):
                yield p
    elif isinstance(obj, list):
        for v in obj[:50]:
            for p in _iter_pairs(v, depth + 1, key):
                yield p


# ======================================================================
# 四、解析层
# ======================================================================
def _parse_body(body, ctype):
    b = body or ''
    if not b.strip():
        return 'empty', None, None
    s = b.lstrip()
    if s[:1] in ('{', '['):
        try:
            return 'json', json.loads(b), None
        except Exception:
            pass
    if 'multipart/form-data' in ctype:
        return 'multipart', None, _parse_multipart(b)
    if 'application/x-www-form-urlencoded' in ctype or ('=' in b and re.fullmatch(
            r'[^\s&=]+=[^\s&]*(?:&[^\s&=]+=[^\s&]*)*', b.strip())):
        try:
            return 'form', None, dict(urllib.parse.parse_qsl(b, keep_blank_values=True))
        except Exception:
            pass
    return 'text', None, None


def _parse_multipart(b):
    """从 multipart 结构里取出「字段名→字段值」与上传文件名（结构性提取，不猜）。

    2026-10-26 修漏拦：旧实现只提取字段名、值恒为空（fields.setdefault(name, '')），
    因此 multipart 里塞 JSON 的请求（前端很常见）完全看不到载荷内容：
        --X
        Content-Disposition: form-data; name="data"

        {"orderId":1,"status":"deleted"}
    现按 boundary 切分、取空行之后的正文作为字段值。
    """
    fields, filenames = {}, []
    raw = b or ''
    if len(raw) > 262144:      # 只看前 256KB，避免大文件拖慢判定
        raw = raw[:262144]
    # 按 boundary 行切分；不依赖具体 boundary 字符串
    for seg in re.split(r'\r?\n--[^\r\n]*', raw):
        if not seg or not seg.strip():
            continue
        mh = re.search(r'name="([^"]*)"(?:\s*;\s*filename="([^"]*)")?', seg, re.I)
        if not mh:
            continue
        name, fn = mh.group(1), mh.group(2)
        if fn:
            filenames.append(fn)
            continue
        # 正文位于第一个空行之后
        idx = seg.find('\r\n\r\n')
        if idx >= 0:
            val = seg[idx + 4:]
        else:
            idx = seg.find('\n\n')
            val = seg[idx + 2:] if idx >= 0 else ''
        val = val.rstrip('\r\n')
        if name:
            fields[name] = val
    return {'fields': fields, 'filenames': filenames, '_is_multipart': True}


def parse(method, url, headers, body):
    method = (method or 'GET').strip().upper()
    try:
        u = urllib.parse.urlparse(url or '')
    except Exception:
        u = urllib.parse.urlparse('')
    raw_path = u.path or '/'
    path = normalize_path(raw_path)
    segs = [s for s in path.split('/') if s]
    query = {}
    try:
        for k, vs in urllib.parse.parse_qs(u.query or '', keep_blank_values=True).items():
            query[k] = vs
    except Exception:
        pass
    hdrs = {}
    for k, v in (headers or {}).items():
        hdrs[str(k).lower()] = str(v)
    ctype = hdrs.get('content-type', '').lower()
    kind, obj, form = _parse_body(body, ctype)
    return {
        'method': method, 'scheme': (u.scheme or '').lower(),
        'host': (u.hostname or '').lower(), 'orig_host': (u.hostname or ''),
        'raw_path': raw_path, 'path': path, 'segs': segs,
        'query': query, 'headers': hdrs, 'ctype': ctype,
        'body_raw': body or '', 'body_kind': kind, 'body': obj, 'form': form,
        'url': url or '',
    }


# ======================================================================
# 五、语义分类层
# ======================================================================
def _seg_words(segs):
    return [(_ntokens(s)[0] if _ntokens(s) else '') for s in segs]


def _strip_tail_ids(segs):
    s = list(segs)
    while len(s) > 1 and re.fullmatch(
            r'(?:\d{1,20}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            r'|[0-9a-f]{16,64})', s[-1], re.I):
        s.pop()
    return s


def _is_static_segment(seg):
    """该路径段是否是静态资源文件名（reset.css / list.js / delete.png）。

    文件名不是动作：/css/reset.css 里的 reset 是样式重置，不是「重置数据」。
    这里按「末段的多段后缀」判断，min.js、d.ts.map 这类同样覆盖。
    """
    low = (seg or '').lower()
    return low.endswith(STATIC_EXT)


def _last_verbs(segs, ignore_static=False):
    """取路径末段（跳过尾随 ID）的全部切词，返回 token 列表。

    只看【末段】是修复 edith/dropdown 误伤的关键（中间段是资源名）。
    但末段本身可能是复合词：batch-delete → ['batch','delete']，
    动作常在词尾而不是词首，所以必须返回全部 token 供调用方扫描。
    静态资源末段返回空——文件名不承载动作语义。
    """
    s = _strip_tail_ids(segs)
    if not s:
        return []
    last = s[-1]
    # 2026-10-26 修漏拦：写方法(POST/PUT/PATCH/DELETE)下，静态后缀是绕过手法而非真静态资源。
    # 实测漏拦：POST /dwr/exec/ItemService.delete.js —— 末段 .js 导致动词直接被清空。
    if _is_static_segment(last) and not ignore_static:
        return []
    if '.' in last:
        last = last.rsplit('.', 1)[0]
    return _ntokens(last)


def _last_verb(segs):
    """兼容旧调用：返回末段的第一个 token。"""
    t = _last_verbs(segs)
    return t[0] if t else ''


def _pick_verb(tokens, read_mode=False):
    """从末段 token 里挑出动作词，优先级：删除 > 修改 > 新建 > 查询。

    batch-delete / deleteBatch / removeById 这类复合词，动作在任意位置都要能识别。
    """
    ts = set(tokens or [])
    if not ts:
        return ''
    for group in (DELETE_VERBS, UPDATE_VERBS, CREATE_VERBS, READ_VERBS):
        for t in tokens:
            if t in group:
                return t
    return ''


def _resource_name(segs):
    """目标资源名：从后往前找第一个非动词、非版本、非 ID 的段。"""
    stop = {'api', 'v1', 'v2', 'v3', 'v4', 'rest', 'service', 'services',
            'internal', 'open', 'outer', 'web', 'app', 'gateway', 'gate', 'public'}
    for s in reversed(segs):
        if re.fullmatch(r'\d{1,20}', s):
            continue
        t = _ntokens(s)
        if not t:
            continue
        w = t[0]
        if w in ALL_VERBS or w in stop:
            continue
        return w
    return ''


def _jsonish(v):
    """若值是「长得像 JSON 的字符串」就解析出来，否则返回 None。

    2026-10-26 补漏拦：multipart / form-urlencoded 里常见把整个 JSON 塞进一个字段：
        --X
        Content-Disposition: form-data; name="data"

        {"orderId":1,"status":"deleted"}
    旧实现只看到 ("data", '{...}')，键名不是 status，软删除/修改判定就漏了。
    """
    if not isinstance(v, str):
        return None
    t = v.strip()
    if len(t) < 2 or t[0] not in '{[':
        return None
    try:
        return json.loads(t)
    except Exception:
        return None


def _yield_pairs_maybe_json(k, v):
    """产出一对键值；值若是 JSON 字符串则继续展开内部键值。"""
    yield k, v
    _j = _jsonish(v)
    if _j is not None:
        for _p in _iter_pairs(_j):
            yield _p


def _all_key_pairs(f):
    """把 query / JSON body / form 统一成 (键, 值) 序列。"""
    for k, vs in f['query'].items():
        for v in vs:
            yield k, v
    b = f['body']
    if isinstance(b, (dict, list)):
        for k, v in _iter_pairs(b):
            yield k, v
    form = f['form']
    if isinstance(form, dict) and not form.get('_is_multipart'):
        for k, v in form.items():
            for p in _yield_pairs_maybe_json(k, v):
                yield p
    elif isinstance(form, dict) and form.get('_is_multipart'):
        for k, v in (form.get('fields') or {}).items():
            for p in _yield_pairs_maybe_json(k, v):
                yield p


_XML_DESTRUCTIVE_RE = re.compile(
    r'<(?:[a-z0-9_]+:)?(delete|remove|drop|destroy|truncate|wipe|purge|update|modify|edit|set|create)'
    r'[a-z0-9_]*[\s>/]', re.I)


def _mutation_action(f):
    """GraphQL mutation / SOAP-XML 破坏性标签（2026-10-26 补漏拦）。

    实测漏拦：
        {"query":"mutation{deleteItem(id:1)}"}                      → 放行
        GET /graphql?query=mutation{deleteItem(id:1)}               → 放行
        <soap:Body><DeleteUser><id>1</id></DeleteUser></soap:Body>  → 放行

    GraphQL 的写操作只能走 mutation，XML/SOAP 的写操作靠标签名表达动作，
    两者的共同点是「动作名称在载荷里」，与 REST 的路径动词判定互补。
    """
    blob = _content_blob(f) or ''
    low = blob.lower()
    if re.search(r'\bmutation\b\s*[\{\(]', low):
        for kw, act in (('delete', 'delete'), ('remove', 'delete'), ('drop', 'delete'),
                        ('destroy', 'delete'), ('truncate', 'delete'), ('wipe', 'delete'),
                        ('update', 'update'), ('modify', 'update'), ('edit', 'update'),
                        ('patch', 'update')):
            if kw in low:
                return act
        return 'update'      # 含 mutation 但看不出具体动作 → 保守按修改
    m = _XML_DESTRUCTIVE_RE.search(blob)
    if m:
        v = (m.group(1) or '').lower()
        if v in ('delete', 'remove', 'drop', 'destroy', 'truncate', 'wipe', 'purge'):
            return 'delete'
        return 'update'
    return None


def mutation_signal(f):
    """GraphQL mutation / SOAP-XML 破坏性标签 —— 只作为语义线索，不直接决定拦截。"""
    try:
        return _mutation_action(f)
    except Exception:
        return None


def _explicit_action(f):
    """读显式动作字段（action/op/__method/...），值才代表动作。"""
    for k, v in _all_key_pairs(f):
        if _nkey(k) not in ACTION_KEYS:
            continue
        low = str(v or '').strip().lower()
        if low in ('delete', 'put', 'patch', 'post', 'get'):
            return {'delete': 'delete', 'put': 'update', 'patch': 'update',
                    'post': 'create', 'get': 'read'}[low]
        toks = set(_ntokens(v))
        if toks & DELETE_VERBS:
            return 'delete'
        if toks & UPDATE_VERBS:
            return 'update'
        if toks & CREATE_VERBS:
            return 'create'
        if toks & READ_VERBS:
            return 'read'
    return None


def _has_existing_ref(f):
    """请求是否指向「已存在的目标资源」——这是区分「新建」与「修改」的核心判据。

    只认目标资源【自己】的标识：
      · 路径尾部的数值/UUID（/order/123）
      · body 里的 id / pk / uuid，或「资源名+Id」（资源是 order 时的 orderId）
      · userId 这类**外键引用**不算修改目标资源（POST /message/add {userId:1} 是新建留言）
    """
    segs = f['segs']
    if segs and re.fullmatch(
            r'(?:\d{1,20}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            r'|[0-9a-f]{16,64})', segs[-1], re.I):
        return True
    res = _resource_name(segs)
    for k, v in _all_key_pairs(f):
        t = _ntokens(k)
        if not t:
            continue
        if t in (['id'], ['pk'], ['uuid'], ['guid']):
            if _truthy_ref(v):
                return True
        # 2026-10-26 修正：不能要求切词长度恰好为 2。
        # _ntokens 现在会额外产出「整段小写」token（orderId → [order, id, orderid]），
        # 原来的 len(t)==2 精确匹配会让 orderId 识别失败，导致「修改订单」被当新建放行。
        # 2026-10-26 修正：不能依赖切词位置/长度。
        # _ntokens 会额外产出「整段小写」token（orderId → [order, id, orderid]），
        # 任何基于下标/长度的精确匹配都会失效。改为「同时出现资源名与 id 词」或「资源名+id 连写」。
        elif res and res in ('game', 'app', 'tenant', 'company', 'org', 'shop', 'store') and ('id' in t):
            # 2026-11-11 SRC 修正：game_id/app_id/tenant_id 是典型【外键维度】而非本资源标识。
            # 例：POST /payment/special/game-char?game_id=5174&openid=xxx 是查询该玩家在某游戏下的角色，
            #     只读业务，不能因为字段名含 game 与 id 就判成「修改 game 资源」。
            continue
        elif res and (('id' in t and res in t) or (res + 'id') in t):
            if _truthy_ref(v):
                return True
    return False


def _has_delete_state(f):
    """载荷是否把状态设成「已删除」（status=deleted / state=DELETED …）。

    这类请求本质是「软删除」，不能被 _is_query_payload 当成「列表筛选」放过去。
    与 find_delete_markers 的区别：这里只看 status/state 字段，且不区分读写语义，
    用于在 resolve_op 阶段就排除「这是查询」的误判。
    """
    for k, v in _all_key_pairs(f):
        nk = _nkey(k)
        if nk in STATUS_KEYS and str(v).strip().lower() in DELETED_VALUES:
            return '%s=%s' % (k, v)
    return None


def _is_query_payload(f):
    """载荷像查询：有分页/过滤字段，没有动作字段，且不指向已存在资源。"""
    toks = set()
    for k, _v in _all_key_pairs(f):
        toks.update(_ntokens(k))
    if not toks:
        return False
    if toks & ACTION_KEYS:
        return False
    if _has_existing_ref(f):
        return False
    # 把 status 设成 deleted 属于「软删除」意图，不是查询筛选
    if _has_delete_state(f):
        return False
    return bool(toks & PAGE_TOKENS) or bool(toks & FILTER_TOKENS)


def _q_pairs(f):
    """返回 query 的 (k, v) 列表。

    2026-10-26 踩坑：f['query'] 是 {键: [值...]} 的 dict，不是字符串，
    最初当字符串用 parse_qsl 解析，异常被吞掉后返回空列表，
    导致「分页豁免」恒不生效、「表单页豁免」恒为真（反而放行了带写入数据的请求）。
    """
    out = []
    q = f.get('query')
    try:
        if isinstance(q, dict):
            for k, vs in q.items():
                if isinstance(vs, (list, tuple)):
                    for v in vs:
                        out.append((k, v))
                else:
                    out.append((k, vs))
        elif q:
            out.extend(urllib.parse.parse_qsl(str(q), keep_blank_values=True))
    except Exception:
        return out
    return out


def _has_destructive_parent(f):
    """路径的【父段】里是否含破坏性动词。

    2026-10-26 用于区分两种「apply」：
        GET /leave/apply     → 申请页（父段是业务名词）      → 放行
        GET /refund/apply    → 对某笔退款执行操作（父段 refund 是删除类）→ 拦截
    """
    segs = [str(x) for x in (f['segs'] or [])]
    if len(segs) < 2:
        return False
    toks = set()
    for sg in segs[:-1]:
        toks |= set(_ntokens(sg))
    return bool(toks & DELETE_VERBS)


def _writable_field_hit(f):
    """POST /资源/<id>/<可写字段> 且 body 同名赋值 → 修改已存在资源。

    实测漏拦：POST /api/order/1/status {"status":2}
    旧逻辑只看「路径尾部 id」，中段 id（/1/status）识别不到，于是落到「新建」被放行。
    """
    segs = [str(x) for x in (f['segs'] or [])]
    if len(segs) < 2:
        return None
    last = _nkey(segs[-1])
    if last not in WRITABLE_FIELD_SEGS:
        return None
    if not any(_ID_SEG_RE.match(s2) for s2 in segs[:-1]):
        return None
    for k, _v in _all_key_pairs(f):
        if _nkey(k) == last:
            return '路径 /%s/ 中段带资源ID且 body 赋值 %s = 修改已存在资源' % (segs[-1], k)
    return None


def _is_paginated_read(f):
    """读方法 + 带分页字段 = 这是一次「列表查询」，路径里的动词只是资源名。

    2026-10-26 修误拦（实测真实流量）：
        GET /galen/external/file/modify-name?current=1&pageSize=1   → 被误判成「修改」
        GET /galen/api-manage/auth/revoke?current=1&pageSize=1      → 被误判成「删除」
        GET /galen/external/audit/auditResult?current=1&pageSize=1
    这些都是分页列表查询，不是执行修改/删除。
    判据：query 里出现分页字段，且没有 action 类字段（action/cmd/_method…）。
    """
    pairs = _q_pairs(f)
    if not pairs:
        return False
    toks = set()
    for k, _v in pairs:
        toks.update(_ntokens(k))
    if toks & ACTION_KEYS:
        return False
    return bool(toks & PAGE_TOKENS)


def _is_form_page_get(f):
    """读方法 + 无「写入型」query 参数 = 打开编辑表单页，不是执行修改。

    2026-10-26 修误拦（实测真实流量）：
        GET /clue-service/car/edit          → 打开车辆编辑页
        GET /clue-service/security/update   → 打开安全设置页
    判据：query 只允许 id 类 / 分页类 / 过滤类参数；
         一旦出现「键=非数字值」（如 name=hack）就视为真写入，继续拦。
    注意：删除类动词不享受本豁免 —— GET 直删是真实漏洞，必须继续拦。
    """
    for k, v in _q_pairs(f):
        nk = _nkey(k)
        if nk in PAGE_TOKENS or nk in FILTER_TOKENS or nk in ACTION_KEYS:
            continue
        if nk == 'id' or nk.endswith('id'):
            continue
        vs = str(v or '').strip()
        if not vs:
            continue
        if re.fullmatch(r'-?\d{1,15}', vs):
            continue
        return False
    return True


# 2026-11-16 lead：包管理器 registry 主机集合（只读 CDN，不是 SRC 目标）
# 背景：GET /remove-blank-lines 这类包名被「末段=删除动作」误判成删除，
#       今日实测误拦 21,781 次，导致 Artex 装 npm 依赖反复失败。
_REGISTRY_HOSTS = frozenset((
    'registry.npmmirror.com', 'registry.npmjs.org', 'registry.yarnpkg.com',
    'registry.npm.taobao.org', 'npmmirror.com', 'cdn.jsdelivr.net',
    'unpkg.com', 'cdnjs.cloudflare.com', 'pypi.org', 'files.pythonhosted.org',
    'pypi.tuna.tsinghua.edu.cn', 'proxy.golang.org', 'sum.golang.org',
    'crates.io', 'static.crates.io', 'repo1.maven.org', 'repo.maven.apache.org',
))


def resolve_op(f):
    """解析「这个请求要做什么」。返回 (op, 依据)。"""
    m = f['method']
    # 2026-11-02：X-HTTP-Method-Override 系列头会改写服务端实际执行的动作
    # （经典绕过：POST /api/user/1 + Override: DELETE，det 只看 POST 就放行了）。
    # 语义层必须按覆盖后的方法判定；guard._llm_state 的提示里本就携带这些头，Jev 同步可见。
    try:
        _hdrs = f.get('headers') or {}
        for _ok in ('x-http-method-override', 'x-method-override', 'x-http-method',
                    'x-override', 'x-amz-method', 'x-method'):
            _ov = _hdrs.get(_ok)
            if _ov:
                _ovm = str(_ov).strip().upper()
                if _ovm in ('GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'):
                    m = _ovm
                    break
    except Exception:
        pass
    if m in ('GET', 'HEAD', 'OPTIONS'):
        # 静态资源（reset.css / list.js）不参与动作判定
        if f['segs'] and _is_static_segment(f['segs'][-1]):
            return 'read', ['静态资源文件，无动作语义']
        # 2026-11-16 lead：包管理器 registry 只读豁免（用户批准「只要不影响就行」）
        # registry 是只读 CDN，包名里的 remove/delete/drop 是包名不是动作。
        if (f.get('host') or '').lower() in _REGISTRY_HOSTS:
            return 'read', ['包管理器 registry 只读（包名含动作词不算删除）']
        # 2026-10-26：先看 query 里的显式动作，再做结构化豁免，最后按末段动词判危险
        _act = _explicit_action(f)
        if _act in ('delete', 'update'):
            return _act, ['读方法但 query 显式动作=%s' % _act]
        # 2026-11-01：GraphQL mutation / SOAP 破坏性标签升格为操作判定。
        # 原先仅作审计线索，导致 GET /graphql?query=mutation{deleteItem(id:1)} 落到
        # 兜底 read/create，交叉校验据此推翻 Jev 的删改结论（实测 conf 0.98 被放行）。
        _mg = mutation_signal(f)
        if _mg:
            return _mg, ['读方法但 GraphQL mutation/SOAP 标签声明动作=%s' % _mg]
        # 2026-11-02（用户要求）：末段为源码/文档/数据文件名时，文件名不承载动作语义。
        # 实测误拦：GET .../SetValForbiddenException.php 被 set 判成修改动作。
        if f['segs']:
            _seg_last = f['segs'][-1]
            _sx = ('.' + _seg_last.rsplit('.', 1)[-1].lower()) if '.' in _seg_last else ''
            if _sx and _sx in FILE_LIKE_EXT:
                return 'read', ['读方法且末段为文件型资源(%s)，文件名不含动作语义' % _sx]
        if _is_paginated_read(f):
            return 'read', ['读方法且带分页字段=列表查询（末段动词为资源名）']
        # 末段含读名词（auditResult / auditList / orderRecords）→ 查询，不是动作
        if f['segs']:
            _lt = set(_ntokens(f['segs'][-1]))
            if _lt & READ_NOUN_TOKENS:
                return 'read', ['读方法且末段含读名词=%s' % sorted(_lt & READ_NOUN_TOKENS)[0]]
        # 2026-10-26 修误拦：末段同时含「读动词」与「动作动词」时按查询处理。
        # 实测误拦：GET /api/payment/refundQuery、GET /api/refund/queryRefund
        #   refundQuery 是「查退款记录」，被 refund 判成了删除动作。
        if f['segs']:
            _lv = set(_ntokens(f['segs'][-1]))
            if (_lv & READ_VERBS) and (_lv & (DELETE_VERBS | UPDATE_VERBS)):
                return 'read', ['末段同时含读动词与动作动词，按查询处理(%s)' %
                                sorted(_lv & READ_VERBS)[0]]
        v = _pick_verb(_last_verbs(f['segs']), read_mode=True)
        # 仅对「页面类」动词豁免（GET + 无写入参数 = 打开表单页）。
        # disable/enable/revoke/restore/approve/reject 等管理动作仍继续拦。
        # 2026-10-26 补：change —— 实测误拦 /.well-known/change-password
        # （W3C/RFC8615 标准改密入口，浏览器直接访问，属公开路径）
        if (v in ('edit', 'update', 'modify', 'apply', 'reset', 'bind', 'unbind',
                  'register', 'signup', 'submit', 'join', 'change', 'transfer')
                and _is_form_page_get(f) and not _has_destructive_parent(f)):
            return 'read', ['读方法且无写入参数，末段=编辑页动词(%s)' % v]
        if v in DELETE_VERBS:
            return 'delete', ['读方法但路径末段为删除动作=%s' % v]
        if v in UPDATE_VERBS:
            return 'update', ['读方法但路径末段为修改动作=%s' % v]
        return 'read', ['方法=读']
    if m == 'DELETE':
        return 'delete', ['方法=DELETE']
    if m == 'PUT':
        return 'replace', ['方法=PUT']
    if m == 'PATCH':
        return 'update', ['方法=PATCH']
    if m != 'POST':
        return 'other', ['非常规方法=%s' % m]

    act = _explicit_action(f)
    if act:
        return act, ['body/query 显式动作字段']
    # 2026-11-01：GraphQL mutation / SOAP 破坏性标签升格为操作判定（同 GET 分支）。
    # 实测漏拦：POST /graphql {"query":"mutation{deleteUser(id:1){ok}}"} 落到兜底
    # create，jev_decide 交叉校验据此推翻 Jev 删改结论（conf 0.98 被放行）；
    # mutation{...} 内含 delete/update 等动作词 → 按其动作归类。
    # 【注意】只升格「结构性写操作」（GraphQL/SOAP 有无歧义的写形态）；裸 SQL 文本
    # 不在此列 —— 它可能是搜索/教程内容，按 2026-10-26 口径仅作审计线索喂 Jev，
    # 由 guard.py 的否决例外（last_destructive_signal）处理交叉校验问题。
    _mg = mutation_signal(f)
    if _mg:
        return _mg, ['GraphQL mutation/SOAP 标签声明动作=%s' % _mg]
    # 2026-10-26：必须在动词判定【之前】判「中段ID+可写字段」。
    # 否则 status 这类词会先被 READ_VERBS 吃掉（"路径末段查询动作=status"），
    # 导致 POST /order/1/status {"status":2} 被误判为读。
    _ws0 = _writable_field_hit(f)
    if _ws0:
        return 'update', [_ws0]
    # 末段含读名词（auditResult）→ 查询类 POST，不是动作
    if f['segs']:
        _lt0 = set(_ntokens(f['segs'][-1]))
        if _lt0 & READ_NOUN_TOKENS:
            return 'read', ['末段含读名词=%s（POST 查询）' % sorted(_lt0 & READ_NOUN_TOKENS)[0]]
    v = _pick_verb(_last_verbs(f['segs'], ignore_static=True))
    if v in DELETE_VERBS:
        return 'delete', ['路径末段删除动作=%s' % v]
    if v in UPDATE_VERBS:
        return 'update', ['路径末段修改动作=%s' % v]
    if v in READ_VERBS:
        return 'read', ['路径末段查询动作=%s' % v]
    if v in CREATE_VERBS:
        if _has_existing_ref(f):
            return 'update', ['新建类动词但携带目标资源标识→实为修改']
        return 'create', ['路径末段新建动作=%s' % v]
    # 软删除判定：只有在【没有明确读动词】时才成立。
    # /user/list {"status":"deleted"} 是「筛出已删除的列表」——读语义，不能拦；
    # /order {"status":"deleted"} 则是「把订单标记为已删除」——写语义，要拦。
    v_pre = _pick_verb(_last_verbs(f['segs']))
    ds = _has_delete_state(f)
    if ds and v_pre not in READ_VERBS and not _is_query_payload(f):
        return 'delete', ['载荷声明将状态置为已删除：%s' % ds]
    if _is_query_payload(f):
        return 'read', ['载荷为分页/过滤查询']
    if _has_existing_ref(f):
        return 'update', ['携带目标资源标识→修改已存在资源']
    return 'create', ['未见修改标识→按新建处理']


# ======================================================================
# 六、效果识别
# ======================================================================
def scope_label(host):
    """主机是否在历史白名单内 —— 仅用于审计标注，不参与拦截决策。

    全站审计模式下，每个请求都会记录 scope=whitelist / scope=other，
    便于事后统计「有多少测试打在了原白名单之外」。
    """
    h = (host or '').lower().split(':')[0]
    if not h:
        return 'unknown'
    if h in ('127.0.0.1', 'localhost', '::1') or h.startswith('127.'):
        return 'loopback'
    if h in tuple(x.lower() for x in CFG['out_of_scope']):
        return 'other'
    for s in CFG['scope_suffix']:
        s = s.lower()
        if h == s.lstrip('.') or h.endswith(s):
            return 'whitelist'
    return 'other'


def in_scope(host):
    """是否属于「受审计范围」。

    2026-10-26：全站审计模式（默认）下恒为 True —— 所有网站都受同一套
    语义规则审计与拦截，不再因主机不在白名单而被 403。
    需要恢复旧白名单行为时，把 CFG['scope_mode'] 设为 'list'。
    """
    if CFG.get('scope_mode', 'all') == 'all':
        return True
    h = (host or '').lower().split(':')[0]
    if h in tuple(x.lower() for x in CFG['out_of_scope']):
        return False
    for s in CFG['scope_suffix']:
        s = s.lower()
        if h == s.lstrip('.') or h.endswith(s):
            return True
    return False


_ABS_PATH_RE = re.compile(
    r'^s*(?:[a-z]:[\\/]|/(?:etc|proc|root|home|var|usr|boot|sys|opt|tmp|srv|windows|'
    r'web-inf|meta-inf|.git|.env|.ssh)[/\\]|../|\.\.\\)', re.I)


def _looks_like_filepath(v):
    """值本身是否像一个服务器绝对路径/穿越路径（与参数名无关）。

    这是「解析值」而不是「匹配关键词」：只要值在结构上是文件路径，
    不管参数叫 f 还是 file 还是 filename，都应当按文件路径检查。
    """
    if not isinstance(v, str):
        return False
    s = _decode_deep(v).strip()
    if not s or len(s) > 400:
        return False
    return bool(_ABS_PATH_RE.match(s)) or '..%2f' in v.lower() or '../' in s


def _sensitive_candidates(f):
    """抽取所有「可能是文件路径」的值：URL 路径 + 文件类参数值 + 值形态像路径的参数。"""
    out = [('path', f['path'])]
    for k, v in _all_key_pairs(f):
        if not isinstance(v, str) or not v.strip():
            continue
        # 2026-10-26 补漏拦：file:// / gopher:// / dict:// 这类「协议包裹的路径」。
        # 实测漏拦：POST /api/download {"url":"file:///etc/passwd"} → 放行
        # 这类是本地文件读取/协议走私的典型写法，必须把内层路径拆出来再判。
        _m = re.match(r'^(?:file|gopher|dict|ldap|jar|netdoc|phar|php|zip|compress\.zlib)://+(.*)$', v.strip(), re.I)
        if _m:
            out.append((k + '(scheme)', normalize_path(_m.group(1))))
            continue
        nk = _nkey(k)
        if nk in FILE_KEYS_N or _looks_like_filepath(v):
            out.append((k, normalize_path(v)))
    return out


# 「公开途径可得的文件」：这些是站点正常对外提供的静态资源，任何人都能拿到，
# 不构成「利用漏洞获取源码」。典型：/static/app.js、/assets/*.css、favicon.ico。
PUBLIC_ASSET_SEGMENTS = frozenset('''
static assets asset public dist build bundles bundle vendor vendors libs lib
css js images image img fonts font media uploads uploads-files files
'''.split())

# 「必须通过漏洞才能拿到的」：配置、版本库、容器描述符、构建残留、备份。
# 这些即便挂在静态目录下，也属于敏感信息泄露（规则 7）。
LEAK_ONLY_MARKERS = (
    '.git/', '.svn/', '.hg/', '.ds_store', '.bzr/',
    'web-inf', 'meta-inf', '.env', 'web.config', 'appsettings',
    'config.php', 'config.json', 'config.yaml', 'config.yml',
    '.yml.bak', '.sql', '.bak', '.old', '.orig', '.swp', '~',
    'phpinfo', '.idea/', '.vscode/', 'composer.json', 'package.json',
    'dockerfile', 'docker-compose', '.dockerenv', '.htaccess', '.htpasswd',
    'web.xml', 'spring.xml', 'log4j', 'application.properties',
)


def _in_public_asset_dir(f):
    """路径是否落在公开静态资源目录下（site 正常对外提供的资源）。"""
    for seg in (f['segs'] or [])[:-1]:
        if seg.lower() in PUBLIC_ASSET_SEGMENTS:
            return True
    return False


def find_sensitive(f):
    """判定是否在「通过漏洞获取源码/敏感文件」。

    用户口径：
      · 公开途径拿到的源码（正常加载的 JS/CSS、公开静态文件）→ 不拦
      · 通过漏洞去获取源码/配置 → 拦（规则 7）

    因此判据是【文件性质】而不是【是否含源码字样】：
      · 配置/版本库/容器描述符/备份残留 → 无论在哪都拦（只能靠漏洞拿到）
      · 系统敏感文件（/etc/passwd 等）→ 拦
      · 普通业务源码（/static/app.js）→ 公开资产目录下放行
    """
    for src, val in _sensitive_candidates(f):
        low = (val or '').lower()
        if not low:
            continue
        # 无危害取证白名单
        if any(a in low for a in ALLOWED_READ):
            continue
        # 系统级敏感文件：任何情况都拦
        for m in SENSITIVE_MARKERS:
            if m in low:
                # 如果只是公开目录下的普通脚本，不因 SENSITIVE_MARKERS 误拦（本就不含）
                return '敏感/源码文件 %s（%s）' % (m, src)
        # 只能靠漏洞拿到的配置/版本库/备份
        for m in LEAK_ONLY_MARKERS:
            if m in low:
                return '仅能通过漏洞获取的文件 %s（%s）' % (m, src)
    return None


def _has_static_ext(path):
    return (path or '').lower().rsplit('/', 1)[-1].endswith(STATIC_EXT)


def is_passive_static(f):
    """页面被动加载的静态资源：属正常浏览，豁免范围检查。

    但必须「确实像静态资源」——含敏感特征或带文件路径参数的，不豁免。
    """
    if f['method'] not in ('GET', 'HEAD', 'OPTIONS'):
        return False
    if not _has_static_ext(f['path']):
        return False
    if find_sensitive(f):
        return False
    for k, v in _all_key_pairs(f):
        nk = _nkey(k)
        if nk in FILE_KEYS_N:
            return False
        # 即便参数名不显眼（f/p/u…），值像文件路径也不应视为被动静态资源
        if _looks_like_filepath(v):
            return False
    return True


def _exec_ext_of(name):
    """文件名里是否含可解析扩展名（含 x.php.jpg 这类绕过）。返回扩展名或 None。"""
    low = _decode_deep(name or '').lower().strip().strip('"\' ')
    low = low.replace('%00', '\x00').split('\x00')[0]
    for ext in EXEC_EXT:
        if low.endswith(ext) or (ext + '.') in low or ext in low:
            return ext
    return None


def find_exec_upload(f):
    """可解析文件上传判定（2026-10-25 用户口径）。

    旧逻辑：只要文件名是 .php/.jsp 就拦 —— 这会把「上传安全验证载荷证明漏洞存在」
    这种正当 PoC 也挡掉，而 PoC 恰恰是 SRC 测试的必需环节。
    新逻辑：先看是不是可解析扩展名；是的话再【看内容】：
      · 只输出固定标记（safetest_pwn）→ 放行，属无害验证
      · 含命令执行/反弹/写入/反连/混淆   → 拦截，属真后门
    """
    names = []
    form = f['form']
    if isinstance(form, dict) and form.get('_is_multipart'):
        names += list(form.get('filenames') or [])
    for k, v in _all_key_pairs(f):
        t = set(_ntokens(k))
        if t & {'file', 'filename', 'name', 'attach', 'attachment'} and isinstance(v, str):
            names.append(v)
    # 2026-10-26 修误拦：GET/HEAD 是下载，不存在「上传可执行文件」。
    # 实测误拦：GET /download?file=zuhaowan_online_new.exe（下载安装包）
    # 下载场景只拦「服务端源码/配置」类后缀（属规则7源码泄露），不拦 .exe/.dll 这类二进制。
    if str(f['method']).upper() in ('GET', 'HEAD', 'OPTIONS'):
        _SRC_EXT = ('.php', '.php3', '.php4', '.php5', '.phtml', '.pht', '.jsp', '.jspx',
                    '.jspf', '.asp', '.aspx', '.ashx', '.asmx', '.config', '.inc',
                    '.class', '.java', '.py', '.rb', '.go', '.sql', '.bak', '.dtd')
        for n in names:
            ext = _exec_ext_of(n)
            if ext and ext in _SRC_EXT:
                return '下载服务端源码/配置文件 %s（文件名=%s）' % (ext, str(n)[:60])
        return None

    for n in names:
        # 2026-10-26 新增：危险配置文件（上传后可改写服务器解析/路由行为，规则 3/7）
        _base = str(n).lower().replace('\\', '/').rsplit('/', 1)[-1].strip()
        if _base in DANGEROUS_UPLOAD_NAMES or _base.startswith('.user.ini'):
            return '危险配置文件上传（文件名=%s）：可改写服务器解析行为' % str(n)[:60]
        ext = _exec_ext_of(n)
        if not ext:
            continue
        ok, why = check_upload_content(f['body_raw'])
        if ok:
            # 安全验证载荷：记录但放行
            return None
        return '%s（文件名=%s，内容特征：%s）' % (ext, str(n)[:60], why)
    # 2026-10-26 新增：非可解析后缀（zip/图片/文档）里藏可执行代码也要拦。
    # 实测漏拦：上传 a.zip，内容含 <?php system(...) ?>（部分应用会自动解压到 webroot）。
    if names:
        _raw = f['body_raw'] or ''
        if re.search(r'<\?(?:php|=)|<%|<jsp:|<\?xml[^>]*\?>\s*<\?php', _raw, re.I):
            _code = _strip_code_noise(_raw)
            for _pat, _nm in DANGEROUS_CODE:
                if re.search(_pat, _code, re.I):
                    return '文件内隐藏可执行代码（%s，文件名=%s）' % (_nm, str(names[0])[:50])
    return None


def find_privesc(f):
    """提权 / 内网横向命令（规则 7）。内容匹配在此是正确做法：识别的是命令本身。"""
    blob = _content_blob(f)
    for pat, name in PRIVESC_PATTERNS:
        if re.search(pat, blob, re.I):
            return name
    return None


def find_bulk_action(f):
    """群发/广播类接口（规则 8：禁止批量操作影响厂商业务）。

    实测漏拦：POST /api/message/sendAll {"content":"hi"}
    这类接口一次调用就影响全部用户，属规则 8 明令禁止。
    """
    toks = set()
    for seg in (f['segs'] or []):
        ts = _ntokens(seg)
        toks.update(ts)
        toks.add(''.join(ts))
    hit = toks & BULK_ACTION_TOKENS
    if hit:
        return '群发/广播接口 %s（一次调用影响全部用户）' % sorted(hit)[0]
    return None


def find_priv_change(f):
    """角色/权限变更（规则 7 提权）。

    实测漏拦：POST /api/role/assign {"userId":1,"roleId":1}
    判据：路径含授权类动词 + body 出现角色/权限字段 → 权限变更。
    """
    verbs = {'assign', 'grant', 'authorize', 'empower', 'grantrole', 'assignrole',
             'setrole', 'addrole', 'bindrole'}
    segtoks = set()
    for seg in (f['segs'] or []):
        segtoks.update(_ntokens(seg))
    hitv = segtoks & verbs
    if not hitv:
        return None
    bodytoks = set()
    for k, _v in _all_key_pairs(f):
        bodytoks.update(_ntokens(k))
    hitk = bodytoks & PRIV_CHANGE_KEYS
    if hitk:
        return '角色/权限变更 %s（字段=%s）' % (sorted(hitv)[0], sorted(hitk)[0])
    return None


def find_ssrf(f):
    for k, v in _all_key_pairs(f):
        if _nkey(k) not in URL_KEYS_N or not isinstance(v, str) or not v.strip():
            continue
        vv = _decode_deep(v)
        try:
            p = urllib.parse.urlparse(vv)
            host = (p.hostname or '').lower()
        except Exception:
            host = ''
        if not host:
            host = vv.split('/')[0].split(':')[0].lower()
        if INTERNAL_IP_RE.search(host) or INTERNAL_HOST_RE.match(host or ''):
            return '%s=%s' % (k, vv[:60])
    return None


def find_dos(f):
    """检测可能影响业务可用性 / 导致 DDoS 的请求（2026-10-29 强化）。

    事故背景：测 linkAnalyze 响应大小限制时，2 MB 文本请求把后端 Python
    线程池占满，该接口 POST 挂起 20+ 分钟仍未恢复。用户明确要求：
    「如果可能会影响业务导致 DDOS 的，也进行拦截」。

    判定原则：不看发了几次，看「单次请求是否可能让服务端长时间占用资源」。
    """
    blob = f['raw_path']
    for _k, _vs in f['query'].items():
        for _v in _vs:
            blob += ' %s=%s' % (_k, _v)
    if f['body_raw']:
        blob += ' ' + f['body_raw']
    try:
        blob = urllib.parse.unquote(blob)
    except Exception:
        pass

    _body_lim = CFG.get('dos_body_max', 100 * 1024)
    _slow_max = CFG.get('dos_slow_max', 8)

    # ① 大载荷：请求体超过阈值（原实现 1 MB 太宽松，2 MB 请求已能压垮服务）
    if f['body_raw']:
        _blen = len(f['body_raw'].encode('utf-8', 'ignore'))
        if _blen > _body_lim:
            return '请求体 %d 字节 > %d 字节上限（大载荷易致服务端解析超时/线程池耗尽）' % (_blen, _body_lim)

    # ② 长等待：sleep/waitfor 类
    for m in SLEEP_RE.finditer(blob):
        try:
            _sec = int(m.group(1))
            if _sec >= _slow_max:
                return 'sleep(%d) >= %d 秒（人为拖长服务端处理时间）' % (_sec, _slow_max)
        except Exception:
            pass

    # ③ 参数名裸露的 DoS 意图
    for k, v in _all_key_pairs(f):
        nk = _nkey(k)
        try:
            n = int(str(v).strip())
        except Exception:
            continue
        if nk in ('delay', 'delayms', 'wait', 'waitms', 'timeout', 'sleep', 'sleepms'):
            if n >= _slow_max * 1000:
                return '参数 %s=%d 毫秒（超长等待）' % (k, n)
        elif nk in ('threads', 'concurrency', 'workers', 'parallel', 'connections'):
            if n >= 50:
                return '参数 %s=%d（高并发，易致连接池耗尽）' % (k, n)
        elif nk in ('repeat', 'loop', 'times', 'iterations', 'retry', 'retries', 'rounds'):
            if n >= 100:
                return '参数 %s=%d（重复执行，易致资源累积）' % (k, n)
    # ④ 分页参数超限（拖库/大规模遍历）
    #
    # 2026-11-06 Lead 修正误拦：原实现用 `t & PAGE_TOKENS`，而 PAGE_TOKENS 包含 'page' /​'size' 等宽泛词，
    # _ntokens('pageId') 会被 camelCase 拆成 ['page','id'] 命中 'page'→把欄目ID当成分页条数。
    # 实测误拦：浙江政务汉王 CMS 的 /front/page/build/unit?pageId=1229820247
    #        （pageId 是固定的欄目ID，不是分页大小）被判为「分页参数 1229820247 > 1000」直接 403。
    # 修正策略：只认「显式表示拉取条数」的键名；带 id/code/no/name/type/key/uuid/column/channel 等标识语义的键一律豁免。
    _ID_TAIL = ('id', 'code', 'no', 'name', 'type', 'key', 'uuid', 'column', 'channel',
                'parent', 'catalog', 'category', 'classify', 'tag', 'group', 'node', 'menu')
    for k, v in _all_key_pairs(f):
        t = set(_ntokens(k))
        if not (t & PAGE_TOKENS) or not isinstance(v, (int, str)):
            continue
        # 豁免标识类键：键名本身就是 xxxId / xxxCode / columnId 这种“标识”语义
        _kl = str(k or '').lower()
        if any(_kl.endswith(_t) for _t in _ID_TAIL):
            continue
        # 豁免明确的欄目/分类词干
        if any(_w in _kl for _w in ('column', 'catalog', 'category', 'classify', 'channel')):
            continue
        try:
            n = int(str(v).strip())
        except Exception:
            continue
        if n > CFG['bulk_max']:
            return '分页参数 %s=%d > %d' % (k, n, CFG['bulk_max'])

    # ⑤ 解析炸弹特征：超深嵌套 / 超多元素（billion laughs、递归展开、zip bomb 同源）
    _raw = f['body_raw'] or ''
    if _raw and (_raw.count('[') + _raw.count('{')) > 500:
        return 'JSON 嵌套/元素数 > 500（易触发解析器递归耗尽）'

    return None


def find_bulk_write(f):
    for k, v in _all_key_pairs(f):
        if isinstance(v, list) and len(v) > CFG['bulk_write_max'] and v and isinstance(v[0], dict):
            return '%s 数组 %d 个对象' % (k, len(v))
    b = f['body']
    if isinstance(b, list) and len(b) > CFG['bulk_write_max'] and b and isinstance(b[0], dict):
        return '顶层数组 %d 个对象' % len(b)
    return None


# ===== 敏感数据批量导出（规则 2 禁止拖库 / 规则 6 禁止大规模遍历用户信息）=====
# 2026-10-25 监控发现：actuator/heapdump、druid、nacos、exportAllUsers 这类接口
# 一旦被利用就是「把整台机器内存 / 全量用户数据拖走」，属规则 2、6 明确禁止。
#
# 关键区分（用户口径：探测不算违规，真实利用漏洞的违规操作才拦）：
#   · 探测存在性 /actuator/env、/actuator、/druid/index.html → 放行（只是看有没有）
#   · 实际拉取全量数据 /actuator/heapdump、/actuator/configprops → 拦截（数据真的被下载）
#
# 判据是【接口语义】：该端点返回的是「整份数据的转储」而不是「一条/一页记录」。
# 这是端点性质的判断，不是关键词命中。

# 一旦请求即等于「全量数据落到本地」的端点（转储类）
DUMP_ENDPOINTS = (
    (r'/actuator/heapdump(?:[/?;]|$)', 'JVM 堆转储（含内存中全部凭据/会话/业务数据）'),
    (r'/actuator/threaddump(?:[/?;]|$)', '线程转储'),
    (r'/actuator/configprops(?:[/?;]|$)', '全部配置项（可能含数据库口令）'),
    (r'/actuator/env(?:[/?;]|$)', '环境变量（可能含密钥）'),
    (r'/actuator/mappings(?:[/?;]|$)', '全部路由映射'),
    (r'/actuator/beans(?:[/?;]|$)', '全部 Bean 定义'),
    (r'/actuator/loggers(?:[/?;]|$)', '日志配置'),
    (r'/druid/(?:index|sql|websession)\.html', 'Druid 监控台（含 SQL 与连接信息）'),
    (r'/nacos/v1/(?:cs|ns)/configs', 'Nacos 配置拉取'),
)
# API 文档（swagger/openapi）不列入阻断：它只描述接口结构，不含用户数据，
# 属「探测」而非「拖库」。按用户口径（合理探测不拦）降级为审计记录。
API_DOC_ENDPOINTS = (
    (r'/(?:v2|v3)/api-docs(?:-ext)?(?:[/?;]|$)', 'API 文档'),
    (r'/swagger(?:-ui)?(?:/|\.html|\?|$)', 'Swagger UI'),
    (r'/openapi\.json(?:[/?;]|$)', 'OpenAPI 描述'),
    (r'/doc\.html(?:[/?;]|$)', '接口文档'),
)

# 「全量导出」类动词：导出的是整个数据集，不是单条记录
BULK_EXPORT_VERBS = frozenset('''
exportall exportalluser exportallusers exportallorder exportallcustomer
dump dumpall dumpdb backup dbbackup downloadall dumpdata exportdata
fullbackup fullexport allusers allorders alldata
'''.split())


def find_mass_export(f):
    """判定是否属「敏感数据批量导出/转储」（规则 2 拖库、规则 6 大规模遍历）。

    只看两件事：
      1) 路径是不是「转储类端点」（请求即得整份数据）
      2) 路径末段是不是「全量导出」语义
    普通探测（/actuator/env 只是看一眼配置、/admin/ 只是探路）不在此列。
    """
    path = (f['path'] or '').lower()
    for pat, name in DUMP_ENDPOINTS:
        if re.search(pat, path):
            return '%s 端点（%s）' % (name, par_tail(path))
    # 全量导出语义：
    #   (a) 单段内整体词 exportAllUsers / dumpAll
    #   (b) 跨段组合 /api/export/all/users —— 把连续几段的 token 拼起来看
    _EXPORT_HEAD = ('export', 'dump', 'download', 'backup')
    segs = f['segs'] or []
    for seg in segs:
        toks = _ntokens(seg)
        if not toks:
            continue
        joined = ''.join(toks)
        if joined in BULK_EXPORT_VERBS:
            return '全量导出接口（%s）' % joined
        if len(toks) >= 3 and toks[0] in _EXPORT_HEAD and 'all' in toks:
            return '全量导出接口（%s）' % '-'.join(toks)
    # (b) 跨段：全部 token 连起来判断 export+all+数据实体
    alltoks = []
    for seg in segs:
        alltoks += _ntokens(seg)
    for i, t in enumerate(alltoks):
        if t not in _EXPORT_HEAD:
            continue
        win = alltoks[i:i + 4]
        if 'all' in win and len(win) >= 3:
            return '全量导出接口（%s）' % '-'.join(win[:4])
    # (c) 2026-10-26 新增：末段直接是 export/dump/backup，且没有指定单条数据
    #     → 请求即得全量。实测漏拦：GET /api/user/export（无任何参数）。
    if segs:
        _last = _nkey(segs[-1])
        if _last in ('export', 'dump', 'backup', 'exportall', 'dumpall',
                     'downloadall', 'outport', 'derive'):
            # 2026-10-26 策略权衡：导出接口是「拖库」的主要载体，但探测导出接口本身
            # 属正常安全测试（用户口径：误拦=正常测试被拦）。
            # 因此只拦【完全没有任何参数】的真·一键全量导出；
            # 带任何筛选/分页/定位参数的放行 —— 返回体量另由 find_dos（分页上限）把关。
            _pairs = list(_all_key_pairs(f))
            if not _pairs:
                return '导出接口 /%s（无任何筛选/分页参数，请求即得全量）' % segs[-1]
    # (d) 2026-10-26 新增：GraphQL / JSON 里的批量取数参数
    _blob = _content_blob(f)
    _mm = re.search(r'\b(?:first|last|limit|take|pagesize|size|count)\s*[:=]\s*(\d{3,})', _blob, re.I)
    if _mm:
        try:
            if int(_mm.group(1)) > int(CFG.get('bulk_max', 1000)):
                return '批量取数参数 %s' % _mm.group(0).strip()[:30]
        except Exception:
            pass
    return None


def par_tail(path):
    segs = [x for x in (path or '').split('/') if x]
    return '/'.join(segs[-2:]) if segs else ''


def find_api_doc(f):
    """API 文档访问（swagger/openapi）——只记录不拦。

    这类端点返回的是「接口长什么样」，不含真实用户数据，属渗透测试的常规探测手段。
    用户口径：合理探测不拦；真正要拦的是把数据拉走。
    """
    path = (f['path'] or '').lower()
    for pat, name in API_DOC_ENDPOINTS:
        if re.search(pat, path):
            return '%s（%s）' % (name, par_tail(path))
    return None


def find_delete_markers(f, op):
    """body 里的删除标记。只在【写】语义下成立——
    读语义下 status=deleted 是列表筛选条件，不是删除动作（这正是旧版误拦点）。
    """
    if op in ('read',):
        return None
    for k, v in _all_key_pairs(f):
        nk = _nkey(k)
        if nk in DELETE_FLAG_KEYS:
            # 删除标记用独立判定：布尔 true / 数字>0 / 字符串 true|1|yes 都算「已声明删除」。
            # 注意这里不能用 _truthy_ref —— 那是给「资源 ID 引用」用的，布尔 true 会被当成非引用。
            if isinstance(v, bool):
                if v:
                    return '%s=true' % k
            elif isinstance(v, (int, float)):
                if v > 0:
                    return '%s=%s' % (k, v)
            elif str(v).strip().lower() in ('true', '1', 'yes', 'y', 'on'):
                return '%s=%s' % (k, v)
        if nk in STATUS_KEYS and str(v).strip().lower() in DELETED_VALUES:
            return '%s=%s' % (k, v)
    return None


def _content_blob(f):
    # 用解码后的 query 值拼装：urlencode 会把 / 再编码成 %2F，导致 rm -rf / 这类载荷识别失败。
    # 这里统一做多轮解码，把 %2520 之类的二次编码也还原（识别载荷必须看到真实字符）。
    blob = f['raw_path'] or ''
    for _k, _vs in f['query'].items():
        for _v in _vs:
            blob += ' %s=%s' % (_k, _v)
    if f['body_raw']:
        blob += ' ' + f['body_raw']
    try:
        blob = _decode_deep(blob, rounds=2)
        return blob.replace('+', ' ')
    except Exception:
        return blob


def find_attack_payload(f):
    """攻击载荷识别（内容匹配在这里是【正确】做法：我们在识别 payload，不是在猜意图）。"""
    blob = _content_blob(f)
    low = blob.lower()
    for pat, name in SQLI_PATTERNS:
        if re.search(pat, low):
            return '破坏性 SQL 载荷 %s' % name
    for pat, name in RCE_PATTERNS:
        if re.search(pat, blob, re.I):
            return '破坏性系统命令 %s' % name
    return None


# ======================================================================
# 七、策略层：效果 → 《测试注意事项和禁止行为》
# ======================================================================
REASONS = {
    'out_of_scope':   '【规则9】范围外主机 %s（禁止测试范围外系统）',
    'delete':         '【规则3/5】删除现有数据：%s',
    'replace':        '【规则3/5】覆盖现有数据：%s',
    'update':         '【规则5】修改现有数据：%s',
    'bulk_read':      '【规则2/6】大规模拉取：%s（禁止拖库/遍历用户信息）',
    'bulk_write':     '【规则8】批量操作：%s（禁止测试批量操作）',
    'dos':            '【规则2】影响服务稳定性：%s',
    'exec_upload':    '【规则7】上传可执行文件：%s（禁止上传恶意代码/后门）',
    'sensitive':      '【规则7】读取源码/敏感文件：%s',
    'ssrf':           '【规则7】内网探测：%s（禁止提权与内网横向）',
    'attack_payload': '【规则2/3】%s',
    'delete_marker':  '【规则5】请求体声明删除：%s',
    'mass_export':    '【规则2/6】敏感数据批量导出：%s（禁止拖库、禁止大规模遍历用户信息）',
    'rate_limit':     '【规则2/4】%s（禁止高并发扫描、禁止影响服务稳定性）',
    'privesc':        '【规则7】提权/内网横向：%s（禁止提权与内网横向）',
}


# 2026-11-02：最近一次 classify 的破坏性载荷线索（payload_signal/mutation_signal），
# 供 guard.py 的交叉校验读取 —— det 识别出破坏性载荷时不得否决 Jev 的删改结论。
_LAST_SIGNALS_TLS = threading.local()


def last_destructive_signal():
    """返回最近一次 classify 识别到的破坏性载荷描述（无则 None）。线程级隔离。"""
    return getattr(_LAST_SIGNALS_TLS, 'sig', None)


def classify(f):
    """Facts → (阻断效果列表, 审计提示列表, op, 依据)

    阻断效果 eff：命中《禁止行为》必须拦下的。
    审计提示 notices：记录了但不拦（如 SSRF 探测、公开源码）。用户要求：
      · SSRF 合理探测不拦
      · 公开途径的源码不拦
      · 只有真实利用漏洞的违规操作 + 删除修改才拦
    """
    eff = []
    notices = []

    # 1) 授权范围（规则 9）
    #    2026-10-26 起为「全站审计」模式：所有网站都审计 + 按同一套语义规则拦截，
    #    白名单只用于在审计日志里标注 scope=whitelist/other，不再作为拦截理由。
    if CFG.get('scope_mode', 'all') != 'all':
        if f['host'] and not in_scope(f['host']) and f['host'] not in ('127.0.0.1', 'localhost'):
            if not is_passive_static(f):
                eff.append(('out_of_scope', f['host']))
    else:
        if f['host'] and scope_label(f['host']) == 'other':
            notices.append(('audited_unlisted_host', f['host']))

    # 2) 操作语义（规则 3/5）——结构性判定
    op, why = resolve_op(f)
    if op == 'delete':
        eff.append(('delete', '；'.join(why)))
    elif op in ('update', 'replace'):
        eff.append((op, '；'.join(why)))

    # 3) body 删除标记（读语义下不算）
    dm = find_delete_markers(f, op)
    if dm:
        eff.append(('delete_marker', dm))

    # 4) 敏感文件（规则 7）——路径归一化后比对
    sen = find_sensitive(f)
    if sen:
        eff.append(('sensitive', sen))

    # 5) 可执行文件上传（规则 7）
    up = find_exec_upload(f)
    if up:
        eff.append(('exec_upload', up))

    # 6) SSRF：**不拦截**
    #    用户明确：「ssrf 的合理探测也不用拦得太死」。SSRF 探测（指向云元数据、
    #    内网端口）是验证漏洞存在的标准手法，属授权范围内的合法测试行为。
    #    真正该拦的是「利用 SSRF 去打内网做实际破坏/横向」——那属于删除修改与
    #    破坏性操作，由 delete/update/attack_payload 等效果另行捕获。
    #    因此这里只产出审计提示，不产生阻断。
    ss = find_ssrf(f)
    if ss:
        notices.append(('ssrf_probe', ss))

    # 7) 批量（规则 2/6/8）——按数量，不按词
    dos = find_dos(f)
    if dos:
        eff.append(('dos', dos))
    bw = find_bulk_write(f)
    if bw:
        eff.append(('bulk_write', bw))

    # 8) 载荷特征 —— 2026-10-26 用户口径：不用正则做拦截判定，
    #    只作为【语义描述的一部分】喂给 Jev，由模型判断是否属删除/修改或 RCE 利用。
    ap = find_attack_payload(f)
    if ap:
        notices.append(('payload_signal', ap))
    _ms = mutation_signal(f)
    if _ms:
        notices.append(('mutation_signal', _ms))

    # 8b) 提权/横向命令 —— 同上，正则只作语义线索，由 Jev 判定是否属 RCE 利用
    pv = find_privesc(f)
    if pv:
        notices.append(('privesc_signal', pv))
    # 8c) 群发/广播接口（规则 8）
    ba = find_bulk_action(f)
    if ba:
        eff.append(('bulk_write', ba))
    # 8d) 角色/权限变更（规则 7 提权）
    pc = find_priv_change(f)
    if pc:
        eff.append(('privesc', pc))

    # 9) 敏感数据批量导出（规则 2 拖库 / 规则 6 大规模遍历）
    #    注意：只拦「转储/全量导出」类端点，普通探测（/admin/、/actuator 根路径）不在此列。
    me = find_mass_export(f)
    if me:
        eff.append(('mass_export', me))

    # 10) API 文档：只记录不拦（探测性质，不含用户数据）
    ad = find_api_doc(f)
    if ad:
        notices.append(('api_doc', ad))

    # 11) 高并发/自动化扫描限速（规则 2 / 规则 4）
    #     只在「没有任何明确违规」时兜底触发，避免把被拦的请求也算进令牌桶。
    if not eff:
        rl = rate_check(f['host'], f['path'], f['method'])
        if rl:
            eff.append(('rate_limit', rl))

    # 2026-11-02：把本次 classify 识别出的「破坏性载荷线索」暴露给 guard.py 的
    # 交叉校验 —— det 内容特征与 Jev 语义两个独立信号同时指向破坏性时，
    # 否决不生效（dml 口径应拦的删除/修改，不属模型噪声）。
    _LAST_SIGNALS_TLS.sig = [n[1] for n in notices
                             if n[0] in ('payload_signal', 'mutation_signal')]
    return eff, notices, op, why


_PRIORITY = ['out_of_scope', 'sensitive', 'exec_upload', 'ssrf', 'delete', 'replace',
             'update', 'delete_marker', 'mass_export', 'bulk_write', 'bulk_read', 'dos',
             'attack_payload', 'privesc', 'rate_limit']


# dml 模式下仍然拦截的效果 —— 只有「删除/修改」与「RCE 利用」
DML_BLOCK_EFFECTS = frozenset('''
delete replace update delete_marker privesc attack_payload dos
'''.split())
# 2026-10-29 用户要求：可能影响业务、导致 DDoS/服务不可用的操作必须拦截。
# 事故：测 linkAnalyze 响应大小限制时 2 MB 请求体把后端 Python 线程池占满，
#       该接口 POST 挂起 20+ 分钟。此前 dos 在 dml 模式只审计不拦，属放行口子。


def _has_id_field(f):
    """载荷里是否有 id 类字段（用于判断数组是「批量修改」还是「批量新建」）。"""
    for k, _v in _all_key_pairs(f):
        nk = _nkey(k)
        if nk == 'id' or nk.endswith('id') or nk in ('ids', 'pk', 'uuid'):
            return True
    return False


def filter_effects(f, eff, notices):
    """按 policy 过滤「哪些效果才真正拦截」，其余降级为审计提示。

    dml 模式（用户 2026-10-26 口径）：
        拦：删除、修改/覆盖、软删除标记、提权、RCE 利用、SQL 删改语句
        放：上传可执行文件、基础 RCE 命令(id/whoami/读文件)、拖库/大规模遍历、
            敏感文件读取、范围外主机、限速
        拦（2026-10-29 起）：DoS / 可能影响业务可用性的大载荷、长等待、高并发、深递归
    """
    mode = str(CFG.get('policy') or 'strict').lower()
    if mode != 'dml':
        return eff, notices
    keep = []
    for name, detail in eff:
        if name in DML_BLOCK_EFFECTS:
            keep.append((name, detail))
            continue
        if name == 'bulk_write':
            # 批量「修改」要拦（数组里带 id），批量「新建」放行
            if _has_id_field(f):
                keep.append((name, detail))
            else:
                notices.append(('audit_bulk_create', detail))
            continue
        notices.append(('audit_' + name, detail))
    return keep, notices


def policy(f, eff, notices=None):
    notices = notices or []
    eff, notices = filter_effects(f, eff, notices)
    if not eff:
        base = '只读/新建，未命中禁止行为'
        if notices:
            base += '｜审计：' + '；'.join('%s(%s)' % (n, d) for n, d in notices[:2])
        return True, [base]
    eff.sort(key=lambda x: _PRIORITY.index(x[0]) if x[0] in _PRIORITY else 99)
    reasons, seen = [], set()
    for name, detail in eff:
        tpl = REASONS.get(name)
        r = (tpl % (detail,)) if tpl else ('%s：%s' % (name, detail))
        if r in seen:
            continue
        seen.add(r)
        reasons.append(r)
    return False, reasons[:5]


# ======================================================================
# 八、对外接口
# ======================================================================
def evaluate(method, url, headers, body):
    f = parse(method, url, headers, body)
    eff, notices, op, why = classify(f)
    return policy(f, eff, notices)


def explain(method, url, headers, body):
    """排查用：把解析结果完整打出来。"""
    f = parse(method, url, headers, body)
    eff, notices, op, why = classify(f)
    allow, reasons = policy(f, eff, notices)
    return {
        'allow': allow,
        'reasons': reasons,
        'op': op,
        'op_evidence': why,
        'effects': eff,
        'notices': notices,
        'facts': {
            'method': f['method'], 'host': f['host'],
            'path_normalized': f['path'], 'segs': f['segs'],
            'query_keys': list(f['query'].keys()),
            'body_kind': f['body_kind'],
            'existing_ref': _has_existing_ref(f),
            'query_payload': _is_query_payload(f),
            'passive_static': is_passive_static(f),
            'last_verb': _last_verb(f['segs']),
            'resource': _resource_name(f['segs']),
        },
    }
