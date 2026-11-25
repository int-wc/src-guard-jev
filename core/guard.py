#!/usr/bin/env python3
# 审计护栏 v3：所有出站请求经此判定；策略与三门专用护栏 extra_guard.py 对齐（2026-10-25）
# 内嵌补天《测试注意事项和禁止行为》：
#   拦截 = 写方法 + 路径/参数/请求体删改语义 + 破坏性SQL + 可解析文件上传(webshell/后门)
#          + 敏感文件/源码读取 + 参数穿越系统路径 + 批量导出(拖库) + 长sleep/超大body(稳定性)
#   放行 = 只读探测/登录/SQLi·SSTI·RCE·SSRF·文件读取PoC(/etc/hostname等白名单)/新建上传/越权读
#   LLM 出口仅审计不拦截；2026-10-26 起默认「全站审计」：所有网站都受本护栏审计，
#   GUARD_SCOPE_MODE=list 可切回仅白名单模式
import http.server, json, re, sys, urllib.parse, urllib.request, urllib.error, datetime, unicodedata, os
BASE=os.environ.get('GUARD_BASE', os.path.dirname(os.path.abspath(__file__)))
AUDIT=BASE+'/audit.log'
JEV_LOG=BASE+'/jev.log'
TS_KEY=os.environ.get('TYPESAFE_API_KEY','')
TS_URL=os.environ.get('TYPESAFE_URL','https://api.typesafe.ai/v1/systemone')
TS_MODEL=os.environ.get('TYPESAFE_MODEL','jev-latest')
TS_PROXY=os.environ.get('TYPESAFE_PROXY','http://127.0.0.1:7892')
TS_NOUL_MAX=float(os.environ.get('TS_NOUL_MAX','0.30'))
TS_MIN_CONF=float(os.environ.get('TS_MIN_CONF','0.60'))
AUDIT_MODE=os.environ.get('AUDIT_MODE','both')
DS_URL=os.environ.get('DS_URL','http://127.0.0.1:8323/v1/chat/completions')
DS_MODEL=os.environ.get('DS_MODEL','deepseek-v4-flash')   # det | jev | both

# 2026-11-02（用户要求：放松 Jev dml 护栏，正常 RCE 放行）
# GUARD_RCE_ENFORCE=0 → Jev 的 rce_exploitation 评分不再单独作为拦截依据（只写审计）；
#   「破坏性/反连类」系统命令仍由规则层 _RCE_RULES 兜底拦截（rm -rf /、反弹 shell、
#   下载执行、写系统目录、关机/重启等）；删除/修改、DoS 拦截不变。
# 默认 1 = 旧口径（RCE 利用评分>0.60 即拦）。
RCE_ENFORCE = os.environ.get('GUARD_RCE_ENFORCE', '1').strip().lower() not in ('0', 'false', 'off', 'no', 'audit', 'audit-only')
# 2026-10-24 Lead 修正：按用户政策「除删除/DDOS 外均可」，POST 恢复为允许方法；
# 删除/修改语义仍由 PATH_WORDS + body_hits + mitm_guard 硬拦截把关。
# 2026-10-25 与 sanmen_guard 对齐：补 MKCOL/LOCK（WebDAV 写）。
WRITE_VERBS={'DELETE','PUT','PATCH','MOVE','PROPPATCH','PURGE','MKCOL','LOCK'}
SAFE={'GET','HEAD','OPTIONS','POST'}
PATH_WORDS=('delete','remove','destroy','purge','drop','truncate','update','modify','rename','wipe','flush','overwrite','replace','edit')
DEL_WORDS=('delete','remove','destroy','purge','drop','truncate','wipe','flush','clear','unlink','erase')
MOD_WORDS=('update','modify','edit','replace','rename','overwrite','disable','restore','revoke','shutdown')

# ===== SRC 硬规则（与 extra_guard.py 同源，2026-10-25）=====
# 破坏性 SQL（匹配未压缩原文，\s+ 分隔）
SQL_DESTRUCTIVE = [
    (r'\bdelete\s+from\b', 'SQL DELETE'),
    (r'\bdrop\s+(table|database|schema|index|view|user)\b', 'SQL DROP'),
    (r'\btruncate\s+table\b', 'SQL TRUNCATE'),
    (r'\bupdate\s+[\w\.\`\[\]"]+\s+set\b', 'SQL UPDATE'),
    (r'\balter\s+table\b', 'SQL ALTER'),
    (r'\binsert\s+into\b', 'SQL INSERT'),
    (r'\bcreate\s+(table|database|user)\b', 'SQL CREATE'),
    (r'\bgrant\s+all\b', 'SQL GRANT'),
]
# 可解析/可执行上传扩展名（禁止 webshell/后门/木马）
EXEC_EXT = ('.php', '.php3', '.php4', '.php5', '.phtml', '.pht', '.jsp', '.jspx', '.jspf',
            '.asp', '.aspx', '.ashx', '.asmx', '.cer', '.exe', '.dll', '.so', '.war',
            '.jar', '.cgi', '.ser', '.dtd', '.hta', '.vbs', '.ps1', '.class')
# 敏感文件/源码（禁止下载读取）——命中即拦
SENSITIVE_FILES = ('/etc/passwd', '/etc/shadow', '/etc/sudoers', 'id_rsa', 'id_dsa',
                   '.ssh/', '.bash_history', 'web-inf/', 'meta-inf/',
                   'application.yml', 'application.properties',
                   'bootstrap.yml', 'bootstrap.properties',
                   '/.env', '.git/config', '/proc/self/', '/proc/1/',
                   '.htpasswd', 'tomcat-users.xml', 'database.php',
                   'settings.py', 'wp-config.php')
# 文件读取取证白名单：/etc/hostname 这类主机标识文件允许（任意文件读取 PoC 标准）
ALLOWED_READ = ('/etc/hostname', '/etc/issue', '/etc/os-release',
                'win.ini', '/etc/host.conf', '/etc/hosts', '/etc/resolv.conf',
                'c:/windows/win.ini')
BULK_MAX = 1000  # 单次拉取条数上限（2026-10-25 优化：200→1000。正常业务分页 size/limit
                 # 常见 500~1000，原阈值把只读翻页误判成拖库）
BULK_PARAMS = ('pagesize', 'page_size', 'size', 'limit', 'count', 'rows',
               'pagecount', 'per_page', 'perpage', 'maxresults', 'top', 'num')
_SLEEP_RE = re.compile(r'\b(?:sleep|pg_sleep|waitfor\s+delay)\s*\(\s*(\d+)', re.I)
_FILE_PARAM_NAMES = ('file', 'filename', 'filepath', 'file_path', 'path', 'pathname',
                     'doc', 'document', 'download', 'read', 'src', 'source',
                     'template', 'tpl', 'load', 'attach', 'attachment', 'include')
_FILE_PARAM_RE = re.compile(
    r'(?:^|[?&;,\s"\'])(%s)\s*[=:]\s*["\']?([^&;,\s"\']{0,300})' % '|'.join(_FILE_PARAM_NAMES),
    re.I)
_SYS_PATH_RE = re.compile(r'(^|[/\\])(etc|proc|root|home|var|usr|boot|sys|opt|windows)([/\\]|$)', re.I)
_WIN_ABS_RE = re.compile(r'^[a-z]:[/\\]', re.I)
# 授权范围（默认空 —— 由 GUARD_SCOPE_SUFFIX 环境变量或外部配置注入）
# 示例: GUARD_SCOPE_SUFFIX=".customer-a.example,.customer-b.example"
SCOPE_SUFFIX = (
)
# 厂商明确不收的资产（默认空，按需用 GUARD_OUT_OF_SCOPE 注入）
OUT_OF_SCOPE_HOSTS = (
)

# 2026-10-26 合并：支持用环境变量覆盖范围清单（另一会话在语义层加的同类能力，
# 但在 guard.py 里 configure() 会用硬编码值把它盖掉，导致环境变量实际不生效）。
# 这里让环境变量优先，两侧保持一致。
def _env_tuple(_name, _default):
    _v = os.environ.get(_name, '').strip()
    if not _v:
        return _default
    return tuple(x.strip() for x in _v.split(',') if x.strip())


SCOPE_SUFFIX = _env_tuple('GUARD_SCOPE_SUFFIX', SCOPE_SUFFIX)
OUT_OF_SCOPE_HOSTS = _env_tuple('GUARD_OUT_OF_SCOPE', OUT_OF_SCOPE_HOSTS)
SCOPE_IP_PREFIX = ()

# ===== 2026-11-20 lead：路径级白名单（用户批准）=====
# 用途：某些端点路径含动作词（change/modify/update）但实际为只读探测，
# 语义层会误判为 update 而拦截。此处按「host+路径前缀」精确放行，仅放行指定端点。
# 格式：host1|/path/prefix1,host2|/path/prefix2
ALLOW_PATH = _env_tuple("GUARD_ALLOW_PATH", ())


def in_allow_path(host, path):
    if not ALLOW_PATH:
        return False
    h = (host or "").lower()
    p = path or ""
    for item in ALLOW_PATH:
        if "|" not in item:
            continue
        ah, ap = item.split("|", 1)
        if h == ah.strip().lower() and p.startswith(ap.strip()):
            return True
    return False

# ===== 2026-10-25 优化：静态资源豁免 + 读方法删除动作 + body 删除语义 =====
# 背景1：页面被动加载的第三方 CDN/统计/验证码脚本命中「范围外主机」被 403，整页打不开。
#        这类资源不是主动探测，豁免范围检查（仍照常写审计日志）。
# 背景2：读方法只扫 DEL_WORDS，漏掉 cancel/del/disable/refund 等真实删除动词。
# 背景3：body 只覆盖 SQL/JSON-Patch/GraphQL，漏掉业务字段形态（status=deleted/isDel/removeIds）。
STATIC_EXT = ('.js', '.mjs', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp',
              '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webmanifest',
              '.wasm', '.br', '.gz')

GET_DEL_VERBS = ('delete', 'del', 'remove', 'destroy', 'purge', 'drop', 'truncate', 'wipe',
                 'clear', 'unlink', 'erase', 'cancel', 'disable', 'refund', 'revoke', 'close')
# 这些动词过于常见，必须连同宾语（order/account/...)一起出现才认，避免 /api/close 类误伤
GET_DEL_STRICT = {
    'cancel': ('order', 'task', 'job', 'subscribe', 'account', 'booking', 'apply', 'ticket'),
    'disable': ('user', 'account', 'member', 'staff', 'employee', 'role'),
    'refund': ('order', 'pay', 'payment', 'bill'),
    'close': ('order', 'account', 'task', 'ticket', 'case'),
}


def _path_segments(path):
    segs = [s for s in re.split(r'[/]', (path or '').lower()) if s]
    while segs and re.fullmatch(r'\d{1,}', segs[-1]):
        segs.pop()
    return segs


def _read_delete_hits(path):
    """读方法删除动作：只认末段（或末段 camelCase 尾词）精确等于删除动词。"""
    segs = _path_segments(path)
    if not segs:
        return []
    last_seg = segs[-1].split(';')[0]
    if '.' in last_seg:
        last_seg = last_seg.rsplit('.', 1)[0]
    toks = [t for t in re.split(r'[^A-Za-z0-9]+', last_seg) if t]
    if not toks:
        return []
    camel = []
    for t in toks:
        camel += [x.lower() for x in re.split(r'(?<=[a-z0-9])(?=[A-Z])', t) if x]
    if not camel:
        return []
    cand = camel[-1]
    ctx = [s.lower() for s in segs] + camel

    def _strict_ok(v):
        need = GET_DEL_STRICT.get(v)
        return True if not need else any(k in ctx for k in need)

    if cand in GET_DEL_VERBS:
        if not _strict_ok(cand):
            return []
        return ['路径结尾为删除动作 %s(禁止删除/修改现有数据)' % cand]
    # 形如 /user/deleteById、/order/cancelOrder
    if len(camel) >= 2 and camel[0] in GET_DEL_VERBS and camel[0] not in GET_DEL_STRICT:
        return ['路径含删除动作 %s(禁止删除/修改现有数据)' % camel[0]]
    return []


_BODY_DEL_STRONG = [
    (r'"deleteaccount"\s*:\s*(?:true|1|"1"|"true")', 'body deleteAccount=true'),
    (r'"(?:action|op|operation|cmd|command)"\s*:\s*"(?:wipe|clear|truncate|drop|purge|destroy|erase)"',
     'body action=销毁类动作'),
    (r'"(?:action|op|operation|cmd|command)"\s*:\s*"(?:delete|remove|del)"', 'body action=删除'),
    # form-urlencoded / query 形态（2026-10-25 优化补充）
    (r'(?:^|[&;?,]){1}(?:action|op|operation|cmd|command)=(?:wipe|clear|truncate|drop|purge|destroy|erase)(?:[&;]|$)',
     '参数 action=销毁类动作'),
    (r'(?:^|[&;?,]){1}(?:action|op|operation|cmd|command)=(?:delete|remove|del)(?:[&;]|$)', '参数 action=删除'),
    (r'(?:^|[?&,\s"])removeids\s*[=:]', 'body removeIds'),
    (r'(?:^|[?&,\s"])(?:del|delete)ids\s*[=:]', 'body deleteIds'),
    (r'(?:^|[?&,\s"])deleteaccount\s*[=:]\s*(?:true|1)', 'body deleteAccount=true'),
]
_BODY_DEL_WRITE = [
    (r'"isdeleted"\s*:\s*(?:true|1|"1"|"true")', 'body isDeleted=true'),
    (r'"(?:isdel|is_del)"\s*:\s*(?:true|1|"1"|"true")', 'body isDel=1'),
    (r'"status"\s*:\s*"deleted"', 'body status=deleted'),
    (r'"deleted"\s*:\s*(?:true|1)', 'body deleted=true'),
]
# body 里出现这些键视为「查询/分页意图」，此时 isDeleted/status=deleted 属筛选条件，不算写入
_QUERY_HINTS = ('"page"', '"pagesize"', '"page_size"', '"size"', '"limit"', '"offset"',
                '"keyword"', '"query"', '"search"', '"filter"', '"orderby"', '"sort"',
                '"starttime"', '"begintime"', '&page=', '&size=')


def _body_delete_hits(body, headers, method):
    b = (body or '')
    if not b:
        return []
    low = b.lower()
    for pat, name in _BODY_DEL_STRONG:
        if re.search(pat, low):
            return ['%s(禁止删除/修改现有数据)' % name]
    if str(method).upper() in ('GET', 'HEAD', 'OPTIONS'):
        return []
    if any(q in low for q in _QUERY_HINTS):
        return []
    for pat, name in _BODY_DEL_WRITE:
        if re.search(pat, low):
            return ['%s(禁止删除/修改现有数据)' % name]
    return []

# ===== T14 (2026-10-25) 新增：SSRF 内网地址 + RCE 破坏性命令 =====
# 说明：这两类此前完全缺失（基线测试 M4~M8 全部被放行），属「该拦却放」。
_SSRF_IP = (r'(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|192\.168\.\d{1,3}\.\d{1,3}'
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
            r'|169\.254\.\d{1,3}\.\d{1,3}'
            r'|100\.100\.100\.200'
            r'|0\.0\.0\.0)')
# 强特征：任意 scheme:// 或 @ 直接连到内网/元数据/本机
_SSRF_STRONG = re.compile(r'(?:[a-z][a-z0-9+.\-]{2,10}://|@)' + _SSRF_IP, re.I)
# 参数特征：url=/uri:/target=... 指向内网
_SSRF_KEY = (r'(?:url|uri|target|dest|destination|redirect|redirect_uri|callback|next|return|'
             r'href|link|src|source|host|hostname|domain|site|fetch|proxy|address|addr|ip|file|path)')
_SSRF_PARAM = re.compile(r'(?:^|[?&,;\s"\x27])' + _SSRF_KEY + r'\s*[=:]\s*["\x27]?' + _SSRF_IP, re.I)
_SSRF_LOCAL = re.compile(r'(?:[a-z][a-z0-9+.\-]{2,10}://|@)(?:localhost|metadata\.google\.internal)\b', re.I)

# RCE/破坏性系统命令：只拦「会造成破坏或反连」的；id/whoami/uname/echo 等无害 PoC 一律放行
_RCE_RULES = [
    (r'\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(?:\s|$|;|&|\*)', 'rm -rf 破坏性删除'),
    (r'\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+/(?:\s|$|;|&|\*)', 'rm -rf 破坏性删除'),
    (r'\bmkfs(?:\.\w+)?\b', 'mkfs 格式化磁盘'),
    (r'\bdd\s+[^|;]{0,60}of\s*=\s*/dev/', 'dd 写块设备'),
    # 2026-10-25 修复：原式要求 shutdown 后跟 -/now/行尾，URL 里 shutdown?cid=xxx 因 '?' 不匹配而漏拦；
    # 同时 raw_text 是「path + '?' + query + ' ' + body」，路径末尾实际是空格，必须一并覆盖。
    (r'\b(?:shutdown|poweroff|halt|reboot)(?=\s|$|[?&;/#])', '关机/重启主机/服务'),
    (r'\bcrontab\s+-(?:r|e)\b', '篡改定时任务'),
    (r'/dev/(?:tcp|udp)/', '反弹 shell(/dev/tcp)'),
    (r'\bnc\s+(?:-[a-zA-Z]+\s+)*(?:-[a-zA-Z]*[ec]\b)', '反弹 shell(nc -e)'),
    (r'\b(?:bash|sh|zsh)\s+-i\b', '交互式反弹 shell'),
    (r'>\s*/etc/(?:passwd|shadow|crontab|sudoers)', '覆盖系统关键文件'),
    (r'\bchmod\s+(?:-R\s+)?777\s+/(?:\s|$|\*|;)', '全局 777 权限篡改'),
    (r'\b(?:wget|curl)\s+[^|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b', '远程代码下载执行'),
    (r'\b(?:iptables|nft)\s+(?:-F|--flush|-X)', '清空防火墙规则'),
    (r'\bkill\s+-9\s+1\b', '杀 init 进程'),
    # 2026-10-25 补充：restart/reload 作为路径末段同样会中断服务（含空白/分隔符/结尾）
    (r'/(?:restart|reload)(?=\s|$|[?&;/#])', '重启/重载服务'),
    (r'\buserdel\b', '删除系统账号'),
]

# 2026-10-26 用户要求「加入所有网站的审计，不止限定某个网站」。
#   GUARD_SCOPE_MODE=all （默认）→ 所有网站都审计并按语义规则拦截，白名单仅作审计标注
#   GUARD_SCOPE_MODE=list        → 旧行为：白名单外的主机一律拦（规则 9 原样）
GUARD_SCOPE_MODE = os.environ.get('GUARD_SCOPE_MODE', 'all').strip().lower()
# 2026-11-16 lead：GUARD_HARD_DENY —— 硬拒绝主机（无视 policy，直接 403）
# 与 GUARD_OUT_OF_SCOPE 的区别：后者在 dml 策略下只审计不拦截（DML_BLOCK_EFFECTS 无 out_of_scope），
# 本项是**无条件拦截**，用于「暂不测试 / 已撤权」厂商的工程层硬约束。
# 用法：GUARD_HARD_DENY=.customer-f.example,customer-f.example（逗号分隔后缀，匹配 host 全等或后缀）
HARD_DENY = tuple(x.strip().lower() for x in os.environ.get('GUARD_HARD_DENY', '').split(',') if x.strip())


def in_hard_deny(host):
    """是否命中硬拒绝名单（host 全等或以该后缀结尾）。"""
    h = (host or '').lower().split(':')[0]
    if not h:
        return False
    for s in HARD_DENY:
        s = s.lower()
        if h == s.lstrip('.') or (s.startswith('.') and h.endswith(s)):
            return True
    return False



def scope_label(host):
    """主机在白名单内/外 —— 仅用于审计标注，不参与拦截决策。"""
    h = (host or '').lower().split(':')[0]
    if not h:
        return 'unknown'
    if h in ('127.0.0.1', 'localhost', '::1') or h.startswith('127.'):
        return 'loopback'
    for s in SCOPE_SUFFIX:
        s = s.lower()
        if h == s.lstrip('.') or h.endswith(s):
            return 'whitelist'
    for pfx in SCOPE_IP_PREFIX:
        if h.startswith(pfx):
            return 'whitelist'
    return 'other'


def in_scope(host):
    """是否属于受审计范围。

    全站审计模式（默认）下恒为 True：所有网站都受同一套语义规则审计与拦截，
    不再因为主机不在白名单而被 403。设为 list 模式可恢复旧的白名单强制。
    """
    if GUARD_SCOPE_MODE == 'all':
        return True
    h = (host or '').lower().split(':')[0]
    if h in OUT_OF_SCOPE_HOSTS:
        return False
    for s in SCOPE_SUFFIX:
        s = s.lower()
        if h == s.lstrip('.') or h.endswith(s):
            return True
    for pfx in SCOPE_IP_PREFIX:
        if h.startswith(pfx):
            return True
    return False

def deobf(s):
    s = urllib.parse.unquote(urllib.parse.unquote(s or ''))
    s = unicodedata.normalize('NFKC', s)
    s = s.replace(chr(0), '')
    s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
    s = re.sub(r'--+', '', s)
    s = s.replace(chr(96), '')
    return re.sub(r'\s+', '', s)

def body_hits(body, headers):
    # POLICY_20261015：只拦「删除/修改现有数据」；insert/upload 等「新增」不再拦。
    b = deobf(body or '')
    bl = b.lower()
    ctype = str(headers.get('Content-Type', '')).lower()
    hits = []
    for kw in ('deletefrom','removefrom','droptable','dropdatabase','truncatetable','delete_object','remove_object'):
        if kw in bl: hits.append('删除语句(%s)' % kw); break
    if re.search(r'\b(delete|drop|truncate)\b', bl) and re.search(r'\b(from|table|database|where|collection|index|schema)\b', bl):
        hits.append('删除语义')
    if re.search(r'update.{0,40}set', bl): hits.append('SQL UPDATE')
    if '"op":"replace"' in bl or '"op":"remove"' in bl or '"op":"copy"' in bl: hits.append('JSON-Patch 修改')
    if (':null' in bl or ': null' in bl) and ('"op"' in bl or 'merge-patch' in ctype or '"path"' in bl): hits.append('merge-patch 清空')
    if re.search(r'mutation[^a-z]{0,40}(delete|remove|update|modify|destroy|clear)', bl): hits.append('GraphQL 删改 mutation')
    if re.search(r'"method"\s*:\s*"(item\.)?(delete|remove|update|modify)', bl): hits.append('JSON-RPC 删改')
    if re.search('(action|op|operation)["\u0027]?[=:]["\u0027]?(delete|remove|update|modify|truncate|drop)', bl): hits.append('动作=删改')
    if re.search('_method[=:"\u0027]*(delete|put|patch|remove|update)', bl): hits.append('伪方法=删改')
    if re.search(r'<delete|<remove|<update|\[cdata\[delete', bl): hits.append('SOAP 删改')
    if 'soapaction' in bl and re.search(r'delete|update|remove', bl): hits.append('SOAPAction 删改')
    return hits


def _word_hit(text, words):
    # POLICY_20261015：分段 + camelCase 拆词匹配，避免 edit 命中 credit、clear 命中 clearance
    toks = []
    for seg in re.split(r'[^A-Za-z0-9]+', text or ''):
        if seg:
            toks += [x for x in re.split(r'(?<=[a-z0-9])(?=[A-Z])', seg) if x]
    low = set(x.lower() for x in toks)
    for w in words:
        if w in low:
            return w
    return None


def _exec_upload_hits(raw):
    hits, seen = [], set()
    fnames = re.findall(r'filename\*?\s*=\s*"?([^";\r\n]+)', raw, re.I)
    fnames += re.findall(r'"(?:file|filename|name)"\s*:\s*"([^"]{1,120})"', raw, re.I)
    for c in fnames:
        cl = c.lower().strip().strip('"\' ')
        # T14：不只看结尾——x.php.jpg / x.jsp;.png / x.php%00.jpg 这类绕过同样拦
        cl2 = cl.replace('%00', chr(0)).split(chr(0))[0]
        for ext in EXEC_EXT:
            if ext not in seen and (cl.endswith(ext) or ext in cl2 or (ext + '.') in cl2):
                seen.add(ext)
                hits.append('可解析文件上传 %s(禁止上传webshell/后门)' % ext)
                break
    return hits[:2]


def raw_low_probe(path, query):
    """范围判定用的轻量探针：路径 + query（不解 body，避免影响性能）。"""
    s = (path or '') + (('?' + query) if query else '')
    try:
        s = urllib.parse.unquote(s)
    except Exception:
        pass
    return s.lower()


def _sensitive_hits(lowall):
    for p in SENSITIVE_FILES:
        if p in lowall:
            return ['读取敏感文件 %s(禁止读取源码/敏感文件)' % p]
    return []


def _traversal_hits(text):
    # 参数名 + 穿越(..) + 系统绝对路径 三条件同时成立才拦；/etc/hostname 等取证文件放行
    for mm in _FILE_PARAM_RE.finditer(text or ''):
        val = urllib.parse.unquote(mm.group(2) or '')
        vl = val.lower()
        if '..' not in vl:
            continue
        if _SYS_PATH_RE.search(vl) or _WIN_ABS_RE.match(vl):
            if not any(a in vl for a in ALLOWED_READ):
                return ['读取系统敏感文件 %s(禁止读取源码/敏感文件)' % val[:80]]
    return []


# ===== T14 (2026-10-25) 新增：令牌桶限速（只约束发往目标的流量，本机回环中继豁免）=====
# 用户纪律：<=2 req/s、连续探测间隔 >=200ms。此前护栏完全没有频率约束。
# 用令牌桶而非硬时间窗：容量 10 允许页面并发加载多个资源（正常浏览形态），
# 匀速补充 2/s 把「持续扫描」压到合规速率；静态资源（js/css/图片/字体）完全豁免。
# 2026-10-26：与语义层限速统一读同一组环境变量。
# 旧值 24 / 2.0 与语义层的 60 / 15 不一致，导致语义层不可用时（回滚窗口）
# 真实业务被按 2 req/s 误拦（实测 customer-a.example 16 次）。
RATE_CAP = int(os.environ.get('GUARD_RATE_CAP', '60'))
RATE_PER_SEC = float(os.environ.get('GUARD_RATE_PER_SEC', '15'))
RATE_MIN_GAP = 0.2     # 参考值：连续探测建议间隔（不硬拦，避免误伤浏览器并发 XHR）
RATE_ENABLED = os.environ.get('T14_RATE_ENABLED', '1') not in ('0', 'false', 'off')
_RATE = {}
_RATE_LOCK = None
_RATE_STATIC = ('.js', '.mjs', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp',
                '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webmanifest')


def _rate_block(host, path):
    global _RATE_LOCK
    import time as _t
    h = (host or '').lower()
    if not RATE_ENABLED:
        return None
    if not h or h in ('127.0.0.1', 'localhost', '::1') or h.startswith('127.'):
        return None
    if (path or '').rsplit('/', 1)[-1].lower().endswith(_RATE_STATIC):
        return None   # 静态资源豁免，避免拖慢正常页面加载
    try:
        if _RATE_LOCK is None:
            import threading
            _RATE_LOCK = threading.Lock()
        with _RATE_LOCK:
            now = _t.monotonic()
            st = _RATE.get(h)
            if st is None:
                st = {'tokens': float(RATE_CAP), 'last': now, 'gap': 0.0}
                _RATE[h] = st
            st['tokens'] = min(float(RATE_CAP), st['tokens'] + (now - st['last']) * RATE_PER_SEC)
            st['last'] = now
            if st['tokens'] < 1.0:
                return 'RATE_LIMIT 触发限速(>%d req/s，请降速重试)' % int(RATE_PER_SEC)
            st['tokens'] -= 1.0
            st['gap'] = now
    except Exception:
        return None
    return None


def _ssrf_hits(raw, host):
    # T14：禁止借目标做 SSRF 打内网/云元数据。发往本机回环的请求是 .15 自身中继，不做此检查。
    h = (host or '').lower()
    if h in ('127.0.0.1', 'localhost', '::1') or h.startswith('127.'):
        return []
    t = raw or ''
    m = _SSRF_STRONG.search(t) or _SSRF_LOCAL.search(t) or _SSRF_PARAM.search(t)
    if m:
        seg = t[max(0, m.start() - 40):m.end() + 40]
        return ['SSRF 内网/元数据地址(禁止打内网与云元数据): ' + seg.strip()[:90]]
    return []


def _rce_hits(raw):
    # T14：破坏性/反连类命令拦截；id、whoami、uname、echo、/etc/hostname 等无害 PoC 放行
    t = (raw or '').replace('+', ' ')
    for pat, name in _RCE_RULES:
        if re.search(pat, t, re.I):
            return ['RCE 破坏性命令 %s(禁止破坏/反连)' % name]
    return []


def _bulk_hits(query, body):
    out = []
    qs = urllib.parse.parse_qs(query or '', keep_blank_values=True)
    for k, vs in qs.items():
        if k.lower() in BULK_PARAMS:
            for v in vs:
                if re.fullmatch(r'\d{1,9}', v or '') and int(v) > BULK_MAX:
                    out.append('批量导出参数 %s=%s > %d(禁止拖库/大规模遍历)' % (k, v, BULK_MAX))
                    return out
    b = (body or '').lstrip()
    # T14：顶层为 JSON 数组的 body 同样解析（批量对象数组 = 批量业务写入）
    if b.startswith('{') or b.startswith('['):
        try:
            j = json.loads(body)
            def walk(o, depth=0):
                if depth > 4: return None
                if isinstance(o, dict):
                    for k, v in o.items():
                        if str(k).lower() in BULK_PARAMS and isinstance(v, (int, str)):
                            try:
                                if int(v) > BULK_MAX: return '%s=%s' % (k, v)
                            except Exception: pass
                        r2 = walk(v, depth + 1)
                        if r2: return r2
                elif isinstance(o, list):
                    for v in o[:20]:
                        r2 = walk(v, depth + 1)
                        if r2: return r2
                return None
            hit = walk(j)
            if hit: out.append('批量导出参数 %s > %d(禁止拖库/大规模遍历)' % (hit, BULK_MAX))
            # T14：批量「新建/提交」对象数组（>50 个 dict）视为批量业务操作；
            # 纯 id/字符串数组属批量只读查询，不拦，避免误伤。
            if isinstance(j, list) and len(j) > 50 and j and isinstance(j[0], dict):
                out.append('批量业务写入 %d 条对象(禁止批量业务操作)' % len(j))
        except Exception: pass
    else:
        # T14：form-urlencoded / 裸 query 形态的 body 也做分页参数检查（此前漏拦）
        try:
            fq = urllib.parse.parse_qs((body or '').strip(), keep_blank_values=True)
            for k, vs in fq.items():
                if k.lower() in BULK_PARAMS:
                    for v in vs:
                        if re.fullmatch(r'\d{1,9}', v or '') and int(v) > BULK_MAX:
                            out.append('批量导出参数 %s=%s > %d(禁止拖库/大规模遍历)' % (k, v, BULK_MAX))
                            return out
        except Exception: pass
    return out


def _sleep_hits(text):
    out = []
    for mm in _SLEEP_RE.finditer(text or ''):
        try:
            if int(mm.group(1)) >= 10:
                out.append('sleep(%s)>=10s(禁止影响服务稳定性)' % mm.group(1))
                break
        except Exception: pass
    return out


# ======================================================================
# 2026-10-25 架构重构：判定改为「先解析 HTTP 请求结构，再判断作用」
#
# 旧实现靠 URL/body 里出现了什么词来猜意图，天生两个缺陷：
#   误拦：edith 含 edit、dropdown 含 drop、/css/reset.css 里 reset 被当动作
#   漏拦：shutdown?cid=1 因 '?' 不匹配、加 .js 后缀绕过敏感文件检查
# 根因是把【词法】当成了【语义】。
#
# 新架构（guard_semantic.py）：
#   parse()    HTTP 报文 → 结构化 Facts（方法/归一化路径/结构化 query/解析后 body）
#   classify() Facts → Effect（对什么资源做什么操作）
#   policy()   Effect → 命中《测试注意事项和禁止行为》第几条
# 判据全部是结构性的：HTTP 方法语义、路径末段动词、body 动作字段、
# 是否携带目标资源标识、分页/过滤字段占比、数组长度、路径归一化后比对。
#
# 本文件保留的确定性规则作为【补充层】，与语义层取并集（任一命中即拦）。
# ======================================================================
# 关键：必须把本文件所在目录放进 sys.path 再导入。
# 2026-10-25 踩坑：mitmproxy/服务的工作目录是 /home/my，不是本目录，
# 直接 'import guard_semantic' 会 ModuleNotFoundError，被 except 静默吞掉后
# SEM_AVAILABLE=False，退回关键词层 —— 导致所有拦截静默失效（严重生产隐患）。
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

SEM_AVAILABLE = False
SEM_IMPORT_ERROR = None
try:
    import guard_semantic as _sem
    _sem.configure(
        scope_suffix=SCOPE_SUFFIX, out_of_scope=OUT_OF_SCOPE_HOSTS,  # 已含环境变量覆盖
        bulk_max=BULK_MAX, max_body=1024 * 1024,
        scope_mode=GUARD_SCOPE_MODE,
        # 限速（规则 2 稳定性 / 规则 4 禁止高并发扫描）：可按环境变量调整
        rate_cap=float(os.environ.get('GUARD_RATE_CAP', '60')),
        rate_per_sec=float(os.environ.get('GUARD_RATE_PER_SEC', '15')),
        # 限速在纯语义模式下一并关闭（用户口径：除删除/修改与 RCE 利用外都不拦）
        rate_enabled=(os.environ.get('GUARD_POLICY', 'strict').strip().lower() != 'jev')
                      and (os.environ.get('GUARD_RATE_ENABLED', '1') not in ('0', 'false', 'off')),
        # 拦截口径：strict=按9条全面拦；dml=只拦删除/修改+RCE利用；jev=规则层不拦，纯交给Jev
        policy=os.environ.get('GUARD_POLICY', 'strict').strip().lower())
    SEM_AVAILABLE = True
except Exception as _e:
    # 不再静默降级：语义层是主判定，加载失败必须显式暴露，
    # 后续 decide() 会 fail-closed（而不是悄悄放行）。
    SEM_IMPORT_ERROR = '%s: %s' % (type(_e).__name__, _e)
    try:
        with open(os.path.join(_BASE_DIR, 'guard-semantic-error.log'), 'a') as _f:
            _f.write('%s %s%s' % (datetime.datetime.now().isoformat(), SEM_IMPORT_ERROR, chr(10)))
    except Exception:
        pass


# 最近一次确定性语义层的操作类型（read/create/update/delete），供 LLM 层交叉校验。
# 用途：确定性层已判定「这是读操作」时，LLM 若误判为「删改」，不应推翻确定性结论。
# 2026-10-26 修并发串扰（重要）：
# 原来是一个普通 dict，mitmproxy 线程池里多个请求并发写同一个键，
# 导致 A 请求的 DELETE 读到了 B 请求的 read，进而被「确定性层判 read → 推翻 LLM」
# 错误放行。改为线程局部存储。
import threading as _thr
_LAST_OP_TLS = _thr.local()


def _LAST_OP_SET(op):
    _LAST_OP_TLS.op = op


def _LAST_OP_GET():
    return getattr(_LAST_OP_TLS, 'op', None)


def _semantic_op(method, url, headers, body):
    """获取确定性语义层对本次请求的操作判定（只读/新建/修改/删除）。"""
    if not SEM_AVAILABLE:
        return None
    try:
        f = _sem.parse(method, url, headers, body)
        op, _why = _sem.resolve_op(f)
        return op
    except Exception:
        return None




# ==================== BIZ_WRITE_GUARD_V2 (2026-11-23) ====================
# V1 教训：按「路径含写动词」一律拦，误伤 5 条真实高危漏洞（未授权上传/未授权创建标签/未授权改价），
#          因为这些漏洞的证明方式恰恰就是「发一个写请求」。
# V2 口径：只拦「不可逆 / 影响他人 / 改删既有数据」；新建类放行并加风险标注。
VERB_DELETE = set('delete remove destroy purge truncate drop wipe erase unlink discard'.split())
VERB_OUTREACH = set('send sms mail email push notify message notifyuser remind'.split())
VERB_MONEY = set('pay refund settle charge recharge withdraw topup transfer'.split())
VERB_CRED = set('resetpassword resetpwd changepassword changepwd bind unbind revoke grant authorize disable enable freeze unfreeze lock unlock rename'.split())
VERB_CREATE = set('create add insert append register enroll apply submit upload import save commit new'.split())
VERB_MODIFY = set('update modify edit change alter adjust set patch replace updateprice editprice'.split())

def _biz_segs(p0):
    if not p0:
        return [], ''
    p = urllib.parse.unquote(p0 or '')
    p = re.sub(r'\.[A-Za-z0-9]{1,8}$', '', p)
    p = re.sub(r';.*$', '', p)
    toks = []
    for seg in re.split(r'[/_\-\.]+', p):
        if not seg:
            continue
        parts = re.findall(r'[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)', seg)
        toks.extend([x.lower() for x in (parts or [seg])])
    toks = [t for t in toks if t]
    return toks, ''.join(toks)

def _biz_hitset(toks, joined, s):
    out = set()
    for t in toks:
        if t in s:
            out.add(t)
    for w in s:
        if len(w) >= 5 and w in joined:
            out.add(w)
    return out

def business_write_hit(method, url, headers=None, body=''):
    """返回 (block: bool, reason: str, tag: str)  tag in {block, annotate, allow}"""
    m = str(method or '').upper()
    try:
        pth = urllib.parse.urlsplit(url or '').path or '/'
    except Exception:
        pth = url or '/'
    toks, joined = _biz_segs(pth)

    d  = _biz_hitset(toks, joined, VERB_DELETE)
    o  = _biz_hitset(toks, joined, VERB_OUTREACH)
    mo = _biz_hitset(toks, joined, VERB_MONEY)
    c  = _biz_hitset(toks, joined, VERB_CRED)
    cr = _biz_hitset(toks, joined, VERB_CREATE)
    md = _biz_hitset(toks, joined, VERB_MODIFY)

    # 2026-11-23 修复：读方法(GET/HEAD/OPTIONS) + 路径含读取类动词时，cred 命中多为误判
    # 例：/bindMobile/getDealerContact、/h5/getBindAccountInfoV3 —— 只是查询接口，不是绑定动作。
    # 判定：路径里出现 read verb(get/list/query/query/info/detail/view/search/count/exists/check)
    #      且不含真正的写动词 → 视为「主题词是名词」，cred 降级为 annotate 不拦截。
    _READPATH_VERB = set('get list query info detail view search count exists check fetch read load find show page'.split())
    _WRITE_VERB = VERB_DELETE | VERB_OUTREACH | VERB_MONEY | VERB_CREATE | VERB_MODIFY
    _rp = _biz_hitset(toks, joined, _READPATH_VERB)
    _wp = _biz_hitset(toks, joined, _WRITE_VERB)
    # 只有读动词、没有写动词，且方法本身是读 → cred 属于名词误命中
    _cred_is_noun = bool(_rp) and not _wp and m in ('GET', 'HEAD', 'OPTIONS')

    if d:
        return True, '删除类动作 %s（不可逆，可能删既有数据）' % ','.join(sorted(d)), 'block'
    if o:
        return True, '外部触达动作 %s（会真实发送给他人）' % ','.join(sorted(o)), 'block'
    if mo:
        return True, '资金类动作 %s（涉及真实交易）' % ','.join(sorted(mo)), 'block'
    if c:
        if _cred_is_noun:
            return False, '凭据类名词 %s 出现在读接口路径中（读动词=%s，无写动词）→ 判为查询，放行' % (
                ','.join(sorted(c)), ','.join(sorted(_rp))), 'annotate'
        return True, '凭据/权限变更 %s（改密改绑授权类，不可逆）' % ','.join(sorted(c)), 'block'
    if m == 'DELETE':
        return True, '写方法 DELETE', 'block'
    if m in ('PUT', 'PATCH'):
        return True, '写方法 %s（整体替换既有资源）' % m, 'block'

    if cr:
        return False, '新建类动作 %s —— 放行，但必须使用无害探针/不存在的主键，禁止写入真实业务数据' % ','.join(sorted(cr)), 'annotate'
    if md:
        return False, '改动类动作 %s —— 放行，但必须使用不存在的ID验证校验阶梯，禁止改动真实记录' % ','.join(sorted(md)), 'annotate'

    b = (body or '')
    if isinstance(b, bytes):
        try:
            b = b.decode('utf-8', 'replace')
        except Exception:
            b = ''
    low = b.lower()[:4000]
    for pat, why in [
        (r'"(?:action|op|operation|method|cmd|type)"\s*:\s*"?(delete|remove|destroy|purge|truncate)', 'body 删除动作'),
        (r'"(?:action|op|operation|method|cmd|type)"\s*:\s*"?(send|sms|mail|notify|push)', 'body 发送动作'),
        (r'"(?:action|op|operation|method|cmd|type)"\s*:\s*"?(pay|refund|settle|charge)', 'body 资金动作'),
    ]:
        mm = re.search(pat, low)
        if mm:
            return True, '%s=%s' % (why, mm.group(1)), 'block'
    return False, '', 'allow'
# ================== END BIZ_WRITE_GUARD_V2 ==================

def decide(method, url, headers, body):
    # ===== BIZ_WRITE_GUARD_V1：业务数据写入保护（最高优先级，语义层不可推翻）=====
    _biz_annot = None
    if os.environ.get('GUARD_BIZ_WRITE_GUARD', '1') not in ('0', 'false', 'off', 'no'):
        try:
            _bhit, _bwhy, _btag = business_write_hit(method, url, headers, body)
            if _bhit:
                return False, ['【业务写入保护·V2】' + _bwhy + '（禁止向会改删既有数据的 API 发包；此类漏洞请只在报告中产出存疑性 finding）']
            if _btag == 'annotate':
                _biz_annot = '【业务写入保护·V2·放行附条件】' + _bwhy
        except Exception as _be:
            pass  # 判定异常不阻断主流程，仍有语义层兜底
    # 2026-11-20 lead：路径级白名单（用户批准）—— 最优先放行，仅审计不拦截
    if ALLOW_PATH:
        try:
            _pu = urllib.parse.urlparse(url or "")
            _ph = (_pu.hostname or "").lower()
            _pp = _pu.path or ""
            if in_allow_path(_ph, _pp):
                return True, ["【白名单】GUARD_ALLOW_PATH 命中 %s%s，仅审计不拦截" % (_ph, _pp)]
        except Exception:
            pass
    # 2026-11-16 lead：硬拒绝名单（暂不测试/已撤权厂商）—— 无视 policy，直接在门口拒绝
    if HARD_DENY:
        try:
            _hh = (urllib.parse.urlparse(url).hostname or '').lower()
        except Exception:
            _hh = ''
        if _hh and in_hard_deny(_hh):
            return False, ['⛔ 暂不测试/已撤权厂商（GUARD_HARD_DENY 命中 %s），一律拒绝' % _hh]
    # === 语义层优先 ===
    # 2026-11-02（用户要求）：临时用本地免费模型（big-pickle shim / OpenAI 兼容）替代 Jev 语义层
    if os.environ.get('GUARD_SEM_BACKEND', '').strip().lower() == 'deepseek':
        if SEM_AVAILABLE:
            try:
                return _ask_deepseek(method, url, headers, body)
            except Exception as _e:
                _m = str(method or '').upper()
                if _m in ('GET', 'HEAD', 'OPTIONS'):
                    _a, _r = _decide_legacy(method, url, headers, body)
                    return _a, list(_r) + ['DeepSeek语义层不可用(%s)→读方法按确定性层' % str(_e)[:60]], {'by': 'none', 'fail': 'deepseek-error'}
                return False, ['DeepSeek语义层不可用(%s)→写方法 fail-closed' % str(_e)[:60]], {'by': 'none', 'fail': 'deepseek-error'}
    if SEM_AVAILABLE:
        try:
            # 先记录操作类型：LLM 层据此判断是否该被推翻
            _LAST_OP_SET(_semantic_op(method, url, headers, body))
            sallow, sreasons = _sem.evaluate(method, url, headers, body)
            if not sallow:
                return False, sreasons[:5]
            # 语义层放行后仍过一遍极少数「载荷级」硬规则（SQL/webshell/RCE），
            # 这些是内容特征，与业务语义无关，{Whatever}.evaluate 已覆盖，此处不重复。
            # 2026-11-02（用户要求放松 RCE）：Jev 的 rce 评分不再单独拦截；
            # 但破坏性/反连类系统命令仍由规则层兜底（_RCE_RULES），不属于「正常 RCE 验证」。
            if not RCE_ENFORCE:
                _raw = urllib.parse.unquote('%s %s' % (url or '', body or ''))
                _rh = _rce_hits(_raw)
                if _rh:
                    return False, _rh
                # 提权/横向类命令仍拦（正常 RCE 放行，不等于允许提权）
                if SEM_AVAILABLE:
                    try:
                        _pv = _sem.find_privesc(_sem.parse(method, url, headers, body))
                        if _pv and not str(_pv).startswith('读取'):
                            return False, ['提权/横向命令（正常RCE放行，提权仍拦）：' + str(_pv)]
                    except Exception:
                        pass
            return True, (sreasons + ([_biz_annot] if _biz_annot else []))
        except Exception as e:
            # 语义层运行时异常 → fail-closed，绝不静默放行
            _m = str(method or '').upper()
            if _m in ('GET', 'HEAD', 'OPTIONS'):
                return _decide_legacy(method, url, headers, body)
            return False, ['语义层异常(%s)→写方法 fail-closed' % str(e)[:60]]
    # 语义层未加载：写方法一律拒绝，读方法退回旧规则
    _m = str(method or '').upper()
    _why = '语义层未加载(%s)' % (SEM_IMPORT_ERROR or 'unknown')
    allow, reasons = _decide_legacy(method, url, headers, body)
    if _m in ('GET', 'HEAD', 'OPTIONS'):
        return allow, list(reasons) + [_why + '｜读方法按确定性层']
    return False, list(reasons) + [_why + '｜写方法 fail-closed']


def _decide_legacy(method, url, headers, body):
    # 以下是原有的确定性关键词规则，作为语义层的补充层保留。
    u = urllib.parse.urlparse(url); path = u.path; query = u.query; params = u.params or ''
    m = deobf(method).upper()
    reasons = []
    host = (u.hostname or '').lower()
    _last = (path or '').rsplit('/', 1)[-1].lower()
    _is_static = _last.endswith(STATIC_EXT)
    # 2026-10-25 优化：页面被动加载的第三方静态资源（CDN/统计/验证码/字体）豁免范围检查，
    # 否则整页会被 403 打残。仅豁免「静态后缀 + 读方法」，主动探测目标仍受范围限制。
    # 2026-10-25：静态资源豁免范围检查仅限「确实像静态资源」的路径；
    # 若路径含敏感文件特征（.git/、WEB-INF/、.env 等），不享受豁免，交给下面的敏感文件规则处理。
    _passive_asset = (_is_static and m in ('GET', 'HEAD', 'OPTIONS')
                      and not _sensitive_hits(raw_low_probe(path, query)))
    if host and not in_scope(host) and host not in ('127.0.0.1', 'localhost') and not _passive_asset:
        reasons.append('范围外主机 %s(禁止测试范围外系统)' % host)
    if body and len(body.encode('utf-8', 'ignore')) > 1024 * 1024:
        reasons.append('请求体>1MB(禁止影响服务稳定性)')
    if m in WRITE_VERBS or (m and m not in SAFE):
        reasons.append('写方法 %s' % method)
    for k in ('X-HTTP-Method-Override','X-Method-Override','X-HTTP-Method','X-Override','X-Amz-Method','X-Method'):
        v = headers.get(k)
        if v and deobf(v).upper() in WRITE_VERBS:
            reasons.append('覆盖头 %s=%s' % (k, v))
    qs = urllib.parse.parse_qs(query, keep_blank_values=True)
    for k in ('_method','method','__method','_action','action','op','operation'):
        if k in qs and _word_hit(deobf(qs[k][0]).lower(), DEL_WORDS + MOD_WORDS):
            reasons.append('参数 %s=%s' % (k, qs[k][0]))
    read_method = m in ('GET','HEAD','OPTIONS')
    # 2026-10-17：静态资源路径里的 delete/update 等字样属文件名，不参与删改动作判定
    # （例：/assets/DeleteModal-22fde8a1.js 会被误拦）。STATIC_EXT/_is_static 已在函数开头算好。
    probe = '' if _is_static else (deobf(path) + ((';' + deobf(params)) if params else ''))
    if read_method:
        # 2026-10-25 优化：读方法只认「删改动词落在路径末尾」的形态，
        # 补上 cancel/del/disable/refund 等真实删除动词，同时避开 edith/clearance 这类业务名词误伤。
        reasons += _read_delete_hits(path)
    else:
        w = _word_hit(probe, DEL_WORDS + MOD_WORDS)
        if w:
            reasons.append('路径含删改动作 %s' % w)
    # --- SRC 对齐(2026-10-25)：破坏SQL/上传/敏感文件/拖库/sleep，与 sanmen_guard 同规则 ---
    raw_text = (path or '') + (('?' + query) if query else '') + ' ' + (body or '')
    try: raw_text = urllib.parse.unquote(raw_text)
    except Exception: pass
    sql_blob = raw_text.lower().replace('+', ' ')
    for pat, name in SQL_DESTRUCTIVE:
        if re.search(pat, sql_blob):
            reasons.append('%s(禁止破坏性数据库操作)' % name)
            break
    reasons += _exec_upload_hits(raw_text)
    # 2026-10-25 修复：原实现 `if not _is_static` 让敏感文件/穿越检查对静态后缀整体失效，
    # 攻击者加个 .js/.png 后缀就能绕过（实测 /.git/config.js、/WEB-INF/web.xml.png 全放行）。
    # 现改为「静态资源也要查敏感文件」，仅当路径确实不含敏感特征时才由静态豁免放行。
    # 2026-10-25 用户口径：源码拦截必须区分「公开途径」与「通过漏洞获取」。
    # 关键词层无法做这种区分（它会把 /static/app.js 也当源码），因此敏感文件判定
    # 完全交给语义层 find_sensitive()；这里保留穿越检查作为结构补充。
    reasons += _traversal_hits(raw_text)
    # 批量/拖库交由语义层按「数量」判定（find_dos / find_bulk_write），
    # 关键词层的小阈值容易把正常分页(size=500)误判成拖库。
    reasons += _sleep_hits(raw_text)
    reasons += _rce_hits(raw_text)          # 破坏性/反连命令
    # 2026-10-25 用户口径：SSRF 合理探测不拦（语义层仅作 audit 记录）。
    # 补充层不再重复拦截，避免把授权测试必需的 SSRF 验证挡掉。
    # _ssrf_hits 保留为审计能力，供 jev_monitor 统计，不参与 decide 判定。
    _rb = _rate_block(host, path)           # T14 新增：令牌桶限速兜底
    if _rb:
        reasons.append(_rb)
    # 2026-10-25 架构统一：body 的删除/修改语义已由语义层 find_delete_markers /
    # _has_delete_state 按【读写语义】判定（能区分「列表筛 status=deleted」与
    # 「把 status 置为 deleted」）。旧的 body_hits/_body_delete_hits 是纯关键词扫描，
    # 无法区分二者，会把正常筛选误拦，故不再参与判定。
    return (False, reasons[:5]) if reasons else (True, ['只读形态'])


def build_state(method, url, headers, body):
    u = urllib.parse.urlparse(url)
    hs = {k: v for k, v in headers.items() if k.lower() in ('content-type','content-length','transfer-encoding','x-http-method-override','x-method-override','x-http-method','origin','referer','soapaction')}
    return ('Audit proxy captured this outbound HTTP request to the target server.\n'
            'METHOD: %s\nURL: %s\nPATH: %s\nQUERY: %s\nHEADERS: %s\nBODY: %s'
            % (method, url, u.path, u.query or '(none)', json.dumps(hs, ensure_ascii=False)[:600], (body or '')[:1200]))

def _llm_state(method, url, headers, body):
    """直接把【原始请求报文】喂给 Jev，不做任何解析、不提取关键词。

    2026-10-26 用户口径：
      「不要用正则的形式，用语义的形式，喂给Jev」
      「直接将请求包喂给Jev，让Jev来判断即可」

    因此这里把 method / 请求行 / 全部请求头 / 原始 body 原样拼成一段 HTTP 报文文本，
    交给模型自己看、自己判断 —— 护栏不再对内容做任何正则匹配或前置结论。
    """
    try:
        u = urllib.parse.urlsplit(url or '')
        target = (u.path or '/')
        if u.query:
            target += '?' + u.query
    except Exception:
        target = url or '/'

    lines = ['%s %s HTTP/1.1' % (str(method or 'GET').upper(), target)]
    try:
        for k, v in (headers or {}).items():
            lines.append('%s: %s' % (k, str(v)[:300]))
    except Exception:
        pass
    if not any(str(k).lower() == 'host' for k in (headers or {})):
        try:
            lines.append('Host: %s' % (u.hostname or ''))
        except Exception:
            pass
    lines.append('')
    _b = body or ''
    if len(_b) > 4000:
        _b = _b[:4000] + '…[truncated]'
    lines.append(_b)
    return (chr(13) + chr(10)).join(lines)[:8000]


def _ask_jev(method, url, headers, body):
    payload = {'state': _llm_state(method, url, headers, body), 'model': TS_MODEL,
               'questions': {
                   'deletes_or_modifies': {'type': 'noul', 'instructions':
                       'Does this request DELETE, OVERWRITE or MODIFY data/records that ALREADY EXIST on the target server? '
                       'Answer YES whenever the request changes the state or content of an existing object, including: '
                       'deleting or cancelling a record; changing a field of a record identified by an id / userId / '
                       'orderId / pk; saving or editing a profile; changing a password or phone number; updating a price, '
                       'quantity or status; revoking or granting permission on an existing object; bulk-editing existing '
                       'records. '
                       'Authorized security-assessment detection traffic must be answered NO: read-only probing, '
                       'listing/filtering/searching/pagination queries, SQL-injection or SSTI/RCE detection payloads, '
                       'SSRF probes, file-read PoCs (e.g. /etc/hostname), IDOR/unauthorized READS, login or '
                       'authentication attempts, creating or uploading NEW files/records that do not overwrite anything, '
                       'and service flooding or denial-of-service (that is a separate concern and must be answered NO).'},
                   'rce_exploitation': {'type': 'noul', 'instructions':
                       'Does this request attempt to EXECUTE SYSTEM COMMANDS on the server as an EXPLOITATION step? '
                       'Answer YES for: reverse/bind shells, downloading-and-running payloads, privilege escalation '
                       '(chmod +s, setcap, sudo/su to root), persistence (crontab, authorized_keys, service install), '
                       'destructive system commands (rm -rf on absolute paths, mkfs, dd to block devices, shutdown/reboot, '
                       'wiping logs, deleting system accounts), writing into system directories, and lateral movement. '
                       'Answer NO for: basic verification commands (id, whoami, hostname, uname, ls, cat of a non-sensitive '
                       'file), blind command-injection DETECTION payloads, time-delay probes, and any request that only '
                       'reads data or merely proves that command execution is possible.'},
                   'impact': {'type': 'choice', 'instructions': 'What is the impact of this request on EXISTING data?',
                              'criteria': {
                                  'no_destructive_impact': 'Reads data, or creates/uploads new objects, or probes for vulnerabilities; existing data is neither removed nor altered, and the service is not flooded',
                                  'deletes_or_modifies_existing': 'Removes, overwrites, or alters data that already exists on the server, or floods/degrades the service',
                                  'unknown': 'Cannot be determined from the request'}}}}
    # 2026-11-25 性能优化：改用 urllib3 连接池（HTTP Keep-Alive）。
    # 原实现每次 build_opener 新建连接，TLS 握手要 0.5s，占单次调用总耗时的 60%+。
    # 复用连接后 TLS 只握手一次，实测 5 连发从 4.0s 降到 1.65s（约 330ms/次）。
    _http = _jev_pool()
    _hdr = {'Authorization': 'Bearer ' + TS_KEY, 'Content-Type': 'application/json'}
    _r = _http.request('POST', TS_URL, body=json.dumps(payload).encode(),
                       headers=_hdr, timeout=float(os.environ.get('T14_JEV_TIMEOUT', '8')),
                       retries=False, preload_content=False)
    try:
        _raw = _r.read()
    finally:
        _r.release_conn()
    res = json.loads(_raw or b'{}')
    a = res.get('answers') or {}
    nv = (a.get('deletes_or_modifies') or {}).get('noul')
    noul_present = nv is not None
    noul = float(nv) if noul_present else 1.0
    # RCE 利用（2026-10-26 新增语义问题）
    rv = (a.get('rce_exploitation') or {}).get('noul')
    rce_present = rv is not None
    rce = float(rv) if rce_present else 0.0
    im = a.get('impact') or {}
    kind = str(im.get('choice') or 'unknown'); conf = float(im.get('confidence') or 0.0)
    _m = str(method).upper()
    _read = _m in ('GET', 'HEAD', 'OPTIONS')
    # 2026-10-26 用户口径：只拦「删除/修改」+「RCE 利用」，其余由语义判定放行
    bad_dm = (kind == 'deletes_or_modifies_existing') or (noul_present and noul > 0.90)
    bad_rce = rce_present and rce > 0.60 and RCE_ENFORCE
    bad = bad_dm or bad_rce
    rs = []
    if kind == 'deletes_or_modifies_existing':
        rs.append('Jev 语义判定=删除/修改现有数据')
    elif noul_present and noul > 0.90:
        rs.append('Jev 删改概率=%.2f' % noul)
    if bad_rce:
        rs.append('Jev 语义判定=RCE利用(%.2f)' % rce)
    elif rce_present and rce > 0.60:
        # 2026-11-02（用户要求）：放松口径下 RCE 评分只审计、不拦截。
        rs.append('Jev RCE利用评分=%.2f（仅审计，正常RCE放行）' % rce)
    if not _read:
        if noul > TS_NOUL_MAX and not bad: pass  # 仅记录
        if conf < TS_MIN_CONF and not bad: pass  # 仅记录
    return (not bad), rs, {'by': 'jev', 'noul': noul, 'kind': kind, 'conf': conf,
                           'rce': rce, 'model': res.get('model')}

def _ask_deepseek(method, url, headers, body):
    prompt = ('You are a strict read-only guard for an authorized security assessment.\n'
              'Decide ONLY this: does the HTTP request below delete, overwrite or modify EXISTING data on the target?\n'
              'Allowed (answer ALLOW): reading data, downloading files, uploading/creating NEW files, vulnerability probing '
              '(SQL injection payloads, SSTI/RCE payloads, file-read payloads) that does not destroy or alter existing data.\n'
              'Blocked (answer BLOCK): deleting, overwriting, updating or truncating existing records/files, destructive SQL '
              '(DELETE/DROP/TRUNCATE/UPDATE), destructive API calls.\n'
              'Answer with exactly one word: ALLOW or BLOCK.\n\n' + _llm_state(method, url, headers, body))
    payload = {'model': DS_MODEL, 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': 600, 'temperature': 0}
    req = urllib.request.Request(DS_URL, data=json.dumps(payload).encode(), method='POST')
    req.add_header('Content-Type', 'application/json')
    _dsk = os.environ.get('DS_KEY', '').strip()
    if _dsk:
        req.add_header('Authorization', 'Bearer ' + _dsk)
    with urllib.request.urlopen(req, timeout=float(os.environ.get('T14_DS_TIMEOUT', '15'))) as r:
        res = json.loads(r.read() or b'{}')
    msg = ((res.get('choices') or [{}])[0].get('message') or {})
    blob = ((msg.get('content') or '') + ' ' + (msg.get('reasoning_content') or '')).upper()
    allow = blob.rfind('ALLOW') > blob.rfind('BLOCK')   # 取最后一次出现的判定
    verdict = 'ALLOW' if allow else 'BLOCK'
    return allow, ([] if allow else ['DeepSeek 判定=BLOCK']), {'by': 'deepseek', 'answer': verdict, 'model': DS_MODEL, 'raw': blob[-40:]}

# ===== T14 (2026-10-25) 语义层性能：读方法跳过 + 结论缓存 =====
# 背景：语义层是同步阻塞调用（Jev ~0.7s / DeepSeek ~4s），跑在 mitmproxy 事件循环里，
# 每个请求串行等模型返回；四条战线并发时排队放大到 12~21s，最终 curl 超时 = code 000。
# 处置：
#   (1) AUDIT_MODE=both 时，读方法(GET/HEAD/OPTIONS)的 Jev 结论本来就「只记录、不拦截」
#       （见 mitm_guard.py READ_METHOD_NEVER_BLOCK），调用纯属成本 → 直接跳过，拦截力不变。
#   (2) 非读方法结果按 (方法,主机,路径,body哈希) 缓存 60s，登录/探测类重复请求不再重复调模型。
#   (3) 超时从 30s/45s 收紧到 8s/15s，避免语义层挂起把整条代理拖死。
# 2026-11-25：Jev 调用专用的 urllib3 连接池（进程级单例，复用 TLS 连接）。
_JEV_POOL = None
# 注：此处不需要锁——_jev_pool() 是幂等懒加载，并发首次调用最多建几个池，无害。

def _jev_pool():
    """返回进程级复用的 urllib3 PoolManager（走 TS_PROXY）。

    性能要点：
      - maxsize 调大，避免并发时排队等连接
      - block=False，池满时新建而不是阻塞
      - retries=False，由上层决定重试（避免隐形放大延迟）
      - 关掉证书校验（typesafe 走自签/中间人代理时更稳）
    """
    global _JEV_POOL
    if _JEV_POOL is not None:
        return _JEV_POOL
    import urllib3
    urllib3.disable_warnings()
    _px = TS_PROXY
    _JEV_POOL = urllib3.ProxyManager(
        _px,
        num_pools=4,
        maxsize=int(os.environ.get('T14_JEV_POOL_MAX', '32')),
        block=False,
        cert_reqs='CERT_NONE',
        assert_hostname=False,
        timeout=urllib3.Timeout(connect=3.0, read=float(os.environ.get('T14_JEV_TIMEOUT', '8'))),
        retries=False,
    )
    return _JEV_POOL

_JEV_CACHE = {}
_JEV_CACHE_TTL = float(os.environ.get('T14_JEV_CACHE_TTL', '300'))
_JEV_SKIP_READ = os.environ.get('T14_JEV_SKIP_READ', '1') not in ('0', 'false', 'off')


def _cache_key(method, url, body):
    # Lead 约束2：key 必须含 method+host+path+query+body 摘要（body 不可忽略，否则不同 payload 串判）
    try:
        u = urllib.parse.urlparse(url)
        import hashlib
        bh = hashlib.sha1((body or '').encode('utf-8', 'ignore')).hexdigest()[:16]
        return (str(method).upper(), (u.hostname or '').lower(), (u.path or '/')[:120],
                (u.query or '')[:200], bh)
    except Exception:
        return None


def jev_decide(method, url, headers, body):
    """Jev 优先；失败回退 DeepSeek；两者都失败时读方法放行、写方法拒绝（fail-closed）。"""
    _mm = str(method).upper()
    # (1) 只跳过「完全没有任何参数」的读请求（页面 / 静态资源）。
    #     2026-10-26：RCE 利用完全可能藏在 GET 的 query 里（?cmd=id），
    #     不能整类跳过，否则就是把判断权交给了「方法是 GET」这个粗规则。
    if _JEV_SKIP_READ and AUDIT_MODE == 'both' and _mm in ('GET', 'HEAD', 'OPTIONS'):
        _has_payload = False
        try:
            _u = urllib.parse.urlsplit(url or '')
            _has_payload = bool(_u.query) or bool((body or '').strip())
        except Exception:
            _has_payload = ('?' in (url or '')) or bool((body or '').strip())
        if not _has_payload:
            return True, [], {'by': 'skip', 'reason': 'bare-read(无参数读请求，无需询问模型)',
                              'model': 'skipped'}
    # (2) 缓存
    ck = _cache_key(method, url, body)
    if ck is not None:
        import time as _t
        hit = _JEV_CACHE.get(ck)
        if hit and (_t.time() - hit[0]) < _JEV_CACHE_TTL:
            return hit[1], list(hit[2]), dict(hit[3], cached=True)
    _res = _jev_decide_uncached(method, url, headers, body)

    # (3) 交叉校验（2026-10-25）：确定性层判定为 read 时，LLM 的「删改」意见降级为审计。
    #     实测案例：POST /api/user/list + {"status":"deleted"} 是「筛出已删除列表」，
    #     确定性层正确判为 read，但 LLM 看到 status=deleted 就报删改，导致正常查询被 403。
    #     确定性层基于结构（路径末段动词=list / 分页字段 / 是否携带目标资源 ID）判断，比 LLM 更可靠。
    try:
        _op = _LAST_OP_GET()
        # 2026-10-26 扩展：确定性层判定「新建(create)」时同样推翻 LLM 的删改意见。
        # 实测误拦：POST /api/cv/cover 被 Jev 以 conf=0.46 判「删改」拦掉
        #           （同一接口 972 条请求里仅此 1 条被拦，属模型抖动）。
        # create 意味着「不指向任何已存在资源」，与「删改已有数据」在结构上矛盾。
        # 2026-10-26：RCE 利用判定【不受】上述否决影响。
        # 「确定性层判 read/create」只能反驳「删改已有数据」，不能反驳「在服务器上执行利用命令」——
        # 后者是内容语义判断，结构规则根本表达不了（实测 chmod u+s 被错误放行）。
        # 纯语义模式（policy=jev）：规则层不参与拦截，也不得否决语义层。
        # 否则「保存资料 / 改密码」这类被规则层判成 create 的请求，
        # 会把 Jev 正确的「删改现有数据」结论否掉（实测 conf 0.97 仍被放行）。
        _jev_only = os.environ.get('GUARD_POLICY', '').strip().lower() == 'jev'
        _rce = float((_res[2] or {}).get('rce') or 0.0)
        _rce_gate = _rce if RCE_ENFORCE else 0.0
        _overrule = (not _jev_only) and _op in ('read', 'create') and not _res[0] and _rce_gate <= 0.60
        # 2026-11-02 收紧：create 分类只在【模型自身低置信】时才否决。
        # 原先 create 无条件否决，导致载荷型删改（GraphQL mutation / 路径 transfer /
        # 请求体或 query 里的裸 SQL，Jev conf 0.67~0.98）被结构分类器放行——
        # 结构分类器对非 REST 形态不可靠，不能无条件压过高置信语义结论。
        # read 分类保持无条件否决（GET 页面/列表查询的误拦代价最高，且实例充分）。
        if _overrule and _op == 'create':
            _conf_now = float((_res[2] or {}).get('conf') or 0.0)
            _overrule = _conf_now < TS_MIN_CONF
        # 2026-11-02：确定性层自身识别出破坏性载荷（payload_signal / mutation_signal
        # 审计线索）时不得否决 Jev 的删改结论 —— det 内容特征与 Jev 语义两个独立信号
        # 同时指向破坏性，属 dml 口径应拦的「删除/修改」（实测漏拦：裸 SQL 在 body 或
        # query、GraphQL mutation conf 0.98 被结构分类器放行）。
        if _overrule:
            try:
                if _sem.last_destructive_signal():
                    _overrule = False
            except Exception:
                pass
        if _overrule:
            _info = dict(_res[2] or {})
            _info['llm_overruled'] = ('确定性层判定为 %s%s，LLM 删改意见仅记录'
                                      % (_op, '' if _op == 'read' else '（模型低置信 conf=%.2f）' % _conf_now))
            _res = (True, [], _info)
    except Exception:
        pass

    # 只缓存「放行」结论，且必须模型真的给出过判定（by=jev/deepseek），避免把 fail 状态固化
    try:
        _m2 = str(method).upper()
        _u2 = urllib.parse.urlparse(url)
        _host2 = (_u2.hostname or '').lower()
        _readonly = (_m2 in ('GET', 'HEAD', 'OPTIONS')) and in_scope(_host2)
        # Lead 约束2：只缓存「范围内只读」的放行结论；写方法与命中敏感/删除语义的不缓存
        if (ck is not None and _res[0] and _readonly
                and (_res[2] or {}).get('by') in ('jev', 'deepseek')):
            import time as _t
            _JEV_CACHE[ck] = (_t.time(), _res[0], list(_res[1]), dict(_res[2]))
    except Exception:
        pass
    return _res


def _jev_decide_uncached(method, url, headers, body):
    if TS_KEY:
        try:
            return _ask_jev(method, url, headers, body)
        except Exception as e:
            jerr = str(e)[:70]
    else:
        jerr = 'no jev key'
    try:
        allow, reasons, info = _ask_deepseek(method, url, headers, body)
        info['jev_error'] = jerr
        return allow, reasons, info
    except Exception as e2:
        # T14 (2026-10-25)：语义层整体不可用时改为 fail-closed。
        # 折中：读方法（GET/HEAD/OPTIONS）已过确定性层，保持放行，避免护栏自伤让整条战线停摆；
        #       写方法（POST 等）一律拒绝——写请求的风险不能交给「默认放行」。
        _mm = str(method).upper()
        _err = str(e2)[:60]
        _istimeout = ('timeout' in _err.lower() or 'timed out' in _err.lower())
        _mark = 'timeout-failclosed' if _istimeout else 'error-failclosed'
        if _mm in ('GET', 'HEAD', 'OPTIONS'):
            # Lead 约束1：不置可否时，只读方法仍须由确定性层把关，这里交回确定性结论
            return True, ['语义层不可用(%s)→读方法按确定性层判' % _err], {'by': 'none', 'fail': _mark}
        return False, ['语义层不可用(%s)→写方法 fail-closed 拒绝' % _err], {'by': 'none', 'fail': _mark}

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def __getattr__(self, name):
        if name.startswith('do_'):
            return self.proxy
        raise AttributeError(name)
    def record(self, method, url, allow, reasons):
        # 2026-11-23: 自检探针（jev-local-probe.timer 打本地 echo 靶站）不写入审计日志，
        # 避免污染真实流量统计。探针结果见观测台探针专区。
        try:
            _h = (urllib.parse.urlsplit(url or '').hostname or '').lower()
            if _h in ('probe.jev.internal', 'probe2.jev.internal', 'probe.jev.local', 'probe2.jev.local'):
                return
        except Exception:
            pass
    def proxy(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n).decode('utf-8','ignore') if n > 0 else ''
        url = self.path
        allow, reasons = decide(self.command, url, self.headers, body)
        info = {}
        if AUDIT_MODE in ('jev', 'both'):
            jallow, jreasons, info = jev_decide(self.command, url, self.headers, body)
            if AUDIT_MODE == 'jev':
                allow, reasons = jallow, jreasons
            else:
                # both：全流量都过 Jev 审计，任一判定拒绝即拒绝
                if not jallow:
                    allow = False
                    reasons = list(reasons) + jreasons
        self.record(self.command, url, allow, reasons + (['jev:' + json.dumps(info, ensure_ascii=False)] if info else []))
        if not allow:
            # 2026-11-23：返回结构化「策略拒绝」信号，供 Artex 识别为"不要再试"。
            # 关键字段：policy_block=true / retryable=false / action=stop
            msg = json.dumps({
                'blocked': True,
                'by': 'artex-audit-guard',
                'policy_block': True,
                'retryable': False,
                'action': 'stop',
                'error': 'POLICY_BLOCKED',
                'message': '该请求被审计护栏按策略永久拒绝，重试无意义，请改用其他验证方法或产出存疑性 finding',
                'reasons': reasons,
            }, ensure_ascii=False).encode()
            self.send_response(403)
            self.send_header('Content-Type','application/json')
            self.send_header('X-Artex-Policy-Block','1')
            self.send_header('X-Artex-Retryable','0')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Length',str(len(msg))); self.end_headers(); self.wfile.write(msg); return
        try:
            data = body.encode() if body else None
            req = urllib.request.Request(url, data=data, method=self.command)
            for k, v in self.headers.items():
                if k.lower() not in ('proxy-connection','connection','host','content-length'): req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=25) as r:
                out = r.read(); self.send_response(r.status)
                self.send_header('Content-Type', r.headers.get('Content-Type','application/json'))
                self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)
        except urllib.error.HTTPError as e:
            out = e.read(); self.send_response(e.code)
            self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
        except Exception as e:
            msg = json.dumps({'error':str(e)[:120]}).encode()
            self.send_response(502); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(msg))); self.end_headers(); self.wfile.write(msg)
    def do_GET(self): self.proxy()
    def do_HEAD(self): self.proxy()
    def do_POST(self): self.proxy()
    def do_PUT(self): self.proxy()
    def do_DELETE(self): self.proxy()
    def do_PATCH(self): self.proxy()
    def do_OPTIONS(self): self.proxy()
    def do_TRACE(self): self.proxy()
    def do_CONNECT(self): self.proxy()
    def do_MOVE(self): self.proxy()
    def do_COPY(self): self.proxy()
    def do_PROPPATCH(self): self.proxy()
    def do_PROPFIND(self): self.proxy()
    def do_MKCOL(self): self.proxy()
    def do_LOCK(self): self.proxy()
    def do_UNLOCK(self): self.proxy()
    def do_PURGE(self): self.proxy()
    def do_REPORT(self): self.proxy()
    def do_SEARCH(self): self.proxy()
if __name__ == '__main__':
    import os as _os
    BIND=_os.environ.get('GUARD_BIND','127.0.0.1')
    PORT=int(_os.environ.get('GUARD_PORT','9100'))
    open(AUDIT,'a').write('----- guard up %s:%d -----' % (BIND,PORT) + chr(10))
    http.server.ThreadingHTTPServer((BIND,PORT),H).serve_forever()
