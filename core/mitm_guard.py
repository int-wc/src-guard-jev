# mitmproxy addon：复用 guard.py 的确定性规则 + Jev 审计
# T14 (2026-10-25)：改为 async addon + 线程池，解决同步语义层阻塞事件循环导致的
# 1~30s 延迟与并发 000。判定逻辑本身仍委托 guard.py，保持单一事实来源。
import os, sys, re, json, datetime, asyncio, concurrent.futures, urllib.parse
_CORE = os.environ.get('GUARD_BASE', os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _CORE)
from mitmproxy import http
import importlib.util
spec = importlib.util.spec_from_file_location('gd', os.path.join(_CORE, 'guard.py'))
gd = importlib.util.module_from_spec(spec); spec.loader.exec_module(gd)
LOG = os.environ.get('GUARD_LOG', os.path.join(_CORE, 'mitm-audit.log'))

# 线程池：语义层调用都在池里跑，事件循环只负责 await，不再被阻塞
_WORKERS = int(os.environ.get('T14_LLM_WORKERS', '12'))
_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix='t14sem')
# 单请求语义层硬超时（秒）。超时立即按 fail-closed 处理，不让请求无限挂起。
SEM_TIMEOUT = float(os.environ.get('T14_SEM_TIMEOUT', '3.0'))

LLM_KEYS = ('api.deepseek.com', 'api.openai.com', 'opencode.ai',
            '127.0.0.1:3000', '127.0.0.1:8323', '127.0.0.1:8330')
LLM_HOSTS = ('api.deepseek.com', 'api.openai.com', 'opencode.ai',
             '127.0.0.1:3000', '127.0.0.1:8323', '127.0.0.1:8330')


# 2026-11-23：自检探针专用主机 —— 不写入审计日志，避免污染真实流量统计。
# 这些是 jev-local-probe.timer 每 10 分钟跑一次的护栏自检流量（打到本地 echo 靶站），
# 不是真实渗透业务，混进 mitm-audit.log 会让面板的拦截率/DoS 计数虚高。
# 需要看探针结果请查阅观测台「探针专区」。
_PROBE_HOSTS = ('probe.jev.internal', 'probe2.jev.internal', 'probe.jev.local', 'probe2.jev.local')

def _is_selfprobe(rec):
    try:
        h = str(rec.get('h') or '').lower()
        return h in _PROBE_HOSTS
    except Exception:
        return False

def _log(rec):
    if _is_selfprobe(rec):
        return
    try:
        with open(LOG, 'a') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + chr(10))
    except Exception:
        pass


# ============ 硬拦截：可能导致数据修改的请求 ============
# 2026-10-25 优化：
#  (1) 关键词从「子串包含」改为「分词后精确匹配」——原实现把 dropdown 的 drop、
#      deletedItems 的 delete、purgeable 的 purge 都当删除动作，属纯误伤。
#  (2) __VIEWSTATE/__EVENTTARGET 不再一律拦。ASP.NET 站点的**登录页、查询页**必然带
#      __VIEWSTATE，原规则把正常登录直接 403；改为只在事件目标确实是删除类动作时才拦。
# 2026-10-26 用户要求：「先将 JEV 设置成什么都不拦截」。
#   GUARD_ENFORCE=0 → 只审计不拦截：所有请求原样放行，但照常写下判定结果与 would_block，
#                     便于随时查看「如果没有关掉，本来会拦什么」。
#   GUARD_ENFORCE=1（默认）→ 恢复正常拦截。
#   改完需 systemctl --user restart jev-proxy 生效。
ENFORCE_MODE = os.environ.get('GUARD_ENFORCE', '1').strip().lower() \
    not in ('0', 'false', 'off', 'no', 'audit', 'audit-only')


HARD_BLOCK_METHODS = ('DELETE', 'PUT', 'PATCH')
HARD_BLOCK_POST_KEYWORDS = (
    'delete', 'remove', 'destroy', 'purge', 'drop', 'truncate', 'wipe',
    'erase', 'unlink',
)
# Web Forms 里代表「删除/清除」的控件名特征（用于 __EVENTTARGET 判定）
_ASPX_DEL_HINT = ('delete', 'remove', 'destroy', 'purge', 'drop', 'truncate', 'wipe',
                  'erase', 'unlink', 'clear', 'reset')

# 2026-11-02 SRC 护栏（Lead 会话按用户授权动态调整）：
# 用户口径：禁止删除/修改/新建/上传/发送等 state-changing 操作（「类似删除概念」），
# 但允许只读探测与最小 RCE 验证。仅在【语义层不可用(超时/异常)】时用本表兜底：
#   · 命中 state-changing 路径关键词 → fail-closed 拦截（含 GET 型副作用，如 send-captcha）；
#   · 写方法(POST/PUT/PATCH/DELETE) → 一律 fail-closed（语义层不可用时无法区分读/写语义）。
_SRC_SIDE_EFFECT_PATH_TOKENS = (
    'sendcaptcha','send-captcha','sendemail','send-email','sendsms','send-sms','/sms',
    'register','signup','sign-up','/upload','upload/','verify/file',
    '/create','/delete','/remove','/update','/reset','rebind','rebinding','unbind',
    '/apply','/commit','/refund','/redeem','exchange','/grant','/assign','/import',
)


def _tokens(s):
    """按非字母数字与 camelCase 切词，统一小写。"""
    out = []
    for seg in re.split(r'[^A-Za-z0-9]+', s or ''):
        if not seg:
            continue
        for x in re.split(r'(?<=[a-z0-9])(?=[A-Z])', seg):
            if x:
                out.append(x.lower())
    return out


def _hard_block_reason(method, url, body=''):
    m = method.upper()
    if m in HARD_BLOCK_METHODS:
        return 'HARD_BLOCK: 写方法 ' + m
    if m == 'POST':
        try:
            path = urllib.parse.urlparse(url).path
        except Exception:
            path = url
        toks = set(_tokens(path))
        for k in HARD_BLOCK_POST_KEYWORDS:
            if k in toks:
                return 'HARD_BLOCK: POST 到修改类路径(含 "%s" 动作词)' % k
        # ASP.NET 表单：只有事件目标本身是删除类动作才拦，登录/查询表单放行
        blob = (url or '') + ' ' + (body or '')
        low = blob.lower()
        if '__viewstate' in low or '__eventtarget' in low:
            ev = ''
            mm = re.search(r'__eventtarget\s*=\s*([^&\s]*)', blob, re.I)
            if mm:
                ev = urllib.parse.unquote(mm.group(1))
            ev_toks = set(_tokens(ev))
            if ev and (ev_toks & set(_ASPX_DEL_HINT)):
                return 'HARD_BLOCK: ASP.NET 表单提交删除事件(%s)' % ev[:40]
    return None


# 2026-10-26 dml 口径：只凭「body 里带 id」推断出来的「修改」是最弱的证据。
# 例：SQLi 探测 {"id":"1 OR sleep(5)"} 会被判成「修改已存在资源」而误拦，
# 但它并没有修改任何东西。这类弱证据不自己下结论，交给 Jev 语义层裁定。
# 2026-11-02（用户授权）：弱证据集合扩展为三类 ——
#   · 仅「携带目标资源标识」推断的修改（原有）；
#   · 仅「路径末段修改动作」推断的修改（applyPermission → apply 这类词表多义误伤）；
#   · 读方法（GET）仅因路径末段动作词被判修改（setCookie → set）。
# 背景：/oa/ledoc/web/space/applyPermission.json（申请权限）被规则5判 update 拦截，
# Jev 判 no_destructive_impact（conf 0.77~0.92）也无法放行；面板口径是
# 「原始请求报文直接交 Jev 判定」，这类仅靠路径动词推断的修改应与「携带 id」同属弱证据。
_WEAK_UPDATE_REASONS = (
    '携带目标资源标识→修改已存在资源',
    '路径末段修改动作=',
    '读方法但路径末段为修改动作=',
)
# 改判保护：Jev 置信度达标 + 确定性层无破坏性载荷线索时才放开，防止弱证据被滥用。
_WEAK_JEV_MIN_CONF = float(os.environ.get('T14_WEAK_JEV_MIN_CONF', '0.60'))


def _policy():
    try:
        return str(os.environ.get('GUARD_POLICY', '')).strip().lower()
    except Exception:
        return ''


def _jev_only():
    """纯语义模式：规则层（含硬拦截）一律不拦截，全部交给 Jev 判定。"""
    return _policy() == 'jev'


def _dml_mode():
    try:
        return str(os.environ.get('GUARD_POLICY', '')).strip().lower() == 'dml'
    except Exception:
        return False


def _weak_only(reasons):
    rs = [str(x) for x in (reasons or [])]
    return bool(rs) and all(any(w in r for w in _WEAK_UPDATE_REASONS) for r in rs)


def _weak_guard_ok(info):
    """弱证据改判的保护条件。返回 (ok, 拒绝原因)。"""
    # 2026-11-02：Jev 对「无参数读请求」按设计直接放行（bare-read skip），此时没有
    # conf 字段；不应把 skip 当成「置信度不足」拒绝改判（实测误拦：下载 .php 源码）。
    if str((info or {}).get('by') or '') == 'skip':
        return True, 'Jev skip(无参数读请求，设计放行)'
    try:
        conf = float((info or {}).get('conf') or 0.0)
    except Exception:
        conf = 0.0
    if conf < _WEAK_JEV_MIN_CONF:
        return False, 'Jev conf=%.2f < %.2f' % (conf, _WEAK_JEV_MIN_CONF)
    try:
        import guard_semantic as _gs
        _sig = _gs.last_destructive_signal()
    except Exception:
        _sig = None
    if _sig:
        return False, '确定性层载荷线索=%s' % (str(_sig[0])[:60],)
    return True, ''


# 2026-11-02（用户要求）：源码托管域名下载豁免。
# GitHub / jsDelivr / Gitee 等代码托管域名的只读下载（GET/HEAD/OPTIONS）不涉及
# 修改目标数据，但路径末段文件名常含 set/update/edit 等词
# （如 SetValForbiddenException.php），会被规则5
# 「读方法但路径末段为修改动作=set」误拦。此处直接放行并写审计。
# 可用环境变量 GUARD_DOWNLOAD_EXEMPT_HOSTS（逗号分隔）追加/覆盖。
DEFAULT_DOWNLOAD_EXEMPT_HOSTS = (
    # github.com 覆盖 codeload./api./gist. 等子域；githubusercontent.com 覆盖
    # raw./gist./objects./avatars. 等子域（后缀匹配已处理子域，无需逐条列）。
    'github.com', 'githubusercontent.com', 'github.io',
    'raw.githack.com', 'cdn.jsdelivr.net', 'fastly.jsdelivr.net',
    'cdn.statically.io', 'gitee.com', 'gitlab.com', 'bitbucket.org',
    'unpkg.com', 'registry.npmjs.org', 'cdnjs.cloudflare.com', 'esm.sh',
)
DOWNLOAD_EXEMPT_HOSTS = tuple(
    x.strip().lower().lstrip('.')
    for x in os.environ.get('GUARD_DOWNLOAD_EXEMPT_HOSTS',
                            ','.join(DEFAULT_DOWNLOAD_EXEMPT_HOSTS)).split(',')
    if x.strip()
)
DOWNLOAD_EXEMPT_METHODS = ('GET', 'HEAD', 'OPTIONS')


def _download_exempt(method, url):
    """代码托管域名的只读下载豁免；返回命中的域名，无则返回空串。"""
    if str(method or '').upper() not in DOWNLOAD_EXEMPT_METHODS:
        return ''
    try:
        host = (urllib.parse.urlsplit(url).hostname or '').lower()
    except Exception:
        return ''
    if not host:
        return ''
    for h in DOWNLOAD_EXEMPT_HOSTS:
        if host == h or host.endswith('.' + h):
            return h
    return ''


def _dos_hard_block(method, url, headers, body):
    """⛔ DoS 硬拦截（2026-10-29 新增，不依赖 Jev 语义层）。

    用户要求：可能影响业务、导致 DDoS/服务不可用的请求必须拦截。
    事故背景：测 linkAnalyze 响应大小限制时，2 MB 文本请求把后端 Python
              线程池占满，该接口 POST 挂起 20+ 分钟。

    独立于此前的规则层/Jev 判定，因为实测发现：
      GUARD_POLICY=jev 模式下规则层被无条件放行（_jev_only() → allow=True），
      Jev 又把 2 MB 请求判成 no_destructive_impact（conf 0.46），两道防线都没拦住。

    返回 (blocked: bool, reason: str)。
    """
    try:
        import guard_semantic as _gs
        # 复用语义层的 find_dos（含大载荷/长等待/高并发/深递归检测）
        f = _gs.parse(method, url, headers, body)
        hit = _gs.find_dos(f)
        if hit:
            return True, '【DoS 硬拦截】' + str(hit)
        # 双保险：直接测请求体字节数（不依赖 find_dos 的实现细节）
        _lim = int(_gs.CFG.get('dos_body_max', 100 * 1024))
        if body:
            _n = len(body if isinstance(body, (bytes, bytearray)) else str(body).encode('utf-8', 'ignore'))
            if _n > _lim:
                return True, '【DoS 硬拦截】请求体 %d 字节 > %d 字节上限' % (_n, _lim)
    except Exception as _e:
        # 硬拦截自身的异常不能影响主流程，但要记下来
        return False, 'dos_hard_block_error:%s' % str(_e)[:80]
    return False, ''


def _evaluate(method, url, headers, body, host, isllm):
    """在线程池里执行的完整判定（同步、可能耗时）。返回 (allow, reasons, info)。"""
    # ⛔ 最高优先级：DoS 硬拦截（2026-10-29 新增）。
    # 放在所有模式判断之前，无论 GUARD_POLICY 是 jev/dml/strict 都强制生效。
    # 理由：这类请求单次就可能让目标服务长时间不可用，不属于「测试手法」范畴，
    #       不应交给语义模型判断，也不应被规则层放行逻辑绕过。
    _dos_block, _dos_why = _dos_hard_block(method, url, headers, body)
    if _dos_block:
        return False, [_dos_why], {'by': 'dos-hard-block', 'rule_layer': 'hard'}

    # 2026-11-02（用户要求）：源码托管域名下载豁免（只读，记审计）。
    _dl_host = _download_exempt(method, url)
    if _dl_host:
        return True, ['源码下载豁免(%s)：代码托管域名只读请求' % _dl_host], \
               {'by': 'download-exempt', 'rule_layer': 'allowlist', 'host': _dl_host}

    allow, reasons = gd.decide(method, url, headers, body)
    info = {}
    _jo = _jev_only()
    if _jo:
        # 纯语义模式：规则层结论只写审计，不参与拦截
        info['rule_layer'] = 'audit-only'
        info['rule_reasons'] = [str(x) for x in (reasons or [])][:4]
        allow = True
        reasons = (['规则层仅审计（不拦截）：' + '；'.join(str(x) for x in reasons)[:120]]
                   if reasons else ['规则层仅审计：未命中'])
    if gd.AUDIT_MODE in ('jev', 'both'):
        jallow, jreasons, info = gd.jev_decide(method, url, headers, body)
        if gd.AUDIT_MODE == 'jev':
            allow, reasons = jallow, jreasons
        elif not jallow:
            # READ_METHOD_NEVER_BLOCK：读只读探测，Jev 语义意见只记录不拦截。
            # 纯语义模式下不再豁免 —— 规则层不兜底了，GET 也可能承载删除/利用。
            if (not _jo) and str(method).upper() in ('GET', 'HEAD', 'OPTIONS'):
                reasons = list(reasons) + ['Jev意见(读方法不拦截):' + '；'.join(
                    [str(x) for x in jreasons])[:80]]
            else:
                allow = False; reasons = list(reasons) + jreasons
        elif (not allow) and _dml_mode() and _weak_only(reasons):
            # 确定性层仅凭「携带 id」或「路径末段动词」推断为修改，而 Jev 判无破坏性影响 →
            # 以语义层结论为准（注入/越权探测/申请权限等业务端点都属于这一类，不该拦）。
            # 2026-11-02：改判加保护 —— Jev 置信度不足或确定性层识别出破坏性载荷时不放开。
            _ok, _why_not = _weak_guard_ok(info)
            if _ok:
                info = dict(info or {})
                info['weak_overruled'] = '仅弱证据推断出的修改，Jev 判无破坏性影响 → 放行'
                allow = True
                reasons = ['弱证据改判：Jev 语义层判定无破坏性影响'] + list(reasons)
            else:
                reasons = list(reasons) + ['弱证据改判被拒：' + _why_not]
    if isllm and not allow:
        allow = True
        reasons = ['LLM出口放行(仅审计不拦截)'] + list(reasons)
    return allow, reasons, info


def _failclosed(method, url, headers, body, isllm, why):
    # 2026-11-02 SRC 护栏：语义层不可用时的兜底（用户授权）
    try:
        _p0 = urllib.parse.urlparse(url).path.lower()
    except Exception:
        _p0 = str(url or '').lower()
    for _k0 in _SRC_SIDE_EFFECT_PATH_TOKENS:
        if _k0 in _p0:
            return False, ['语义层不可用(%s)→命中 state-changing 路径(%s)，fail-closed(SRC)' % (str(why)[:40], _k0)], {'by': 'none', 'fail': why}
    _m0 = str(method or '').upper()
    if _m0 not in ('GET', 'HEAD', 'OPTIONS'):
        return False, ['语义层不可用(%s)→写方法 fail-closed(SRC)' % str(why)[:40]], {'by': 'none', 'fail': why}
    if _jev_only():
        # 纯语义模式：规则层平时不拦截。但语义层不可用（超时/异常）时，
        # 如果规则层明确判定为「删除/修改」，仍兜底拦截 —— 这两种操作是
        # 用户唯一要求拦的类别，不能因为模型超时就整体放行。
        # 其余类别（读、探测、上传、拖库…）在语义层不可用时一律放行。
        try:
            dallow, dreasons = gd.decide(method, url, headers, body)
            _rs = '；'.join(str(x) for x in (dreasons or []))
            if (not dallow) and ('删除' in _rs or '修改' in _rs or '覆盖' in _rs):
                return False, ['语义层不可用，规则层兜底(仅删改)：' + _rs[:110]], \
                       {'by': 'rule-fallback', 'fail': why}
        except Exception:
            pass
        return True, ['语义层不可用，纯语义模式放行：' + str(why)[:80]], {'by': 'none', 'fail': why}
    """LLM 超时/异常时的降级判定。

    2026-10-25 修正（重要）：原实现在 LLM 超时时只按 HTTP 方法决定放行与否
    —— GET/HEAD/OPTIONS 放行，其余一律拒绝。但业务请求大量用 POST 做查询
    （/expert/list、/member/query、/channels/search、/sso/login …），
    实测导致 28 条正常业务被 fail-closed 误拦。

    正确做法：LLM 只是「语义补充」，超时时应当**退回确定性语义层**的结论。
    确定性层（guard_semantic）已把请求解析成 read/create/update/delete 四类：
      · 判定 delete/update/replace → 维持拦截（真风险，不能因 LLM 超时放过）
      · 判定 read/create          → 放行（LLM 没参与，不该凭空加严）
      · 确定性层自身异常          → 写方法 fail-closed，读方法放行
    """
    m = str(method).upper()
    try:
        dallow, dreasons = gd.decide(method, url, headers, body)
    except Exception:
        dallow, dreasons = None, ['确定性层异常']
    if dallow is None:
        if m in ('GET', 'HEAD', 'OPTIONS'):
            allow, reasons = True, [why + '；确定性层异常→读方法放行']
        else:
            allow, reasons = False, [why + '；确定性层异常→写方法拒绝']
    elif not dallow:
        allow, reasons = False, list(dreasons) + [why]
    else:
        allow, reasons = True, list(dreasons) + [why + '(LLM超时→按确定性层结论)']
    if isllm and not allow:
        allow = True
        reasons = ['LLM出口放行(仅审计不拦截)'] + reasons
    return allow, reasons, {'by': 'none', 'fail': why}


def _req_body(flow) -> str:
    """取请求体文本，并【按 Content-Encoding 解压】。

    2026-10-26 修漏拦（重要）：
        旧实现直接 flow.request.get_text()，对 Content-Encoding: gzip 的请求
        解出来是乱码（二进制被当 UTF-8 强行解码），护栏完全看不见载荷内容：
            POST /api/order
            Content-Encoding: gzip
            <gzip 压缩的 {"orderId":1,"status":"deleted"}>
        → 软删除/GraphQL mutation/SOAP 删除全部能靠「压缩一下」绕过。

    这里只在【本地副本】上解压，不修改要转发的 flow，
    避免把请求体变成明文影响目标服务器的解析。
    """
    raw = b''
    try:
        raw = flow.request.content or b''
    except Exception:
        return ''
    enc = ''
    try:
        enc = (flow.request.headers.get('Content-Encoding') or '').strip().lower()
    except Exception:
        enc = ''
    if enc and raw:
        _dec = None
        try:
            from mitmproxy.net import encoding as _menc
            _dec = _menc.decode(enc, raw)
        except Exception:
            _dec = None
        if _dec is None:
            try:
                import gzip as _g
                import zlib as _z
                if 'gzip' in enc:
                    _dec = _g.decompress(raw)
                elif 'deflate' in enc:
                    try:
                        _dec = _z.decompress(raw)
                    except Exception:
                        _dec = _z.decompress(raw, -_z.MAX_WBITS)
            except Exception:
                _dec = None
        if _dec:
            raw = _dec
    try:
        return raw.decode('utf-8', 'replace')
    except Exception:
        return ''


async def request(flow: http.HTTPFlow) -> None:
    method = flow.request.method
    url = flow.request.pretty_url
    headers = dict(flow.request.headers)
    body = _req_body(flow)
    # 透明模式(REDIRECT)下 flow.request.host 会退化为主机 IP，导致域名作用域匹配失效。
    # pretty_host 优先取 Host 头 / TLS SNI，两种模式都能拿到域名。
    host = (getattr(flow.request, 'pretty_host', '') or flow.request.host or '').lower()
    _hp = host if flow.request.port in (80, 443) else (host + ':' + str(flow.request.port))
    isllm = (host in LLM_HOSTS) or (_hp in LLM_HOSTS) or any(k in url for k in LLM_KEYS)

    # ---- 硬拦截优先，不经过线程池 ----
    _hb = _hard_block_reason(method, url, body)
    if _hb:
        try:
            _scope0 = gd.scope_label(host)
        except Exception:
            _scope0 = 'unknown'
        _log({'pid': os.getpid(), 'h': host, 'isllm': False, 'scope': _scope0,
              'ts': datetime.datetime.now().isoformat(),
              'method': method, 'url': url[:200],
              'allow': False, 'would_block': True,
              'enforced': bool(ENFORCE_MODE) and not _jev_only(),
              'reasons': [_hb], 'jev': {'hard_block': True}})
        if ENFORCE_MODE and not _jev_only():
            flow.response = http.Response.make(
                403, _hb.encode('utf-8'), {'Content-Type': 'text/plain; charset=utf-8'})
            return
        # 只审计模式：硬拦截也只记录，继续放行（不 return）

    loop = asyncio.get_running_loop()
    try:
        allow, reasons, info = await asyncio.wait_for(
            loop.run_in_executor(_POOL, _evaluate, method, url, headers, body, host, isllm),
            timeout=SEM_TIMEOUT)
    except asyncio.TimeoutError:
        allow, reasons, info = _failclosed(method, url, headers, body, isllm,
                                           'timeout-failclosed(语义层>%.1fs)' % SEM_TIMEOUT)
    except Exception as e:
        allow, reasons, info = _failclosed(method, url, headers, body, isllm,
                                           'error-failclosed(%s)' % str(e)[:50])

    # 2026-10-25：强制拦截扩展到全部主机（LLM 出口与本机回环服务豁免）
    _isloop = host in ('127.0.0.1', 'localhost') or host.startswith('127.0.0.1') \
        or host.startswith('localhost')
    ENFORCE_ENABLED = (not _isloop) and bool(ENFORCE_MODE)
    _would_block = not allow
    # 2026-10-26 全站审计：每条记录都带 scope 标注（whitelist / other / loopback），
    # 便于统计「有多少测试流量打在原白名单之外」，白名单本身已不再触发拦截。
    try:
        _scope = gd.scope_label(host)
    except Exception:
        _scope = 'unknown'
    _log({'pid': os.getpid(), 'h': host, 'isllm': isllm, 'scope': _scope,
          'ts': datetime.datetime.now().isoformat(),
          'method': method, 'url': url[:200],
          'allow': allow, 'would_block': _would_block, 'enforced': ENFORCE_ENABLED,
          'reasons': (reasons or [])[:4], 'jev': info})
    if ENFORCE_ENABLED and _would_block:
        _joined = '；'.join([str(x) for x in (reasons or [])])
        # 限速与策略拦截区分开：限速回 429 + Retry-After，避免战线把「降速」误判成「越界/被封」
        if 'RATE_LIMIT' in _joined:
            _msg = 'rate limited by guard | ' + _joined[:300]
            flow.response = http.Response.make(
                429, _msg.encode('utf-8'),
                {'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '1'})
            return
        # 2026-11-23：返回结构化「策略拒绝」信号，供 Artex 识别为「不要再试」
        # 避免它把 403 当网络错误而毫秒级狂重试（曾 7 秒重试 34 次）
        _msg = 'blocked by jev guard | ' + _joined[:300]
        import json as _json
        _body = _json.dumps({
            'blocked': True,
            'by': 'artex-audit-guard',
            'policy_block': True,
            'retryable': False,
            'action': 'stop',
            'error': 'POLICY_BLOCKED',
            'message': '该请求被审计护栏按策略永久拒绝，重试无意义；请改用其他验证手法，或在报告中产出存疑性 finding',
            'detail': _joined[:300],
        }, ensure_ascii=False)
        flow.response = http.Response.make(
            403, _body.encode('utf-8'),
            {'Content-Type': 'application/json; charset=utf-8',
             'X-Artex-Policy-Block': '1',
             'X-Artex-Retryable': '0',
             'Cache-Control': 'no-store',
             'X-Blocked-Reason': _joined[:120].encode('ascii','replace').decode('ascii')})
