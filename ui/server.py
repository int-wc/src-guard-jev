#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jev-live —— Jev 护栏实时观测台（第一性原理设计）

唯一真源 : mitm-audit.log（append-only JSONL）
职责     :
  1) 增量 tail 该文件，把每条审计记录以 SSE 亚秒级推给浏览器
  2) 维护指标：总数/放行/拦截/判定层/Jev kind/理由/主机/每分钟桶/误截疑似
  3) 只读暴露"当前策略"（现场 import guard.py，确保与线上判定同源）
  4) 策略模拟器：本地执行 guard.decide()/jev_decide()，演示判定链路，不产生任何目标侧流量
只读约束 : 不写日志、不改配置、不触发任何目标请求
"""
import json, os, re, time, threading, queue, datetime, collections, importlib.util, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.environ.get('GUARD_ROOT', os.path.dirname(_HERE))
_CORE = os.environ.get('GUARD_BASE', os.path.join(_ROOT, 'core'))

LOG   = os.environ.get('GUARD_LOG', os.path.join(_CORE, 'mitm-audit.log'))
PROBE_LOG   = os.environ.get('GUARD_PROBE_LOG', os.path.join(_ROOT, 'probe_history.jsonl'))
PROBE_SCRIPT = os.environ.get('GUARD_PROBE_SCRIPT', os.path.join(_ROOT, 'probes', 'local_probe.py'))
GUARD = os.path.join(_CORE, 'guard.py')
MITM  = os.path.join(_CORE, 'mitm_guard.py')  # LLM_KEYS_PARSE：LLM 出口豁免名单在这里
HTML  = os.path.join(_HERE, 'index.html')
BIND  = ('0.0.0.0', 8789)
RING  = 4000

LOCK = threading.Lock()
SUBS_SCOPE = {}
SUBS = []


# ===== 2026-11-04: 战役分组过滤（scope groups）=====
# 目的：jev-live 的 hosts/reasons 只显示 Top-N，历史高流量战役会把新战役挤掉。
# 这里按域名后缀把请求归入"战役"，前端可切换只看某个战役。
# ===== 2026-11-04: 战役分组（动态可扩展）=====
# 设计：分组配置外置到 JSON 文件，支持热重载 + HTTP API 增删改。
# 新增战役时无需改代码、无需重启：调用 /api/scopes 或直接编辑 JSON 后 reload。
SCOPES_FILE = os.environ.get('JEV_SCOPES_FILE', os.path.join(_ROOT, 'scopes.json'))

# 默认分组（首次启动若无 JSON 文件则写入）
DEFAULT_SCOPES = {
    "version": 1,
    "groups": [
        {"key": "customer-a", "label": "客户 A", "color": "#e8562a",
         "suffixes": ["customer-a.example", "customer-a-alt.example"]},
        {"key": "customer-b", "label": "客户 B", "color": "#00b4a6",
         "suffixes": ["customer-b.example"]},
        {"key": "customer-c", "label": "客户 C", "color": "#2f6fdb",
         "suffixes": ["customer-c.example"]},
        {"key": "public", "label": "公开测试目标", "color": "#8b5cf6",
         "suffixes": ["example.com", "example.org"]},
    ],
}


_SCOPES = {"mtime": 0, "groups": {}, "labels": {}, "colors": {}, "order": []}



def _write_default_scopes():
    try:
        os.makedirs(os.path.dirname(SCOPES_FILE), exist_ok=True)
        with open(SCOPES_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_SCOPES, f, ensure_ascii=False, indent=2)
        print('[scopes] 已生成默认配置', SCOPES_FILE)
    except Exception as e:
        print('[scopes] 写默认配置失败:', e)


def _apply_scopes(cfg):
    groups, labels, colors, order = {}, {}, {}, []
    for g in (cfg.get('groups') or []):
        k = str(g.get('key') or '').strip().lower()
        if not k:
            continue
        sufs = tuple(str(s).strip().lower() for s in (g.get('suffixes') or []) if str(s).strip())
        groups[k] = sufs
        labels[k] = str(g.get('label') or k)
        colors[k] = str(g.get('color') or '#64748b')
        order.append(k)
    labels['other'] = '其它'
    colors.setdefault('other', '#94a3b8')
    _SCOPES['groups'] = groups
    _SCOPES['labels'] = labels
    _SCOPES['colors'] = colors
    _SCOPES['order'] = order
    _SCOPES['cache_dirty'] = True


def _scope_cache_clear():
    try:
        with LOCK:
            S['by_scope'] = {}
    except Exception:
        pass


def load_scopes(force=False):
    """读取 scopes.json；文件 mtime 变化时自动热重载。"""
    try:
        if not os.path.exists(SCOPES_FILE):
            _write_default_scopes()
        mtime = os.path.getmtime(SCOPES_FILE)
        if force or mtime != _SCOPES['mtime'] or not _SCOPES['groups']:
            with open(SCOPES_FILE, encoding='utf-8') as f:
                cfg = json.load(f)
            _apply_scopes(cfg)
            _SCOPES['mtime'] = mtime
    except Exception as e:
        if not _SCOPES['groups']:  # 兜底：文件坏了用默认值
            _apply_scopes(DEFAULT_SCOPES)
        print('[scopes] 加载失败，使用内置默认:', e)
    return _SCOPES


def reload_scopes():
    load_scopes(force=True)
    with LOCK:
        S['by_scope'] = {}
    _replay_scope_from_log()
    return scope_summary_locked()


def save_scopes(cfg):
    """保存配置并立即生效（供 HTTP API 调用）。"""
    with open(SCOPES_FILE, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return reload_scopes()


def list_scopes_cfg():
    load_scopes()
    out = []
    for k in _SCOPES['order']:
        out.append({'key': k, 'label': _SCOPES['labels'].get(k, k),
                    'color': _SCOPES['colors'].get(k, '#64748b'),
                    'suffixes': list(_SCOPES['groups'].get(k) or [])})
    return out


def scope_of_host(h):
    if not _SCOPES['groups']:
        load_scopes()
    h = (h or '').split(':')[0].lower()
    for g in _SCOPES['order']:
        for s in (_SCOPES['groups'].get(g) or ()):
            if h == s or h.endswith('.' + s):
                return g
    return 'other'


def scope_color(k):
    return _SCOPES['colors'].get(k, '#94a3b8')


def scope_label(k):
    return _SCOPES['labels'].get(k, k)


def _replay_scope_from_log():
    """分组变更后，按日志重放重建各 scope 的统计（保持与总量口径一致）。"""
    try:
        if not os.path.exists(LOG):
            return
        for line in open(LOG, errors='ignore'):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            try:
                _ingest_scope_only(rec)
            except Exception:
                pass
    except Exception as e:
        print('[scopes] 重放失败:', e)


def _ingest_scope_only(rec):
    """只更新 scope 分桶（不广播、不改全局计数），用于重放。"""
    if is_probe_traffic(rec):
        return
    u = str(rec.get('url', ''))
    h = host_of(u)
    sc = scope_of_host(h)
    _sb = S['by_scope'].get(sc)
    if _sb is None:
        _sb = new_counter_bucket()
        S['by_scope'][sc] = _sb
    _sb['total'] += 1
    if rec.get('allow'):
        _sb['allow'] += 1
    else:
        _sb['block'] += 1
    _sb['hosts'][h] += 1
    _sb['methods'][str(rec.get('method'))] += 1
    _sb['last_ts'] = str(rec.get('ts', ''))
    _sb['last_seen'] = time.time()
    j = rec.get('jev') if isinstance(rec.get('jev'), dict) else {}
    if j:
        _sb['kinds'][str(j.get('kind'))] += 1
    L = layer_of(rec)
    _sb['by_layer'][L] += 1
    if not rec.get('allow'):
        _sb['blk_hosts'][h] += 1
        if rec.get('enforced'):
            _sb['enforced'] += 1
        for r in (rec.get('reasons') or []):
            n = norm_reason(r)
            if n:
                _sb['reasons'][n] += 1
        if str(j.get('kind')) == 'no_destructive_impact':
            _sb['fp_suspect'] += 1
    ev = summarize(rec, L)
    _sb['events'].append(ev)
    minute = str(rec.get('ts', ''))[:16].replace('T', ' ')
    if minute:
        m = _sb['minutes'].get(minute)
        if m is None:
            m = {'n': 0, 'a': 0, 'b': 0}
            _sb['minutes'][minute] = m
        m['n'] += 1
        m['a' if rec.get('allow') else 'b'] += 1
        while len(_sb['minutes']) > 120:
            _sb['minutes'].popitem(last=False)


def new_counter_bucket():
    return {
        'total': 0, 'allow': 0, 'block': 0, 'enforced': 0, 'fp_suspect': 0,
        'hosts': collections.Counter(), 'blk_hosts': collections.Counter(),
        'reasons': collections.Counter(), 'methods': collections.Counter(),
        'by_layer': collections.Counter(), 'kinds': collections.Counter(),
        'minutes': collections.OrderedDict(), 'last_ts': None, 'last_seen': None,
        'events': collections.deque(maxlen=2000),
    }

S = {
    'started': time.time(), 'total': 0, 'allow': 0, 'block': 0, 'llm': 0,
    'fp_suspect': 0, 'enforced': 0, 'by_layer': collections.Counter(), 'kinds': collections.Counter(),
    'reasons': collections.Counter(), 'hosts': collections.Counter(),
    'blk_hosts': collections.Counter(), 'methods': collections.Counter(),
    'minutes': collections.OrderedDict(), 'events': collections.deque(maxlen=RING),
    'last_ts': None, 'last_seen': None, 'bad': 0,
    'by_scope': {},
}

def host_of(u):
    try:
        return urlparse(u).netloc or '?'
    except Exception:
        return '?'

def norm_reason(r):
    r = str(r)
    if r.strip() == '只读形态':
        return None
    if r.startswith('Jev'):
        if '删改' in r or '删除现有数据' in r: return 'Jev 语义：删改现有数据'
        if 'RCE' in r: return 'Jev 语义：RCE 利用'
        if '失败' in r or '不可用' in r: return '语义层不可用'
        return 'Jev 其他'
    if r.startswith('写方法'): return '写方法（HTTP 动词）'
    if r.startswith('覆盖头'): return '方法覆盖头'
    if r.startswith('路径含'): return '路径含删改动作'
    if r.startswith('参数 '): return '参数声明删改动作'
    if r.startswith('可解析文件上传') or r.startswith('可执行'): return '上传可解析文件（webshell）'
    if r.startswith('读取敏感文件') or r.startswith('读取系统敏感文件'): return '读取敏感文件/源码'
    if r.startswith('批量导出'): return '批量导出（拖库）'
    if r.startswith('sleep'): return '长 sleep（DoS）'
    if r.startswith('请求体>'): return '超大请求体'
    if r.startswith('删除语句'): return '请求体：删除语句'
    if r.startswith('删除语义'): return '请求体：删除语义'
    if r.startswith('SQL'): return '请求体：SQL 改'
    if r.startswith('JSON-Patch'): return '请求体：JSON-Patch'
    if r.startswith('merge-patch'): return '请求体：merge-patch'
    if r.startswith('GraphQL'): return '请求体：GraphQL'
    if r.startswith('JSON-RPC'): return '请求体：JSON-RPC'
    if r.startswith('SOAP'): return '请求体：SOAP'
    if r.startswith('动作='): return '请求体：动作=删改'
    if r.startswith('伪方法'): return '伪方法=删改'
    # ---- 2026-10-26 新口径：语义层输出的理由格式 ----
    if r.startswith('HARD_BLOCK'): return '硬拦截（写方法/删除路径）'
    if 'Jev 语义判定=删除' in r: return 'Jev 语义：删改现有数据'
    if 'Jev 语义判定=RCE' in r: return 'Jev 语义：RCE 利用'
    if r.startswith('【规则'):
        seg = r.split('】', 1)[1] if '】' in r else r
        if '删除' in seg: return '删除现有数据'
        if '修改' in seg or '覆盖' in seg: return '修改现有数据'
        if '提权' in seg or '横向' in seg: return 'RCE 利用（提权/横向）'
        if '破坏性系统命令' in seg: return 'RCE 利用（破坏性命令）'
        if 'SQL' in seg: return 'SQL 删改'
        if '敏感' in seg or '源码' in seg: return '读取敏感文件/源码'
        if '导出' in seg: return '批量导出（拖库）'
        if '稳定性' in seg or 'DoS' in seg: return 'DoS'
        if '范围' in seg: return '范围外主机'
        return '规则命中'
    return '其他'

def layer_of(rec):
    if rec.get('isllm') or 'deepseek.com' in str(rec.get('url','')) or 'openai.com' in str(rec.get('url','')):
        return 'LLM 出口豁免'
    parts = [str(x) for x in (rec.get('reasons') or []) if str(x) != '只读形态']
    sem = any(p.startswith('Jev') or 'Jev' in p for p in parts)
    det = any(not (p.startswith('Jev') or 'Jev' in p) for p in parts)
    if not rec.get('allow'):
        if sem and det: return 'Jev 语义 + 确定性'
        if sem: return '仅 Jev 语义'
        if det: return '仅确定性规则'
        return '拦截（未标注）'
    return '确定性层放行'

PROBE_HOSTS = ("probe.jev.internal", "probe2.jev.internal", "probe.jev.local", "probe2.jev.local")

def is_probe_traffic(rec):
    try:
        h = host_of(str(rec.get("url", ""))).split(":")[0].lower()
        return h in PROBE_HOSTS
    except Exception:
        return False

def ingest(rec, broadcast=True):
    if is_probe_traffic(rec):
        return
    with LOCK:
        S['total'] += 1
        if rec.get('allow'): S['allow'] += 1
        else: S['block'] += 1
        u = str(rec.get('url','')); h = host_of(u)
        S['hosts'][h] += 1
        _sc = scope_of_host(h)
        _sb = S['by_scope'].get(_sc)
        if _sb is None:
            _sb = new_counter_bucket(); S['by_scope'][_sc] = _sb
        _sb['total'] += 1
        if rec.get('allow'): _sb['allow'] += 1
        else: _sb['block'] += 1
        S['methods'][str(rec.get('method'))] += 1
        _sb['methods'][str(rec.get('method'))] += 1
        _sb['hosts'][h] += 1
        _sb['last_ts'] = str(rec.get('ts',''))
        _sb['last_seen'] = time.time()
        j = rec.get('jev') if isinstance(rec.get('jev'), dict) else {}
        if j:
            S['kinds'][str(j.get('kind'))] += 1
            _sb['kinds'][str(j.get('kind'))] += 1
        L = layer_of(rec)
        S['by_layer'][L] += 1
        _sb['by_layer'][L] += 1
        if L == 'LLM 出口豁免': S['llm'] += 1
        if not rec.get('allow'):
            _sb['blk_hosts'][h] += 1
            S['blk_hosts'][h] += 1
            if rec.get('enforced'):
                S['enforced'] += 1; _sb['enforced'] += 1
            for r in (rec.get('reasons') or []):
                n = norm_reason(r)
                if n:
                    S['reasons'][n] += 1; _sb['reasons'][n] += 1
            if str(j.get('kind')) == 'no_destructive_impact':
                S['fp_suspect'] += 1; _sb['fp_suspect'] += 1
        ts = str(rec.get('ts',''))
        S['last_ts'] = ts
        S['last_seen'] = time.time()
        minute = ts[:16].replace('T',' ')
        if minute:
            m = S['minutes'].get(minute)
            if m is None:
                m = {'n':0,'a':0,'b':0}; S['minutes'][minute] = m
            m['n'] += 1
            m['a' if rec.get('allow') else 'b'] += 1
            _m2 = _sb['minutes'].get(minute)
            if _m2 is None:
                _m2 = {'n':0,'a':0,'b':0}; _sb['minutes'][minute] = _m2
            _m2['n'] += 1
            _m2['a' if rec.get('allow') else 'b'] += 1
            while len(_sb['minutes']) > 120:
                _sb['minutes'].popitem(last=False)
            while len(S['minutes']) > 120:
                S['minutes'].popitem(last=False)
        ev = summarize(rec, L)
        S['events'].append(ev)
        _sb['events'].append(ev)
    if broadcast:
        payload = json.dumps(ev, ensure_ascii=False)
        for q in list(SUBS):
            try: q.put_nowait(('req', payload))
            except Exception: pass

def summarize(rec, layer=None):
    j = rec.get('jev') if isinstance(rec.get('jev'), dict) else {}
    return {
        'ts': str(rec.get('ts',''))[:19].replace('T',' '),
        'method': rec.get('method'), 'url': rec.get('url'),
        'host': host_of(str(rec.get('url',''))),
        'allow': bool(rec.get('allow')), 'layer': layer or layer_of(rec),
        'enforced': bool(rec.get('enforced')), 'would_block': bool(rec.get('would_block')),
        'isllm': bool(rec.get('isllm')),
        'reasons': [str(x) for x in (rec.get('reasons') or [])][:4],
        'kind': j.get('kind'), 'noul': j.get('noul'), 'conf': j.get('conf'), 'by': j.get('by'),
        'pid': rec.get('pid'),
    }

def snapshot(scope=None):
    """scope=None 表示全量；否则只返回该战役分组的数据。
    2026-11-04: 历史高流量战役会占满 Top-N，导致新战役(如客户 C)看不到自己流量。
    """
    with LOCK:
        if scope and scope in S.get('by_scope', {}):
            b = S['by_scope'][scope]
            tot = b['total']
            mins_src = b['minutes']
            return {
                'scope': scope, 'scope_label': scope_label(scope),
                'scopes': scope_summary_locked(),
                'totals': {'total': tot, 'allow': b['allow'], 'block': b['block'],
                           'rate': round(100.0*b['block']/tot, 2) if tot else 0.0,
                           'llm': 0, 'fp_suspect': b['fp_suspect'],
                           'enforced': b['enforced'],
                           'jev_only': b['by_layer'].get('仅 Jev 语义', 0),
                           'enforcement': 'partial', 'would_block': b['block']},
                'by_layer': b['by_layer'].most_common(), 'kinds': b['kinds'].most_common(),
                'reasons': b['reasons'].most_common(12),
                'hosts': b['hosts'].most_common(60),
                'blk_hosts': b['blk_hosts'].most_common(20),
                'methods': b['methods'].most_common(),
                'minutes': [{'m': k, 'n': v['n'], 'a': v['a'], 'b': v['b']} for k, v in list(mins_src.items())[-60:]],
                'last_ts': b['last_ts'],
                'last_seen_age': round(time.time()-b['last_seen'],1) if b['last_seen'] else None,
                'events': list(b['events'])[-500:][::-1],
                'bad': S['bad'],
            }
        # 全量
        tot = S['total']
        mins = [{'m': k, 'n': v['n'], 'a': v['a'], 'b': v['b']} for k, v in list(S['minutes'].items())[-60:]]
        return {
            'scope': None, 'scope_label': '全部',
            'scopes': scope_summary_locked(),
            'totals': {'total': tot, 'allow': S['allow'], 'block': S['block'],
                       'rate': round(100.0*S['block']/tot, 2) if tot else 0.0,
                       'llm': S['llm'], 'fp_suspect': S['fp_suspect'],
                       'enforced': S['enforced'],
                       'jev_only': S['by_layer'].get('仅 Jev 语义', 0), 'enforcement': 'partial', 'would_block': S['block']},
            'by_layer': S['by_layer'].most_common(), 'kinds': S['kinds'].most_common(),
            'reasons': S['reasons'].most_common(12), 'hosts': S['hosts'].most_common(100),
            'blk_hosts': S['blk_hosts'].most_common(20), 'methods': S['methods'].most_common(),
            'minutes': mins, 'last_ts': S['last_ts'],
            'last_seen_age': round(time.time()-S['last_seen'],1) if S['last_seen'] else None,
            'events': list(S['events'])[-500:][::-1], 'bad': S['bad'],
        }


# ---------- 本地探针专区 ----------
_probe_run = {'t': 0, 'running': False, 'last': None}


def probe_last():
    """读最近一次探针结果。"""
    try:
        if not os.path.exists(PROBE_LOG):
            return None
        with open(PROBE_LOG, errors='ignore') as f:
            lines = collections.deque(f, maxlen=1)
        if not lines:
            return None
        d = json.loads(lines[0])
        return d
    except Exception:
        return None


def probe_history(n=30):
    """最近 n 次探针的摘要（不含明细，轻量）。"""
    try:
        if not os.path.exists(PROBE_LOG):
            return []
        with open(PROBE_LOG, errors='ignore') as f:
            lines = collections.deque(f, maxlen=n)
        out = []
        for ln in lines:
            try:
                d = json.loads(ln)
            except Exception:
                continue
            out.append({'ts': d.get('ts'), 'ok': d.get('ok'), 'total': d.get('total')})
        return out
    except Exception:
        return []


def probe_run_now():
    """同步跑一次探针（用于页面按钮）。"""
    if _probe_run['running']:
        return {'error': '探针正在运行中'}
    _probe_run['running'] = True
    try:
        r = subprocess.run(['/usr/bin/python3', PROBE_SCRIPT],
                           capture_output=True, text=True, timeout=180,
                           cwd=_ROOT)
        _probe_run['last'] = (r.stdout or '') + (r.stderr or '')
        return {'ok': True, 'result': probe_last()}
    except Exception as e:
        return {'error': str(e)}
    finally:
        _probe_run['running'] = False


def probe_summary():
    """探针专区数据：最近一次明细 + 历史通过率。"""
    last = probe_last()
    hist = probe_history(30)
    cat = collections.Counter()
    if last:
        for r in (last.get('rows') or []):
            cat[r.get('cat') or '?'] += 1
    return {'installed': os.path.exists(PROBE_SCRIPT),
            'running': _probe_run['running'],
            'last': last, 'history': hist,
            'categories': cat.most_common(),
            'endpoint': 'http://127.0.0.1:9102 → probe.jev.internal:18080 (本地 echo；破坏性规则走离线内存验证)',
            'script': PROBE_SCRIPT}


def scope_summary_locked():
    """各战役的汇总（供前端渲染切换标签）。调用方需已持有 LOCK。"""
    out = []
    for k, b in S.get('by_scope', {}).items():
        t = b['total']
        out.append({'scope': k, 'label': scope_label(k), 'color': scope_color(k), 'total': t,
                    'allow': b['allow'], 'block': b['block'],
                    'rate': round(100.0*b['block']/t, 2) if t else 0.0,
                    'hosts': len(b['hosts']),
                    'last_ts': b['last_ts'],
                    'last_seen_age': round(time.time()-b['last_seen'],1) if b['last_seen'] else None})
    out.sort(key=lambda x: -x['total'])
    return out


# ---------- 现场读取 guard.py（与线上判定同源） ----------
def load_guard():
    spec = importlib.util.spec_from_file_location('gd_live', GUARD)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m

_GD = None
_gd_synced = {'key': None}


def _sync_cfg(g):
    """把观测台里的 guard 模块配置成【线上正在跑的】那一套。

    2026-10-26：jev-live 自己的进程环境没有 GUARD_POLICY 等变量，
    若直接 import guard.py，模块会按默认 strict 配置，导致「策略模拟器」
    与 9102 实际判定不一致（模拟器说拦、线上其实放行）。
    这里统一从运行中的护栏进程读取配置并同步。
    """
    try:
        pol = (_guard_env('GUARD_POLICY') or 'strict').strip().lower()
        scope = (_guard_env('GUARD_SCOPE_MODE') or 'all').strip().lower()
        suf = tuple(x.strip() for x in (_guard_env('GUARD_SCOPE_SUFFIX') or '').split(',') if x.strip())
        oos = tuple(x.strip() for x in (_guard_env('GUARD_OUT_OF_SCOPE') or '').split(',') if x.strip())
        key = (pol, scope, suf, oos)
        if _gd_synced['key'] == key:
            return
        sem = getattr(g, '_sem', None)
        if sem is not None and hasattr(sem, 'configure'):
            sem.configure(policy=pol, scope_mode=scope,
                          scope_suffix=(suf or None), out_of_scope=(oos or None))
        _gd_synced['key'] = key
    except Exception:
        pass


def guard_mod():
    global _GD
    if _GD is None: _GD = load_guard()
    _sync_cfg(_GD)
    return _GD

def llm_keys():
    # LLM_KEYS_PARSE：从 :9100 addon（mitm_guard.py）解析 LLM 出口豁免名单
    try:
        src = open(MITM, encoding='utf-8').read()
        m = re.search(r"LLM_KEYS\s*=\s*\(([^)]*)\)", src, re.S)
        if m:
            return [x.strip().strip("'").strip('"') for x in m.group(1).split(',') if x.strip()]
    except Exception:
        pass
    return []


def enforce_hosts():
    # 从 :9100 addon 源码解析强制拦截（真 403）的目标范围：ENFORCE_ENABLED = _isgov or _iscustomerf
    try:
        src = open(MITM, encoding='utf-8').read()
        m = re.search(r'^\s*ENFORCE_ENABLED\s*=\s*(.+)$', src, re.M)
        if not m: return []
        expr = m.group(1).strip()
        # 2026-10-25：ENFORCE_ENABLED = not _isloop（或 True）表示全部主机强制，仅回环/LLM 豁免
        if expr == 'True' or 'not _isloop' in expr:
            return ['*全部主机（LLM 出口/本机回环豁免）']
        out = []
        for var in re.findall(r'_(\w+)', expr):
            dm = re.search(r'^\s*_' + re.escape(var) + r'\s*=\s*\((.+)\)', src, re.M)
            if dm:
                out += re.findall(r"'([^']+)'", dm.group(1))
        return sorted(set(out))
    except Exception:
        return []


def _guard_env(name, default=None):
    """从真正在跑的护栏进程读环境变量 —— 比本观测台自己的环境更权威。"""
    try:
        # 注意：不能用 pgrep -f 'listen-port 9102' —— subprocess(shell=True) 的
        # 命令行本身就含这个字符串，pgrep 会匹配到自己，拿到错误的 pid。
        # 改为按监听端口定位真实进程。
        pid = (sh("ss -lntp 2>/dev/null | grep ':9102 ' | "
                  "grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2") or '').strip()
        if pid:
            with open('/proc/%s/environ' % pid, 'rb') as f:
                for kv in f.read().split(b'\0'):
                    k, _, v = kv.partition(b'=')
                    if k.decode('utf-8', 'ignore') == name:
                        return v.decode('utf-8', 'ignore')
    except Exception:
        pass
    return os.environ.get(name, default)


def policy_digest():
    """当前策略 —— 现场从 guard.py / guard_semantic.py 读取，与线上判定同源。

    2026-10-26 口径变更后重写：
      · 拦截口径由 GUARD_POLICY 决定（dml=只拦删除/修改+RCE利用；strict=按9条全面拦）
      · 判定方式：原始请求报文直接交给 Jev；正则只作审计线索
    """
    g = guard_mod()
    sem = getattr(g, '_sem', None)
    cfg = getattr(sem, 'CFG', {}) if sem is not None else {}
    pol = str(_guard_env('GUARD_POLICY') or cfg.get('policy') or 'strict').lower()
    enf = str(_guard_env('GUARD_ENFORCE', '1')).strip().lower() not in ('0', 'false', 'off', 'no')
    dml = (pol == 'dml')
    jev_only = (pol == 'jev')

    def _attr(mod, name, default):
        v = getattr(mod, name, None)
        return v if v is not None else default

    blocks = (['删除 / 修改（由 Jev 语义判定）',
               'RCE 利用（由 Jev 语义判定）']
              if jev_only else
              ['删除 / 修改（DELETE、PUT、PATCH、软删除、指向已存在资源的修改）',
               'RCE 利用（反弹 shell、提权、持久化、破坏性系统命令、SQL 删改）']
              if dml else
              ['删除 / 修改', 'RCE 利用', '敏感文件与源码读取', '可执行文件上传',
               '批量导出 / 拖库', 'DoS / 超大请求', '范围外主机', '高并发限速'])
    audit_only = (['规则层的全部命中（硬拦截、删除语义、SQL、上传、敏感文件、拖库、范围外、限速…）',
                   '仅当 Jev 不可用时，规则层才对「删除/修改」兜底']
                  if jev_only else
                  ['上传可执行文件（含 webshell 载荷）',
                   '基础 RCE 命令（id / whoami / 读非敏感文件 / sleep 探测）',
                   '敏感文件读取（.git/config、actuator/heapdump、/etc/passwd）',
                   '拖库 / 大规模遍历', '范围外主机', '高并发限速']
                  if dml else [])

    return {
        'mode': ('jev（规则层完全不拦截，全部交给 Jev 语义模型）' if jev_only
                 else 'dml（只拦删除/修改 + RCE 利用）' if dml
                 else 'strict（按 9 条禁止事项全面拦截）'),
        'policy': pol,
        'enforce': bool(enf),
        'audit_mode': getattr(g, 'AUDIT_MODE', '?'),
        'judge': '原始请求报文直接交给 Jev 语义模型；正则仅作审计线索，不参与拦截',
        'questions': ['deletes_or_modifies —— 是否删除/修改已存在数据',
                      'rce_exploitation —— 是否属 RCE 利用（基础命令不算）'],
        'blocks': blocks,
        'audit_only': audit_only,
        # 兼容页面原有字段（值改为从新模块读取）
        'blocked_methods': sorted(getattr(g, 'HARD_BLOCK_METHODS', []) or []),
        'safe_methods': ['GET', 'HEAD', 'OPTIONS', 'POST'],
        'del_words': list(_attr(sem, 'DELETE_VERBS', [])),
        'mod_words': list(_attr(sem, 'UPDATE_VERBS', [])),
        'sql_rules': [n for _p, n in _attr(sem, 'SQLI_PATTERNS', [])],
        'rce_rules': [n for _p, n in _attr(sem, 'RCE_PATTERNS', [])],
        'exec_ext': list(_attr(sem, 'EXEC_EXT', [])),
        'sensitive_files': list(_attr(sem, 'SENSITIVE_MARKERS', [])),
        'allowed_read': list(_attr(sem, 'ALLOWED_READ', [])),
        'bulk_max': cfg.get('bulk_max'),
        'scope': {'suffixes': list(cfg.get('scope_suffix') or ()), 'mode': cfg.get('scope_mode')},
        'rate': {'cap': cfg.get('rate_cap'), 'per_sec': cfg.get('rate_per_sec')},
        'llm_hosts': llm_keys(),
        'enforce_hosts': enforce_hosts(),
        'noul_max': getattr(g, 'TS_NOUL_MAX', None), 'min_conf': getattr(g, 'TS_MIN_CONF', None),
        'guard_mtime': datetime.datetime.fromtimestamp(os.path.getmtime(GUARD)).strftime('%Y-%m-%d %H:%M:%S'),
        'summary': ('拦截=删除/修改类操作 + RCE 利用（原始请求报文交 Jev 判定）；'
                    '放行并只写审计=上传可执行文件、基础 RCE 命令、敏感文件读取、拖库、范围外主机、高并发限速'
                    if dml else
                    '拦截=删除/修改 + RCE 利用 + 敏感文件读取 + 可执行文件上传 + 拖库 + DoS + 范围外 + 限速'),
    }

_sem = {'t': 0, 'v': None}


def _reach_ok(code):
    # 只要端点"有 HTTP 响应"即视为网络可达；仅 000（连接失败）或 45x（地区封锁）不算
    c = str(code or '')
    return bool(c) and c != '000' and not c.startswith('45')


_probe = {'t': 0, 'v': None}


# 2026-11-25：探针保活线程。
# 探针 60s 才调一次，连接池里的 TLS 连接早就空闲超时了，每次都要重新握手（+500ms）。
# 这里起一个后台线程每 20s 打一次轻量请求，让连接始终温热，探针拿到的就是真实稳态延迟。
_keepwarm_started = False

def _start_keepwarm():
    global _keepwarm_started
    if _keepwarm_started:
        return
    _keepwarm_started = True
    import threading
    def _loop():
        while True:
            try:
                time.sleep(20)
                g = guard_mod()
                g.jev_decide('POST', 'http://guard-health.internal:18090/__keepwarm__',
                             {'Content-Type': 'application/json'}, '{"keepwarm":1}')
            except Exception:
                pass
    t = threading.Thread(target=_loop, name='jev-keepwarm', daemon=True)
    t.start()


def _live_probe():
    # 真实调用语义层（与线上判定同一条代码路径），用于权威判定"Jev 在线/降级"
    # 2026-11-25：60s 缓存（原 300s）；配合 _start_keepwarm() 保活连接，延迟稳定在 ~330ms
    if time.time() - _probe['t'] < 60 and _probe['v']:
        return _probe['v']
    t0 = time.time()
    try:
        g = guard_mod()
        # 2026-11-23 修复：探针改为打【本机自建】的健康靶站，不再借用真实业务域名。
        #   - 靶站：jev-health-target.service → 127.0.0.1:18090（只回固定 JSON，无副作用）
        #   - 主机名：guard-health.internal（/etc/hosts 映射；不用 .local，会被 mDNS 抢占）
        #   - 用 POST 是为了避免 bare-read 被 skip，能真正问一次模型
        _a, jr, ji = g.jev_decide('POST', 'http://guard-health.internal:18090/__health__',
                                  {'Content-Type': 'application/json'},
                                  '{"probe":1,"note":"guard health check"}')
        ji = ji if isinstance(ji, dict) else {}
        _probe['v'] = {'ok': ji.get('by') in ('jev', 'skip'), 'by': ji.get('by'), 'kind': ji.get('kind'),
                       'model': ji.get('model'), 'err': ji.get('jev_error'),
                       'ms': int((time.time() - t0) * 1000), 'reasons': [str(x) for x in (jr or [])][:2]}
    except Exception as e:
        _probe['v'] = {'ok': False, 'by': None, 'error': str(e)[:140], 'ms': int((time.time() - t0) * 1000)}
    _probe['t'] = time.time()
    return _probe['v']


def semantics():
    # 语义层（Jev API）健康：最近判定的来源构成 + 端点可达性（30s 缓存）
    if time.time() - _sem['t'] < 30 and _sem['v']:
        return _sem['v']
    by = collections.Counter(); model = collections.Counter(); last = None
    try:
        with open(LOG, errors='ignore') as f:
            lines = collections.deque(f, maxlen=300)
        for line in lines:
            try: d = json.loads(line)
            except Exception: continue
            j = d.get('jev') or {}
            by[str(j.get('by'))] += 1; model[str(j.get('model'))] += 1
            last = {'ts': str(d.get('ts'))[:19].replace('T', ' '), 'by': str(j.get('by')), 'model': str(j.get('model'))}
    except Exception:
        pass
    reach = {}
    for k, cmd in (('direct', 'curl -s -m 8 -o /dev/null -w %{http_code} https://api.typesafe.ai/v1/systemone'),
                   ('proxy', 'curl -s -m 8 -o /dev/null -w %{http_code} -x http://127.0.0.1:7892 https://api.typesafe.ai/v1/systemone')):
        reach[k] = sh(cmd) or '?'
    n = sum(by.values())
    ok = _reach_ok(reach.get('proxy')) or _reach_ok(reach.get('direct'))
    # 2026-10-26：无参数的裸读会被 skip（不询问模型），不能因此判定降级
    hist_deg = n > 0 and (by.get('jev', 0) == 0) and (by.get('skip', 0) == 0)
    probe = _live_probe()
    degraded = (not probe.get('ok')) or hist_deg
    v = {'by': by.most_common(), 'model': model.most_common(4), 'last': last, 'reach': reach,
         'degraded': bool(degraded), 'reachable': bool(ok), 'hist_degraded': bool(hist_deg), 'recent_n': n, 'probe': probe, 'has_key': bool(os.environ.get('TYPESAFE_API_KEY'))}
    _sem['t'] = time.time(); _sem['v'] = v
    return v


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=6).stdout.strip()
    except Exception:
        return ''

_hc = {'t': 0, 'v': None}
def health():
    if time.time() - _hc['t'] < 5 and _hc['v']: return _hc['v']
    v = {
        'guard': sh('systemctl --user is-active artex-r3-guard.service'),  # patched: 9102 已退役，实际生效的是 9120
        # patched 2026-11-23: artex-egress.service(nft) 已退役，
        # 现由 artex-transparent-lock.service + iptables ARTEX-TRANSPARENT 接管
        'egress': sh('systemctl is-active artex-transparent-lock.service') or 'inactive',
        # patched: artex.service 已停用，实际运行为 Docker 容器 artex-clean-artex-1
        'artex': ('active' if sh("docker inspect -f '{{.State.Running}}' artex-clean-artex-1 2>/dev/null") == 'true'
                   else sh('systemctl --user is-active artex.service')),
        # patched 2026-11-23: 改查 iptables（nft 表已删除）
        'iptables_rules': sh("sudo -n iptables -t nat -S ARTEX-TRANSPARENT 2>/dev/null | grep -c 'ARTEX-TRANSPARENT'") or '0',
        'log_size': os.path.getsize(LOG) if os.path.exists(LOG) else 0,
        'log_age': round(time.time()-os.path.getmtime(LOG),1) if os.path.exists(LOG) else None,
        'now': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    _hc['t'] = time.time(); _hc['v'] = v
    return v

# ---------- tail ----------
def tail_loop():
    # 首次全量回填（构建指标 + 最近事件）
    if os.path.exists(LOG):
        try:
            with open(LOG, errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try: ingest(json.loads(line), broadcast=False)
                    except Exception: S['bad'] += 1
        except Exception: pass
    f = open(LOG, errors='ignore')
    f.seek(0, os.SEEK_END)
    try:
        cur_ino = os.fstat(f.fileno()).st_ino
    except Exception:
        cur_ino = None
    buf = ''
    while True:
        # ---- 轮转/截断自愈 (2026-10-30) ----
        # jev_retention.sh 每小时可能原地截断 mitm-audit.log（gzip 备份后 : > 文件）。
        # 旧实现只在启动时 seek(0, END)：文件被截断后读偏移恒大于文件长度，
        # readline() 永远返回空 → 观测台永久静默失明，但页头仍显示"在线"。
        try:
            st = os.stat(LOG)
            reopened = False
            if cur_ino is not None and st.st_ino != cur_ino:
                reopened = True   # 换了文件（inode 变化）
            elif st.st_size < f.tell():
                reopened = True   # 原地截断
            if reopened:
                try: f.close()
                except Exception: pass
                f = open(LOG, errors='ignore')
                f.seek(0)
                try: cur_ino = os.fstat(f.fileno()).st_ino
                except Exception: cur_ino = None
                buf = ''
                continue
        except FileNotFoundError:
            time.sleep(0.5); continue
        except Exception:
            pass
        line = f.readline()
        if not line:
            time.sleep(0.25); continue
        buf += line
        if not buf.endswith(chr(10)): continue
        for one in buf.splitlines():
            one = one.strip()
            if not one: continue
            try: ingest(json.loads(one))
            except Exception: S['bad'] += 1
        buf = ''

# ---------- HTTP ----------
DEFAULT_CASES = [
    {'cat': '未授权改密',      'method': 'GET',  'url': 'https://a.local/api/user/reset-pwd', 'body': ''},
    {'cat': '未授权改密(变体)', 'method': 'POST', 'url': 'https://a.local/api/v1/open/user/set-pwd', 'body': '{"userId":1,"newPwd":"x"}'},
    {'cat': '改手机号',        'method': 'POST', 'url': 'https://a.local/api/open/user/update-phone', 'body': '{"phone":"13800000000"}'},
    {'cat': '越权读用户',      'method': 'GET',  'url': 'https://a.local/api/v1/user/1001/profile', 'body': ''},
    {'cat': '越权读订单',      'method': 'GET',  'url': 'https://a.local/api/v1/order/20260116', 'body': ''},
    {'cat': 'SQL 注入',        'method': 'GET',  'url': "https://a.local/api/item?id=1' OR 1=1--", 'body': ''},
    {'cat': 'SQL 时间盲注',    'method': 'GET',  'url': 'https://a.local/api/item?id=1 AND sleep(5)', 'body': ''},
    {'cat': 'SSTI 模板注入',   'method': 'GET',  'url': 'https://a.local/api/render?tpl={{7*7}}', 'body': ''},
    {'cat': '命令注入',        'method': 'GET',  'url': 'https://a.local/api/ping?host=127.0.0.1;whoami', 'body': ''},
    {'cat': '任意文件读取',    'method': 'GET',  'url': 'https://a.local/api/download?file=../../../../etc/passwd', 'body': ''},
    {'cat': '文件读取(编码)',  'method': 'GET',  'url': 'https://a.local/api/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'body': ''},
    {'cat': 'SSRF 云元数据',   'method': 'GET',  'url': 'https://a.local/api/fetch?url=http://169.254.169.254/latest/meta-data/', 'body': ''},
    {'cat': 'SSRF 内网',       'method': 'POST', 'url': 'https://a.local/api/proxy', 'body': '{"url":"http://127.0.0.1:8080/actuator/env"}'},
    {'cat': '未授权上传',      'method': 'POST', 'url': 'https://a.local/api/file/upload', 'body': 'filename=x.jsp'},
    {'cat': '批量转账',        'method': 'POST', 'url': 'https://a.local/api/v1/command/batchTransfer', 'body': '{"to":"attacker","amount":1}'},
    {'cat': 'GraphQL 删改',    'method': 'POST', 'url': 'https://a.local/graphql', 'body': '{"query":"mutation{deleteUser(id:1){ok}}"}'},
    {'cat': 'JSON-RPC 删改',   'method': 'POST', 'url': 'https://a.local/api/rpc', 'body': '{"method":"item.delete","params":[1]}'},
    {'cat': '改配置(混淆)',    'method': 'GET',  'url': 'https://a.local/tenant/up%64ateTenantName?name=x', 'body': ''},
    {'cat': '改配置',          'method': 'POST', 'url': 'https://a.local/api/config/saveCustomConfig', 'body': '{"a":1}'},
    {'cat': '未授权删除',      'method': 'GET',  'url': 'https://a.local/api/item/1/delete', 'body': ''},
    {'cat': '对照组:查询',     'method': 'GET',  'url': 'https://a.local/api/user/list?page=1', 'body': ''},
    {'cat': '对照组:登录',     'method': 'POST', 'url': 'https://a.local/api/login', 'body': '{"u":"a","p":"b"}'},
    {'cat': '批量导出(拖库)',   'method': 'GET',  'url': 'https://a.local/api/user/list?pageSize=5000', 'body': ''},
    {'cat': '敏感文件读取',     'method': 'GET',  'url': 'https://a.local/api/download?file=../../../etc/shadow', 'body': ''},
    {'cat': '主机文件读取(放行)','method': 'GET',  'url': 'https://a.local/api/download?file=../../../etc/hostname', 'body': ''},
    {'cat': '上传 webshell',   'method': 'POST', 'url': 'https://a.local/api/file/upload', 'body': '------X\r\nContent-Disposition: form-data; name="f"; filename="shell.jsp"\r\n\r\n<%@page %>\r\n------X--'},
    {'cat': '慢查询 DoS',      'method': 'GET',  'url': "https://a.local/api/search?q=1 AND sleep(15)", 'body': ''},
]


def simulate_one(case):
    method = str(case.get('method', 'GET')).upper()
    url = str(case.get('url', ''))
    body = str(case.get('body', '') or '')
    headers = case.get('headers') or {}
    out = {'cat': case.get('cat', ''), 'method': method, 'url': url, 'body': body}
    try:
        g = guard_mod()
        mode = getattr(g, 'AUDIT_MODE', 'both')
        dallow, dreasons = g.decide(method, url, headers, body)
        out['deterministic'] = {'allow': bool(dallow), 'reasons': [str(x) for x in dreasons]}
        allow, reasons = bool(dallow), [str(x) for x in dreasons]
        if mode in ('jev', 'both'):
            try:
                jallow, jreasons, jinfo = g.jev_decide(method, url, headers, body)
                info = {}
                if isinstance(jinfo, dict):
                    info = dict((k, jinfo.get(k)) for k in ('by', 'kind', 'noul', 'conf', 'model') if k in jinfo)
                out['jev'] = {'allow': bool(jallow), 'reasons': [str(x) for x in jreasons], 'info': info}
                if mode == 'jev':
                    allow, reasons = bool(jallow), [str(x) for x in jreasons]
                elif not jallow:
                    allow = False; reasons = reasons + [str(x) for x in jreasons]
            except Exception as e:
                out['jev'] = {'allow': None, 'reasons': ['调用失败: ' + str(e)[:120]], 'info': {}}
        ks = llm_keys()
        isllm = any(k in url for k in ks) if ks else False
        if isllm and not allow:
            allow = True; reasons = ['LLM出口放行(仅审计不拦截)'] + reasons
        out['exempt'] = isllm
        out['final'] = '放行' if allow else '拦截 403'
        out['final_reasons'] = reasons[:4]
    except Exception as e:
        out['error'] = str(e)[:200]
    return out


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def _send(self, code, body, ctype='application/json; charset=utf-8'):
        b = body if isinstance(body, bytes) else str(body).encode('utf-8')
        self.send_response(code); self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b))); self.send_header('Cache-Control', 'no-store')
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = urlparse(self.path)
        if p.path in ('/', '/index.html'):
            try:
                with open(HTML, 'rb') as f: self._send(200, f.read(), 'text/html; charset=utf-8')
            except Exception as e: self._send(500, json.dumps({'error': str(e)}))
            return
        if p.path == '/api/snapshot':
            qs = parse_qs(p.query or '')
            sc = (qs.get('scope') or [None])[0]
            if sc in ('', 'all'): sc = None
            self._send(200, json.dumps(snapshot(sc), ensure_ascii=False)); return
        if p.path == '/api/policy':
            try: self._send(200, json.dumps(policy_digest(), ensure_ascii=False))
            except Exception as e: self._send(500, json.dumps({'error': str(e)}))
            return
        if p.path == '/api/health': self._send(200, json.dumps(health(), ensure_ascii=False)); return
        if p.path == '/api/semantics': self._send(200, json.dumps(semantics(), ensure_ascii=False)); return
        if p.path == '/api/probe':
            self._send(200, json.dumps(probe_summary(), ensure_ascii=False)); return
        if p.path == '/api/scopes':
            qs = parse_qs(p.query or '')
            if (qs.get('reload') or [''])[0] in ('1','true'):
                try:
                    reload_scopes()
                except Exception:
                    pass
            else:
                load_scopes()
            with LOCK:
                summ = scope_summary_locked()
            self._send(200, json.dumps({'file': SCOPES_FILE, 'groups': list_scopes_cfg(),
                                        'summary': summ}, ensure_ascii=False)); return
        if p.path == '/events':
            qs2 = parse_qs(p.query or '')
            sc2 = (qs2.get('scope') or [None])[0]
            if sc2 in ('', 'all'): sc2 = None
            self.sse(sc2); return
        self._send(404, json.dumps({'error':'not found'}))
    def sse(self, scope=None):
        q = queue.Queue()
        SUBS.append(q)
        SUBS_SCOPE[id(q)] = scope
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache'); self.send_header('Connection', 'keep-alive')
        self.send_header('X-Accel-Buffering', 'no'); self.end_headers()
        try:
            self.wfile.write(b'event: hello\ndata: {"ok":true}\n\n'); self.wfile.flush()
            last = 0
            while True:
                try:
                    kind, payload = q.get(timeout=2.0)
                    self.wfile.write(('event: ' + kind + '\ndata: ' + payload + '\n\n').encode('utf-8'))
                    self.wfile.flush()
                except queue.Empty:
                    pass
                if time.time() - last > 1.5:
                    snap = json.dumps(snapshot(), ensure_ascii=False)
                    self.wfile.write(('event: metrics\ndata: ' + snap + '\n\n').encode('utf-8'))
                    self.wfile.flush(); last = time.time()
        except Exception:
            pass
        finally:
            try: SUBS.remove(q)
            except ValueError: pass
    def do_POST(self):
        p = urlparse(self.path)
        if p.path == '/api/probe/run':
            self._send(200, json.dumps(probe_run_now(), ensure_ascii=False)); return
        if p.path == '/api/scopes':
            try:
                n = int(self.headers.get('Content-Length') or 0)
                body = json.loads(self.rfile.read(n) or b'{}')
            except Exception as e:
                self._send(400, json.dumps({'error': 'bad json: ' + str(e)})); return
            act = str(body.get('action') or 'add')
            try:
                cfg = {'version': 1, 'groups': list_scopes_cfg()}
                gs = cfg['groups']
                if act == 'add':
                    k = str(body.get('key') or '').strip().lower()
                    if not k:
                        self._send(400, json.dumps({'error': 'key required'})); return
                    gs = [g for g in gs if g.get('key') != k]
                    gs.append({'key': k, 'label': str(body.get('label') or k),
                               'color': str(body.get('color') or '#64748b'),
                               'suffixes': [str(s).strip().lower() for s in (body.get('suffixes') or []) if str(s).strip()]})
                elif act == 'remove':
                    k = str(body.get('key') or '').strip().lower()
                    gs = [g for g in gs if g.get('key') != k]
                elif act == 'set_all':
                    gs = body.get('groups') or []
                else:
                    self._send(400, json.dumps({'error': 'action must be add|remove|set_all'})); return
                cfg['groups'] = gs
                summ = save_scopes(cfg)
                self._send(200, json.dumps({'ok': True, 'groups': list_scopes_cfg(),
                                            'summary': summ}, ensure_ascii=False))
            except Exception as e:
                self._send(500, json.dumps({'error': str(e)}))
            return
        p = urlparse(self.path)
        if p.path == '/api/simulate_batch':
            n = int(self.headers.get('Content-Length') or 0)
            try: req = json.loads(self.rfile.read(n) or b'{}')
            except Exception: req = {}
            cs = req.get('cases') or DEFAULT_CASES
            res = [simulate_one(c) for c in cs]
            ok = sum(1 for r in res if r.get('final') == '放行')
            self._send(200, json.dumps({'results': res, 'summary': {'total': len(res), 'allow': ok, 'block': len(res) - ok}}, ensure_ascii=False))
            return
        if p.path != '/api/simulate':
            self._send(404, json.dumps({'error':'not found'})); return
        n = int(self.headers.get('Content-Length') or 0)
        try: req = json.loads(self.rfile.read(n) or b'{}')
        except Exception: req = {}
        method = str(req.get('method','GET')).upper()
        url = str(req.get('url','https://example.local/api/x'))
        body = str(req.get('body','') or '')
        headers = req.get('headers') or {}
        out = {'method': method, 'url': url, 'body': body}
        try:
            g = guard_mod()
            mode = getattr(g, 'AUDIT_MODE', 'both')
            dallow, dreasons = g.decide(method, url, headers, body)
            out['deterministic'] = {'allow': bool(dallow), 'reasons': [str(x) for x in dreasons]}
            allow, reasons = bool(dallow), [str(x) for x in dreasons]
            if mode in ('jev', 'both'):
                try:
                    jallow, jreasons, jinfo = g.jev_decide(method, url, headers, body)
                    info = {}
                    if isinstance(jinfo, dict):
                        info = dict((k, jinfo.get(k)) for k in ('by', 'kind', 'noul', 'conf', 'model', 'jev_error') if k in jinfo)
                    out['jev'] = {'allow': bool(jallow), 'reasons': [str(x) for x in jreasons], 'info': info}
                    if mode == 'jev':
                        allow, reasons = bool(jallow), [str(x) for x in jreasons]
                    elif not jallow:
                        allow = False; reasons = reasons + [str(x) for x in jreasons]
                except Exception as e:
                    out['jev'] = {'allow': None, 'reasons': ['调用失败: ' + str(e)[:140]], 'info': {}}
            ks = llm_keys()
            isllm = any(k in url for k in ks) if ks else False
            out['exempt'] = isllm
            if isllm and not allow:
                allow = True
                reasons = ['LLM出口放行(仅审计不拦截)'] + reasons
            out['final'] = '放行' if allow else '拦截 403'
            out['final_reasons'] = reasons[:5]
        except Exception as e:
            out['error'] = str(e)[:200]
        self._send(200, json.dumps(out, ensure_ascii=False))

def main():
    _start_keepwarm()
    load_scopes()  # 启动预加载分组配置
    t = threading.Thread(target=tail_loop, daemon=True)
    t.start()
    srv = ThreadingHTTPServer(BIND, H)
    print('jev-live listening on %s:%d' % BIND)
    srv.serve_forever()

if __name__ == '__main__':
    main()
