#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jev 护栏健康探针靶站（本地自建，仅供 _live_probe 打）。

用途：
  供观测台 server.py 的 _live_probe() 做语义层健康检查。
  以前探针打的是不存在的 probe.health.local，导致 by=none 永久误报。
  现在改为打本机自建的真实 HTTP 服务，主机名 guard-health.local:18090。

安全：
  - 只监听 127.0.0.1，不对外暴露
  - 不读任何文件、不连数据库、不发起出站请求
  - 无副作用：所有方法只回固定 JSON，不修改任何状态

端点：
  GET/POST /__health__   健康检查主端点（探针用这个）
  GET       /healthz     同上（别名）
  *         其余路径     回 200 + 通用 JSON
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = ('127.0.0.1', 18090)
VERSION = 'health-probe-target/1.0'


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *a):
        # 记录访问，便于确认探针确实打到本靶站（写到 health.log）
        try:
            sys.stderr.write('[%s] %s %s\n' % (
                __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                self.command, self.path))
            sys.stderr.flush()
        except Exception:
            pass

    def _reply(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Health-Target', VERSION)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > 0:
            try:
                self.rfile.read(n)
            except Exception:
                pass
        self._reply(200, {'ok': True, 'service': VERSION, 'path': self.path,
                          'method': 'GET', 'note': 'local health probe target'})

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        raw = b''
        if n > 0:
            try:
                raw = self.rfile.read(n)
            except Exception:
                raw = b''
        self._reply(200, {'ok': True, 'service': VERSION, 'path': self.path,
                          'method': 'POST', 'body_len': len(raw),
                          'note': 'local health probe target'})

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


def main():
    srv = ThreadingHTTPServer(BIND, H)
    print('health-probe-target listening on %s:%d' % BIND, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == '__main__':
    main()
