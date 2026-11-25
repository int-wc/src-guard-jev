#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""出网封禁验证：确认目标程序无法绕过护栏直连外网。

用法：在**受控环境**里跑（会尝试真实的 TCP 连接）。

预期结果：
  - 直连靶机 / 内网网关 / 公网出口 → 全部不通（被 iptables 封）
  - 经护栏代理 → 可以（这是唯一合法出口）

注意：脚本里的地址都是 RFC5737 文档专用地址或公共 DNS，
      请按你的实际部署替换 GATEWAY / TARGET_HOST 后再跑。
"""
import socket
import urllib.error
import urllib.request

# ---- 按实际部署修改 ----
GATEWAY = '192.0.2.1'        # 网关/宿主地址（示例占位）
TARGET_HOST = '192.0.2.10'   # 受控靶机地址（示例占位）
TARGET_PORT = 9101
GUARD_PORT = 9200
PROXY = 'http://127.0.0.1:%d' % GUARD_PORT
# ----------------------


def try_tcp(host, port, timeout=4):
    s = socket.create_connection((host, port), timeout=timeout)
    s.close()
    return 'TCP 可连'


def try_http(url, timeout=5, proxy=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
    op = urllib.request.build_opener(*handlers)
    try:
        with op.open(url, timeout=timeout) as r:
            return 'HTTP %d' % r.status
    except urllib.error.HTTPError as e:
        return 'HTTP %d' % e.code
    except Exception as e:
        return '失败: %s' % type(e).__name__


def probe(name, fn):
    try:
        print('  %-46s %s' % (name, fn()))
    except Exception as e:
        print('  %-46s 不可达 (%s)' % (name, type(e).__name__))


if __name__ == '__main__':
    print('=== 出网封禁验证 ===')
    print('预期：下面除「经护栏」外都应不通')
    print()
    probe('直连靶机 %s:%d' % (TARGET_HOST, TARGET_PORT),
          lambda: try_tcp(TARGET_HOST, TARGET_PORT))
    probe('网关直连 %s:22' % GATEWAY, lambda: try_tcp(GATEWAY, 22))
    probe('外网出口 1.1.1.1:443', lambda: try_tcp('1.1.1.1', 443))
    probe('DNS 出口 8.8.8.8:53', lambda: try_tcp('8.8.8.8', 53))
    probe('HTTP 直连外网（不经代理）',
          lambda: try_http('http://example.com/'))
    print()
    print('=== 对照：经护栏应可达 ===')
    probe('经护栏代理访问外网',
          lambda: try_http('http://example.com/', proxy=PROXY))
