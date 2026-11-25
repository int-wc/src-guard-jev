# src-guard-jev

为 AI 自动化渗透测试（如 Artex）配套的**出站流量审计护栏**。

> 🤖 **如果你是 AI agent，请先读 [AGENTS.md](AGENTS.md)** —— 里面有「被拦住时怎么做」的硬性规则。
用 mitmproxy 抓取全部出站请求，交给 Jev 语义模型判断「是否在改删既有数据 / 是否在 RCE 利用」，
危险动作直接 403 阻断，其余放行并记审计日志。

## 为什么需要它

AI 自主渗透测试会**真的去执行**它想到的动作。没有护栏时：
- 可能给真实用户发短信（`/sso/authLogin/sms`）
- 可能删掉业务数据（`DELETE /api/pic/delete`）
- 可能提交订单、改客户资料

本护栏把「只读探测」和「会改变现实的动作」分开，后者一律拦。

## 架构

```
┌─────────────┐    HTTP_PROXY    ┌──────────────┐   TLS   ┌────────────┐
│ Artex 容器  │ ───────────────> │ mitmproxy    │ ──────> │ 目标网站   │
│ (AI agent)  │   :9200          │ + guard.py   │         └────────────┘
└─────────────┘                  └──────┬───────┘
                                        │ 语义判定
                                        v
                                 ┌──────────────┐
                                 │ Jev 模型 API │
                                 │ (typesafe)   │
                                 └──────────────┘
```

三层防护：

| 层 | 机制 |
|---|---|
| 规则层 | 路径/方法/参数关键词匹配（确定性，快） |
| 语义层 | Jev 模型判断意图（LLM，准） |
| 硬拦截 | 分页参数 >1000、写方法 PUT/DELETE 等 |

## 目录结构

```
core/
  guard.py            规则层 + 语义层编排 + 决策
  guard_semantic.py   确定性语义分析（路径分词、载荷特征）
  mitm_guard.py       mitmproxy addon（实际挂载点）
ui/
  server.py           观测台后端（实时面板 + SSE + 策略模拟器）
  index.html          观测台前端（单文件，无构建）
healthsvc/
  health_server.py    本地健康检查靶站（供探针打）
probes/
  local_probe.py      护栏自检探针（25 项判定矩阵）
  containment_test.py 出网封禁验证
deploy/
  *.service.example   systemd unit 模板
  install.sh          安装脚本
examples/
  scopes.example.json 战役分组配置示例
docs/
  ARCHITECTURE.md     详细设计
  SANITIZATION.md     脱敏说明
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

```bash
cp examples/scopes.example.json scopes.json
# 编辑 scopes.json，填入你**有授权**的目标域名后缀

export JEV_API_KEY='your-typesafe-api-key'
export JEV_API_URL='https://api.typesafe.ai/v1/systemone'
export JEV_PROXY='http://127.0.0.1:7892'   # 访问 Jev API 的出口代理
```

### 3. 启动护栏

```bash
mitmdump -q --listen-host 0.0.0.0 --listen-port 9200 \
  --set ssl_insecure=true -s core/mitm_guard.py
```

### 4. 让目标程序走护栏

```bash
export HTTP_PROXY=http://127.0.0.1:9200
export HTTPS_PROXY=http://127.0.0.1:9200
# 还要把 mitmproxy CA 证书装进信任链
```

### 5. 打开观测台

```bash
python3 ui/server.py     # 默认 0.0.0.0:8789
# 浏览器打开 http://127.0.0.1:8789/
```

## 判定逻辑

请求进来后：

```
1. 规则层扫路径/方法/载荷
   ├─ 命中「删除/资金/外部触达/凭据变更」→ 403
   ├─ 命中「新建/改动」→ 放行但标注
   └─ 未命中 → 进入语义层

2. 语义层问 Jev 三个问题
   ├─ 是否删除或修改已存在数据？
   ├─ 是否 RCE 利用？
   └─ 影响面如何？

3. 综合判定
   ├─ 规则层+语义层都说危险 → 403
   ├─ 规则层说安全但语义层说危险 → 看置信度
   └─ 都说不危险 → 放行
```

### 特殊处理

| 场景 | 处理 |
|---|---|
| GET 无参数请求 | 跳过语义层（省 API 调用） |
| 读方法 + 路径含 `get/list/query` + 无写动词 | `bind` 等名词不算凭据变更 |
| Jev API 不可用 | 读方法放行、写方法 fail-closed 拒绝 |
| 被拦后重试 | 403 返回 `X-Artex-Retryable: 0`，调用方可识别不重试 |

## 性能

启用连接池（HTTP Keep-Alive）后实测：

| 指标 | 值 |
|---|---|
| 稳态延迟 | ~320ms |
| P90 | ~350ms |
| 冷启动首次 | ~800ms（TLS 握手） |

关键：`guard.py` 里的 `_jev_pool()` 用 urllib3 ProxyManager 复用连接，
否则每次调用都要重新 TLS 握手（+500ms）。

## 配置项

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `JEV_API_KEY` | 必填 | TypeSafe API Key |
| `JEV_API_URL` | typesafe 官方 | Jev 端点 |
| `JEV_PROXY` | 无 | 访问 Jev 的代理 |
| `GUARD_POLICY` | `dml` | `dml`=只拦删改+RCE，`jev`=纯模型，`strict`=全拦 |
| `GUARD_ENFORCE` | `1` | `0`=只审计不拦截 |
| `GUARD_SCOPE_MODE` | `all` | `all`=全站审计，`list`=仅白名单 |
| `GUARD_SCOPE_SUFFIX` | 空 | 逗号分隔的授权域名后缀 |
| `AUDIT_MODE` | `both` | `off`/`jev`/`both` |
| `T14_JEV_TIMEOUT` | `8` | Jev 调用超时（秒） |
| `T14_JEV_CACHE_TTL` | `300` | 判定结果缓存（秒） |

## 观测台面板

打开后能看到：

- **实时流量**：每条请求的判定结果、原因、Jev 置信度
- **战役分组**：按客户/项目分组统计（配置见 `scopes.json`）
- **拦截原因**：命中哪条规则
- **语义层健康**：Jev 是否在线、延迟、降级状态
- **策略模拟器**：输入一个 URL 看会被怎么判

## 自检

```bash
# 跑 25 项判定矩阵，验证护栏按预期工作
python3 probes/local_probe.py

# 验证出网封禁
python3 probes/containment_test.py
```

## ⚠️ 使用前提

**必须有目标资产的明确书面授权。**

本护栏减少误伤，但不能替代授权。它会拦截大部分破坏性动作，
但**不保证 100% 拦截**——模型判定有置信度，规则有盲区。

## 相关项目

- [mitmproxy](https://mitmproxy.org/) — 抓包与拦截框架
- [Jev](https://typesafe.ai/) — 语义安全判定模型
- [Artex](https://github.com/) — AI 自主渗透测试编排系统

## License

MIT
