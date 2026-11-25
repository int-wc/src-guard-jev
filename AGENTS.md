# AGENTS.md — 给 AI Agent 的使用说明

> 如果你是一个 AI agent，被要求用这套护栏做渗透测试，**先读完这份**。
> 人类用户可跳过，直接看 README.md。

---

## 一、这套护栏在做什么

它挂在你的出站流量的必经之路上，逐条判断：

```
你发出的每个请求
      ↓
  规则层扫一遍（路径/方法/载荷）
      ↓
  语义层问模型（这个是删数据还是读数据？）
      ↓
  放行 / 403
```

**它不是限速器，也不是 WAF。** 它只做一件事：

> 区分「只读探测」和「会改变现实的动作」

改变现实的动作包括：

| 类别 | 例子 |
|---|---|
| 删数据 | `DELETE /api/pic/delete` |
| 改数据 | `POST /customer/changeMobile` |
| 发短信/邮件给真人 | `POST /sso/authLogin/sms` |
| 涉及资金 | `POST /pay/refund` |
| 改凭据/权限 | `POST /user/bindMobile` |
| 命令执行 | `chmod u+s`、反弹 shell |

---

## 二、被 403 拦住时怎么办

### 正确理解这个 403

响应长这样：

```json
{"blocked": true,
 "by": "src-guard-jev",
 "policy_block": true,
 "retryable": false,
 "action": "stop",
 "error": "POLICY_BLOCKED",
 "message": "该请求被审计护栏按策略永久拒绝，重试无意义",
 "reasons": ["【业务写入保护】外部触达动作 sms"]}
```

响应头：

```
X-Guard-Policy-Block: 1
X-Guard-Retryable: 0
```

### ⛔ 绝对不要做的事

**不要重试。**

`retryable: false` 是明确信号：这条请求**永远**会被拦。
重试只会制造噪音——实测有 agent 在 7 秒内重试了 34 次同一个发短信请求。

**不要想办法绕过。**

包括但不限于：

```
❌ 换 IP 再试
❌ 加 Host 头绕路由
❌ 拆分请求让规则不匹配
❌ 换编码（URL 编码、base64、大小写）
❌ 走别的出口（socks / 直连）
```

这些行为会：

1. 被记录进审计日志
2. 被视为「agent 在试图规避安全控制」
3. 可能导致整个任务被终止

### ✅ 正确做法

**把这个点记为「需要人工确认」，然后继续测别的。**

具体怎么做：

1. **产出一个 finding**，写清楚：

   ```
   接口: POST /sso/authLogin/sms
   观察: 该接口无频率限制，理论上可短信轰炸
   状态: 未验证（护栏按策略拦截，需人工授权后验证）
   ```

2. **继续下一个目标点**，不要在一个点上打转。

3. 如果这个点确实是任务的核心目标，**停下来报告**，让人来决定。

---

## 三、什么请求能通过

### 默认放行

| 类型 | 例子 |
|---|---|
| GET 读接口 | `GET /api/user/info?id=1` |
| 查询/列表 | `POST /api/user/list` |
| 无害探测 | `GET /api/x?id=1'`（SQLi 探测不算破坏） |
| 上传新文件 | `POST /upload`（不覆盖已有文件） |
| 创建新记录 | `POST /api/comment`（不指向已存在资源） |

### 会被警告但放行

| 类型 | 说明 |
|---|---|
| 新建类动作 | 放行，但要求用**不存在的主键**测试 |
| 改动类动作 | 放行，但要求用**不存在的 ID** 验证 |

看到 `【...·放行附条件】` 标记时，**必须遵守附加条件**。

---

## 四、参数怎么传

### ❌ 硬编码密钥

```python
KEY = 'apikey_xxxxx'              # 不要
```

### ✅ 从环境变量读

```python
import os
KEY = os.environ.get('JEV_API_KEY')   # 正确
```

---

## 五、调试护栏本身

### 看某条请求被怎么判的

```bash
tail -100 /var/log/jev-guard/mitm-audit.log | grep 'your-target.com'
```

每行一个 JSON：

```json
{"ts":"2026-01-01T00:00:00",
 "h":"target.example",
 "method":"POST",
 "url":"https://target.example/api/x",
 "allow":false,
 "reasons":["【业务写入保护】外部触达动作 sms"],
 "jev":{"by":"jev","conf":0.87}}
```

### 用模拟器测一个 URL 会怎么判

```bash
curl -X POST http://127.0.0.1:8789/api/simulate \
  -H 'Content-Type: application/json' \
  -d '{"method":"POST","url":"https://target.example/api/x","body":"{}"}'
```

返回里能看到规则层和语义层各自的判定。

### 跑自检矩阵

```bash
python3 probes/local_probe.py
```

25 项覆盖：读/写/删/改/RCE/穿越/上传/SQLi/DoS。
如果 `不符` 数量 > 0，说明护栏配置有问题。

---

## 六、常见误判

| 现象 | 原因 | 怎么办 |
|---|---|---|
| `GET /getBindAccountInfo` 被拦 | 路径含 `bind`，规则以为是改绑 | 已修复（读动词优先）；如仍遇到，报告 |
| `POST /api/user/list` 被拦 | 请求体含 `deleted` 字段 | 模型误判；用模拟器确认，必要时报告 |
| Jev 调用超时 | 代理/网络问题 | 检查 `JEV_PROXY`；读请求会自动放行 |
| 延迟突然变高 | 连接池冷启动 / 代理问题 | 首次调用 ~800ms 正常，稳态 ~320ms |

---

## 七、边界

### 这套护栏不保证什么

- ❌ **不保证 100% 拦截**——模型有置信度，规则有盲区
- ❌ **不防数据渗出**——只拦「改删」，读操作默认放行
- ❌ **不替代授权**——你必须先有目标资产的书面授权

### 你的责任

护栏是**降低误伤概率**，不是**免除责任**。

如果你不确定某个动作是否会伤害真实用户，**先问，别试**。

---

## 八、快速检查清单

开始任务前：

- [ ] 确认目标在授权范围内
- [ ] 确认 `GUARD_ENFORCE=1`（拦截已开启）
- [ ] 确认 `scopes.json` 里有你的目标域名
- [ ] 跑一次 `probes/local_probe.py` 确认护栏正常

遇到 403 时：

- [ ] 读响应体的 `reasons` 字段
- [ ] 确认 `retryable` 是 `false`
- [ ] **停止重试**
- [ ] 记 finding，继续下一个点

任务结束时：

- [ ] 检查审计日志有没有异常重试
- [ ] 把「因护栏未验证」的点单独列出
