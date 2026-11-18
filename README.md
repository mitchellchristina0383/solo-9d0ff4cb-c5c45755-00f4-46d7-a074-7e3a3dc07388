# PCAP HTTP/1.1 Flow Analyzer & ARP 争用诊断

面向网络值班的抓包分析 API：

1. **HTTP 流分析**：上传以太网 / IPv4 / TCP 抓包（pcap 或 pcapng），
   对**完整捕获三次握手、目的端口 80、且每连接仅有一次 HTTP/1.1 请求**的连接，
   返回**请求行、Host、响应状态码和连接标识**。
2. **ARP 网关争用诊断**：上传以太网抓包，指定**已登记网关 IPv4** 和
   **应答等待时长**，按 VLAN 关联 ARP 探测请求与应答，核对是否有两个不同
   MAC 冒答同一网关地址（离线取证，宁可待核也不硬凑证据）。

## 快速开始

```bash
docker compose up --build
# 打开 http://localhost:8000/docs
# 用 POST /analyze 上传 pcap 文件；仓库自带样例 samples/sample.pcap，
# 也可先 GET /sample 下载样例再上传，或直接 POST /analyze/sample 分析内置样例。
# ARP 诊断：POST /analyze/arp 上传 samples/arp_contention.pcap
# （可先 GET /sample/arp 下载），表单填 gateway_ip=192.168.1.1、wait_ms=500；
# 或直接 POST /analyze/arp/sample 分析内置 ARP 样例。
```

本地运行（无 Docker）：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## API

| 端点 | 说明 |
| --- | --- |
| `POST /analyze` | 上传 pcap/pcapng（表单字段 `file`），返回 HTTP 流分析 JSON |
| `GET /sample` | 下载内置样例 `sample.pcap` |
| `POST /analyze/sample` | 直接分析内置样例 |
| `POST /analyze/arp` | ARP 争用诊断：表单字段 `file`（抓包）、`gateway_ip`（已登记网关 IPv4）、`wait_ms`（每个探测的应答等待时长，毫秒，默认 500） |
| `GET /sample/arp` | 下载内置 ARP 样例 `arp_contention.pcap` |
| `POST /analyze/arp/sample` | 直接分析内置 ARP 样例（查询参数 `gateway_ip`、`wait_ms` 可覆盖默认值） |
| `GET /docs` | Swagger UI（可在线上传文件） |

### 结果结构

```jsonc
{
  "summary": { "tcp_segments": 75, "flows": 9, "ok": 2, "unreliable": 3, "skipped": 4 },
  "flows": [
    {
      "id": 0,
      "status": "ok",                    // ok | unreliable | skipped
      "connection": { "client": "10.0.0.10:50001", "server": "93.184.216.34:80", ... },
      "request":  { "request_line": "GET /index.html HTTP/1.1", "method": "GET",
                    "target": "/index.html", "version": "HTTP/1.1", "host": "example.com" },
      "response": { "status_line": "HTTP/1.1 200 OK", "status_code": 200, ... },
      "directions": {
        "client_to_server": { "reliable": true, "header_complete": true,
                              "reassembled_bytes": 60, "gaps": [], "conflicts": [],
                              "truncated": false, ... },
        "server_to_client": { ... }
      },
      "reasons": []
    }
  ]
}
```

## ARP 争用诊断

### 结果结构

```jsonc
{
  "gateway_ip": "192.168.1.1",
  "reply_wait_ms": 500.0,
  "verdict": "suspected_contention",   // suspected_contention | no_contention_observed | no_probes_found
  "summary": { "frames_total": 18, "arp_frames": 17, "arp_truncated_excluded": 1,
               "probes": 6, "replies": 8, "suspected_contentions": 1,
               "probes_single_responder": 2, "probes_no_valid_reply": 3,
               "pending_replies": 2, "unmatched_replies": 2, ... },
  "findings": [
    { "probe": { "packet_index": 0, "timestamp": 1700000001.0, "vlan": 10,
                 "prober_mac": "02:00:00:00:00:10", "prober_ip": "10.0.0.10" },
      "status": "suspected_contention",          // suspected_contention | single_responder | no_valid_reply
      "parties": [ { "sender_mac": "02:00:00:00:00:01", "reply_packets": [1] },
                   { "sender_mac": "02:00:00:00:00:99", "reply_packets": [2] } ] }
  ],
  "pending_replies":  [ { "packet_index": 5, "candidate_probe_packets": [3, 4], ... } ],
  "unmatched_replies": [ { "packet_index": 12, ... } ]
}
```

`packet_index` 是报文在抓包文件中的序号（从 0 开始，按文件顺序）。

### 判定规则

- **探测**：ARP 请求 `tpa == 网关 IPv4`；**应答**：ARP 响应 `spa == 网关 IPv4`。
  只处理标准的 Ethernet/IPv4 ARP（htype=1, ptype=0x0800, hlen=6, plen=4）。
- **按 VLAN 关联**：应答只与**同一 VLAN** 的探测匹配（未打标签的帧自成一组；
  QinQ 叠加标签取最外层 VID）。跨 VLAN 的应答绝不互相归属。
- **可归属**：应答还须指向探测者（`tpa/tha == 探测的 spa/sha`），且时间落在
  探测后的等待窗口 `(probe.ts, probe.ts + wait]` 内。**有且仅有一个**探测
  满足全部条件时，应答才归属该探测。
- **疑似争用**：同一探测收到**两个不同发送 MAC** 的可归属应答才报告，
  并列出探测、双方 MAC 和各自应答的报文序号。
- **等待期交叠**：ARP 没有事务号。重复探测的等待窗口交叠时，落在交叠区的
  应答同时匹配多个探测、无法唯一归属——单列 `pending_replies` 待核，
  **不充当任何一方的证据**（对应探测记为 `no_valid_reply` 并注明有待核应答）。
- **单方应答 / 无有效回复**：恰好一个 MAC 应答记 `single_responder`；
  窗口内无可归属应答记 `no_valid_reply`，两者分别说明。
- **截断报文不能计入**：凡被 snaplen 截断（捕获长度 < 线上长度）或 ARP 体
  不完整的帧一律排除在计数与证据之外，只计入 `arp_truncated_excluded`。
- **未匹配应答**：不满足归属条件的网关应答（如 gratuitous 广播、跨 VLAN、
  超出窗口、对应探测未被捕获）列入 `unmatched_replies`，仅供人工核对。

### 内置 ARP 样例覆盖的场景

`samples/arp_contention.pcap`（由 `scripts/make_arp_sample_pcap.py` 生成）：

| 报文序号 | 场景 | 预期 |
| --- | --- | --- |
| 0–2 | 探测收到网关与冒用者两个 MAC 的应答 | suspected_contention，双方及报文序号入列 |
| 3–6 | 两个探测等待窗口交叠，双方应答落在交叠区 | 2 条应答 pending 待核，探测记 no_valid_reply |
| 7–8 | 仅网关应答 | single_responder |
| 9 | 无应答 | no_valid_reply |
| 10–11 | VLAN 20 上的正常一问一答 | 按 VLAN 正确关联，single_responder |
| 12 | 冒用者应答打在 VLAN 10（探测在 VLAN 20） | unmatched，不跨 VLAN 归属 |
| 13 | 冒用者应答被 snaplen 截断 | 排除计数（否则 #10 会被误判争用） |
| 14 | 冒用者 gratuitous 广播应答 | unmatched |
| 15–17 | TCP 帧、其他地址的 ARP 问答 | 诊断忽略 |

## 判定规则（HTTP 流分析）

- **流筛选**：必须完整捕获 SYN / SYN-ACK / ACK 三次握手；服务器端口必须为 80；
  请求必须是 HTTP/1.1；一条连接上只允许一个请求（检测到流水线/第二个请求即跳过，
  避免把响应误配给别的请求）。
- **字节还原**：每个方向按 TCP 序列号（相对于各自 ISN）归并；乱序报文按序号排序，
  同内容重传/重叠只计一次。
- **可靠性**（按方向判定，只关心头部结束之前的字节）：
  - 头部结束（`\r\n\r\n`）之前存在**缺口** → 该方向 unreliable；
  - 重叠字节**内容冲突** → 该方向 unreliable；
  - 任一报文被 snaplen **截断**（捕获长度 < 线上长度且载荷受损）→ 该方向 unreliable；
  - 头部始终未完整出现 → 该方向 unreliable。
- 一个方向不可靠时，**另一个方向的结果照常返回**（例如请求缺缺口但响应完整，
  仍返回响应状态码，请求字段为 null）；响应永远只与同一连接配对，绝不跨连接猜测。
- 头部结束之后的缺口/冲突不影响判定（本工具只取请求行、Host、状态码）。

## 样例 PCAP 覆盖的场景

`samples/sample.pcap`（由 `scripts/make_sample_pcap.py` 生成，可重新生成）：

| 客户端端口 | 场景 | 预期状态 |
| --- | --- | --- |
| 50001 | 普通 OK，请求/响应头各跨 2 个报文 | ok |
| 50002 | 乱序 + 同内容重传 | ok（不重复计数） |
| 50003 | 请求头中间缺一段 | unreliable（响应 404 仍返回） |
| 50004 | 响应重叠字节冲突（200 vs 500） | unreliable（请求仍返回） |
| 50005 | 无三次握手 | skipped |
| 50006 | 目的端口 8080 | skipped |
| 50007 | 流水线两个请求 | skipped |
| 50008 | 请求报文被截断 | unreliable（响应 200 仍返回） |
| 50009 | HTTP/1.0 请求 | skipped |

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

HTTP 部分覆盖：重传去重、乱序归并、缺口检测、重叠冲突、截断标记、握手完整性、
端口过滤、单请求限制，以及基于样例 PCAP 的 API 端到端断言。

ARP 部分覆盖：双 MAC 争用检出、同 MAC 重复应答不算争用、**交叠等待窗口**的
应答待核且不作证据、窗口不交叠时正常归属、**跨 VLAN 隔离**与按 VLAN 关联、
**截断应答不计入**（含"仅缺尾部字节也算截断"）、无应答、超窗应答、
gratuitous 广播、非本网关地址过滤、无标签帧自成一组，以及样例 PCAP 的
API 端到端断言。

## 已知限制

- 不重组 IP 分片（分片报文被跳过，在流上表现为缺口 → 该方向 unreliable）。
- 不解析 TLS；`Transfer-Encoding: chunked` 的请求体长度不用于"第二请求"检测
  （请求带 chunked body 且同连接还有后续请求时可能漏判多请求）。
- 同一四元组在捕获内被重复用于多条连接（TIME_WAIT 后重建）时按一条流处理。
- pcapng 时间戳按默认微秒分辨率解析（不读取 `if_tsresol` 选项）。
- ARP 诊断仅支持以太网链路（含 802.1Q；QinQ 取最外层 VID 关联），
  不解析其他链路类型上的 ARP。
- ARP 无事务号：等待窗口交叠时的应答只能列为待核，工具不会猜测归属；
  抓包起点之前的探测所对应的应答会落入 `unmatched_replies`。
