# PCAP HTTP/1.1 Flow Analyzer

面向网络值班的抓包分析 API：上传以太网 / IPv4 / TCP 抓包（pcap 或 pcapng），
对**完整捕获三次握手、目的端口 80、且每连接仅有一次 HTTP/1.1 请求**的连接，
返回**请求行、Host、响应状态码和连接标识**。

## 快速开始

```bash
docker compose up --build
# 打开 http://localhost:8000/docs
# 用 POST /analyze 上传 pcap 文件；仓库自带样例 samples/sample.pcap，
# 也可先 GET /sample 下载样例再上传，或直接 POST /analyze/sample 分析内置样例。
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
| `POST /analyze` | 上传 pcap/pcapng（表单字段 `file`），返回分析结果 JSON |
| `GET /sample` | 下载内置样例 `sample.pcap` |
| `POST /analyze/sample` | 直接分析内置样例 |
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

## 判定规则

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

覆盖：重传去重、乱序归并、缺口检测、重叠冲突、截断标记、握手完整性、
端口过滤、单请求限制，以及基于样例 PCAP 的 API 端到端断言。

## 已知限制

- 不重组 IP 分片（分片报文被跳过，在流上表现为缺口 → 该方向 unreliable）。
- 不解析 TLS；`Transfer-Encoding: chunked` 的请求体长度不用于“第二请求”检测
  （请求带 chunked body 且同连接还有后续请求时可能漏判多请求）。
- 同一四元组在捕获内被重复用于多条连接（TIME_WAIT 后重建）时按一条流处理。
- pcapng 时间戳按默认微秒分辨率解析（不读取 `if_tsresol` 选项）。
