# E 数据导入后攻击链显示 core-server 指南

## 1. 目标

本指南用于说明：

> 将 E 数据导入系统后，如何确认攻击链和攻击图中能够正确出现 `core-server` 节点，以及 `win10-jump -> core-server` 这条关键访问路径。

E 数据中的关键攻击过程应体现为：

```text
attack-external -> web-server -> win10-jump -> core-server
                                      \
                                       -> c2-server
```

其中：

```text
win10-jump -> core-server
```

对应的是内部数据访问行为，D 模块会将其识别为：

```text
Collection / T1005 Data from Local System
```

而不是横向移动。原因是该行为的语义是 HTTP GET 内部文件资源，不是 SSH/RDP/SMB/WinRM 等远程服务登录。

## 2. 准备文件

导入 E 数据需要以下文件：

```text
out/eval_e_final_host_events.json
out/eval_e_final_network_events.json
data/hosts_e_case01.csv
```

三个文件的作用：

| 文件 | 作用 |
| --- | --- |
| `eval_e_final_host_events.json` | E 数据中的主机侧事件 |
| `eval_e_final_network_events.json` | E 数据中的网络侧事件 |
| `hosts_e_case01.csv` | IP 到主机名映射 |

主机映射中必须包含以下关键映射：

```text
10.10.10.10 -> attack-external
10.10.10.20 -> c2-server
10.10.20.10 -> web-server
10.10.30.10 -> win10-jump
10.10.30.20 -> core-server
```

如果缺少 `10.10.30.20 -> core-server`，攻击图中可能只显示 IP，而不是 `core-server`。

## 3. 合并 E 的主机事件和网络事件

由于 E 数据分为主机事件和网络事件两份 JSON，导入前需要合并成一份完整事件文件。

在项目根目录执行：

```powershell
python -c "import json,pathlib; root=pathlib.Path('.'); files=[root/'out/eval_e_final_host_events.json',root/'out/eval_e_final_network_events.json']; data=[]; [data.extend(json.loads(f.read_text(encoding='utf-8'))) for f in files]; out=root/'out/eval_e_final_events.json'; out.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8'); print('merged',len(data),out)"
```

正常情况下会生成：

```text
out/eval_e_final_events.json
```

当前 E 数据合并后应为：

```text
47775 条事件
```

## 4. 导入 E 数据

使用项目内置脚本重置数据库并导入 E 数据：

```powershell
python scripts\reset_import_export.py --name e_final --events out\eval_e_final_events.json --hosts data\hosts_e_case01.csv
```

这个命令会做几件事：

1. 删除旧的本地开发数据库 `data/attack_trace.db`。
2. 临时启动后端。
3. 导入 E 的 47775 条事件。
4. 同步 9 条主机映射。
5. 导出带数据库内部 ID 的 EventOut。
6. 停止临时后端。

成功时应看到类似结果：

```text
imported: 47775
failed: 0
hosts: 9
batch_id: e_final
id: 1~47775
```

注意：

> D 的 `evidence_event_ids` 使用的是导入后 SQLite 生成的数据库内部 `events.id`，所以必须先导入数据库，再由后端返回 EventOut。

## 5. 启动平台

导入脚本结束后会停止临时后端，所以需要重新启动平台：

```powershell
python scripts\start_platform.py --no-open
```

或直接运行：

```powershell
启动平台.bat
```

启动成功后访问：

```text
http://127.0.0.1:8000/
```

接口文档：

```text
http://127.0.0.1:8000/docs
```

健康检查：

```text
http://127.0.0.1:8000/health
```

## 6. 在前端页面确认

打开平台页面后：

1. 进入数据管理或批次选择区域。
2. 选择批次 `e_final`。
3. 进入攻击链 / 攻击图页面。
4. 刷新分析结果。
5. 检查图中是否包含 `core-server`。

攻击图中应至少出现以下节点：

```text
attack-external
web-server
win10-jump
core-server
c2-server
```

应出现以下关键边：

```text
attack-external -> web-server
web-server -> win10-jump
win10-jump -> core-server
win10-jump -> c2-server
```

其中：

```text
win10-jump -> core-server
```

对应阶段应该是：

```text
Collection
```

技术编号：

```text
T1005
```

## 7. 用接口确认

如果前端页面没有及时刷新，可以直接请求攻击链接口确认。

```powershell
python -c "import urllib.request,json; data=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/attack-chain?case_id=e_final', timeout=20)); print('nodes', len(data.get('nodes',[])), 'links', len(data.get('links',[]))); print([n.get('host') for n in data.get('nodes', [])]); [print(l.get('attack_stage'), l.get('source_host'), '->', l.get('target_host')) for l in data.get('links', []) if l.get('source_host') == 'win10-jump' and l.get('target_host') == 'core-server']"
```

正常情况下应能看到：

```text
nodes 5
links ...
['win10-jump', 'core-server', 'attack-external', 'web-server', 'c2-server']
Collection win10-jump -> core-server
```

这说明后端和 D 模块已经识别出 core-server。

## 8. 为什么 core-server 会出现

E 数据中存在这样的真实访问：

```text
10.10.30.10 -> 10.10.30.20:9100
GET /finance_demo.txt HTTP/1.1
```

经过 host_map 映射：

```text
10.10.30.10 -> win10-jump
10.10.30.20 -> core-server
```

D 的 Collection 规则识别的是通用语义：

```text
内部主机 -> 内部服务器
event_type = http_request
method = GET
访问文件或资源
资源名或上下文体现敏感数据访问
```

所以输出：

```text
Collection / T1005
win10-jump -> core-server
```

这里没有硬编码：

```text
没有硬编码 10.10.30.10
没有硬编码 10.10.30.20
没有硬编码 9100
没有硬编码 /finance_demo.txt
```

只要以后出现类似“内部主机访问内部服务器文件资源”的事件，也可以触发同类规则。

## 9. 为什么不是 Lateral Movement

横向移动规则主要识别：

```text
内网主机 -> 内网主机
并且目标端口是远程服务端口
```

典型远程服务包括：

```text
22    SSH
445   SMB
3389  RDP
5985  WinRM
5986  WinRM over HTTPS
```

而 E 数据里的 `win10-jump -> core-server` 是：

```text
HTTP GET /finance_demo.txt
```

它更像是攻击者通过跳板机访问核心服务器上的数据资源，因此判成：

```text
Collection / T1005
```

如果强行判成 Lateral Movement，ATT&CK 语义反而不准确。

## 10. 如果看不到 core-server，怎么排查

### 10.1 检查是否导入了 E 数据

```powershell
python -c "import sqlite3; con=sqlite3.connect('data/attack_trace.db'); print('events', con.execute('select count(*) from events').fetchone()[0]); print('hosts', con.execute('select count(*) from hosts').fetchone()[0])"
```

正常应为：

```text
events 47775
hosts 9
```

如果 `events = 0`，说明数据库是空的，需要重新导入。

### 10.2 检查批次是否存在

```powershell
python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/batches').read().decode('utf-8'))"
```

正常应包含：

```text
e_final
```

### 10.3 检查 host_map 是否有 core-server

检查：

```text
data/hosts_e_case01.csv
```

必须包含：

```text
10.10.30.20,core-server,server-zone
```

如果没有这条，D 可能无法把 `10.10.30.20` 显示成 `core-server`。

### 10.4 检查网络事件是否包含 HTTP 请求

E 数据中需要存在：

```text
event_type = http_request
src_ip = 10.10.30.10
dst_ip = 10.10.30.20
detail.method = GET
detail.uri = /finance_demo.txt
```

如果 C 侧解析结果仍然是普通：

```text
event_type = network_connection
```

而没有升级为：

```text
event_type = http_request
```

那么 D 可能无法识别为 Collection。

### 10.5 检查页面是否还是旧缓存

如果接口已经能看到 `core-server`，但前端页面没有：

1. 刷新页面。
2. 重新选择 `e_final` 批次。
3. 重新点击分析。
4. 重启后端。

## 11. 讲解时可以这样说

导入 E 数据后，系统会先将主机日志和网络流量统一入库，并同步 IP 到主机名映射。D 模块在分析攻击链时，不直接使用裸 IP 展示节点，而是通过 host_map 将 `10.10.30.10` 映射为 `win10-jump`，将 `10.10.30.20` 映射为 `core-server`。

E 数据中存在 `win10-jump` 访问 `core-server` 上内部文件资源的 HTTP GET 行为。D 根据“内部主机访问内部服务器敏感资源”的通用语义，将其识别为 `Collection / T1005`，并在攻击图中生成 `win10-jump -> core-server` 这条边。

因此，最终攻击图中不仅有初始入侵路径：

```text
attack-external -> web-server -> win10-jump
```

也有核心数据访问路径：

```text
win10-jump -> core-server
```

以及 C2 通信路径：

```text
win10-jump -> c2-server
```

这说明系统能够从多源事件中还原攻击者进入内网、移动到跳板机、访问核心服务器数据并与 C2 通信的完整过程。

