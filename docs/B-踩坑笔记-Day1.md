# B的踩坑笔记 · Day 1（9/7 提前完成）

> 按任务清单要求记录，Day 2 写 Linux 解析器、Day 3 全量导入时直接复用。
> ⭐ = 今天实际踩到并已解决；其余为验证过的注意事项。

## 1. ⭐ `wevtutil epl` 导出本机日志需要管理员权限

- 现象：普通终端执行 `wevtutil epl Security out.evtx` → `拒绝访问`。
- 解决：用**管理员身份**运行终端再执行；或者不折腾，直接用公开样例数据集。
- 本次用的数据源：GitHub **sbousseaden/EVTX-ATTACK-SAMPLES**（带ATT&CK标注的真实攻击evtx，任务书要求"收集互联网数据集"，正对口）。

## 2. ⭐ `raw.githubusercontent.com` 在当前网络环境连不上

- 现象：`curl` 下载样例报 SSL 错误（exit code 35），但 `api.github.com` 是通的。
- 解决：走 GitHub Contents API 拿 base64 再解码（文件<1MB时可用）：

```python
import base64, json, urllib.request
url = "https://api.github.com/repos/sbousseaden/EVTX-ATTACK-SAMPLES/contents/<路径>.evtx"
data = json.load(urllib.request.urlopen(url))
open("out.evtx", "wb").write(base64.b64decode(data["content"]))
```

- ⚠️ 仓库名是 `sbousseaden/`（原版）；搜"Yamato"那个是记忆错误，会404。

## 3. ⭐ python-evtx 0.8.1 的两个时间可能差1~2秒

- `record.timestamp()`（evtx记录头里的FILETIME）和 XML 里 `TimeCreated/SystemTime`（事件查看器显示的）**不是同一个值**，实测相差约1.7秒。
- 结论：**以XML的 SystemTime 为准**（这是事件真正的发生时间），`record.timestamp()` 只做兜底。
- evtx内部时间是**UTC**，已统一转成UTC+8输出（契约硬规矩）。XML里的格式是 `2020-09-09 13:18:23.627951+00:00`，`datetime.fromisoformat()` 能直接解析。

## 4. ⭐ SubStatus 查表的大小写坑（测试抓出来的真bug）

- 数据里是 `0xc000006a`（小写x小写十六进制），码表键是 `0xC000006A`；
- 直接 `sub.upper()` 会把 `0x` 也变成 `0X` → 查表永远失配；
- 解决：`_norm_substatus()`——先按 `0x` 切开，十六进制部分单独大写再拼回去。

## 5. Windows事件XML解析要点

- 命名空间必须带：`{http://schemas.microsoft.com/win/2004/08/events/event}`，否则所有findtext返回None（不报错，更难查）。
- `<EventID Qualifiers="">4625</EventID>`：EventID可能带Qualifiers属性，取text就行。
- `<EventData>` 里 `<Data Name="...">text</Data>`，业务字段全在这，按Name建dict。
- **空值统一是 `"-"`**：4624本地登录时 `IpAddress="-"`，必须转null（契约规矩2），否则"-"会污染D的IP关联。
- 4625 的 `FailureReason` 是 `%%2313` 这种消息占位符不是人话；**判断失败原因要看 `SubStatus`**（0xC0000064用户不存在 / 0xC000006A密码错误 / 0xC0000072禁用 / 0xC0000234锁定）。

## 6. 实测数据形态（写Day2规则时用）

- 网络登录（LogonType 3）**有src_ip**，且**可能是IPv6**（实测 `fe80::79bf:...` 本地链路地址）——D做IP关联、B写异常规则时都要兼容IPv6。
- 机器账号长这样：`WIN-77LTAPHIQ1R$`（结尾带$），不是真人登录，规则里要区分。
- 一个68KB的evtx样本≈10条记录，几十MB的文件就是几万条——Day2全量导入务必按"条"try-except（已实现）。
- 4624的 `ProcessName` 是完整路径，入库前取了basename。

## 7. 环境备忘

- Python 3.10.11；`pip install python-evtx requests` 一次成功（0.8.1 / 2.34.2）。
- Git Bash 里跑Python打印中文：前面加 `PYTHONIOENCODING=utf-8`。
- 控制台看到 `鏉庡浗瀹` 这种乱码就是编码问题，数据文件本身是UTF-8无碍。

## 8. Day 1 产出清单（给Day 2的自己）

| 产出 | 位置 |
|---|---|
| 契约文档（待会议定稿） | docs/数据格式契约-v1.md |
| 标准事件代码版 | b_host_parser/schema.py |
| Windows解析器 | b_host_parser/windows_evtx.py |
| Sysmon解析器 | b_host_parser/sysmon.py |
| 导入客户端（jsonl/POST） | b_host_parser/import_client.py |
| 命令行入口 | b_host_parser/run_parse.py |
| 一键自检脚本 | b_host_parser/verify_day1.py |
| 样例数据×4 | data/sample_logs/*.evtx |
| 解析结果 | data/output/*.jsonl（22条，契约校验全过） |
| 给A的样例文档 | docs/给A的标准事件样例-v1.1.md |

## 9. Day 1.5 补充（应A"要真实样例"需求，提前做了4688+Sysmon时踩的坑）

1. **UnboundLocalError: cmdline** —— 给4688分支加cmdline时，4624/4625分支没这个变量，make_event里`cmdline=cmdline`直接炸，登录事件全军覆没。教训：**多分支构造dict时，公共变量先给默认值**（`cmdline = None`放分支前）。幸好按"条"try-except兜住了，文件没崩、统计里`failed`直接暴露。
2. **sysmon.py漏传raw_log** —— make_event没传raw_log导致它为null（契约里是必填）。被自检脚本的"raw_log必填"断言抓出来。教训：**必填字段的校验要写进verify脚本**，人眼会漏。
3. **4688的 NewProcessId ≠ ProcessId** —— `NewProcessId`才是新建进程的PID，`ProcessId`是创建者(父)进程的PID，第一次取反了。
4. **4688的CommandLine是空字符串""而不是缺失** —— 没开"进程创建命令行审核策略"时它是`""`，`_clean()`把""转成null，正好符合"没有就null不造假"的约定。
5. **Sysmon的User字段看配置** —— ID 11/13的样本里没有User字段（采集配置没启用），如实null；ID 1/3有。
6. **Sysmon ID 12 ≠ ID 13** —— 12是注册表对象创建/删除，13是键值修改；当前只做13，12计入other。
7. **4624的IpPort是源端口不是目的端口** —— 放`detail.src_port`，别冒充dst_port。
