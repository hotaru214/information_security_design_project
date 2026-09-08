# B踩坑笔记 · Day2（2026-09-08）

> 承接《B-踩坑笔记-Day1.md》。今天主题：会话重建、8个新事件ID、异常预标记、全量导入。

## 1. python-evtx 的容错性远比想象的强（全量导入的容错设计依据）

做任务9前做了组实验（往各种"坏文件"上跑 python-evtx）：

| 输入 | python-evtx行为 |
|---|---|
| 空文件（0字节） | **打开即抛** `ValueError: cannot mmap an empty file` |
| 纯垃圾字节 | 打开成功，`records()` 返回 **0条**，不报错 |
| 截断50%/90% | 打开成功，返回 **0条**，不报错 |
| 文件头魔术字被砸（`ElfFile\x00`→`GARBAGE!`） | 照常打开，甚至还能"解析"出记录（内容不可信） |

**结论**：指望"坏文件抛异常"来兜底不现实——大多数坏文件是**静默产出0条**。所以全量导入做了三层：
1. 解析器内部按"条"try-except（Day1就有）：一条坏记录只丢一条；
2. `run_parse.py --dir` 按"文件"try-except：真抛异常的文件（如空文件）只丢一个文件；
3. **"0条记录"的文件单独标出来**（`[⚠️无记录]`）：既不是成功也不是异常，报告里必须看得见，否则E给的数据悄悄少一块都不知道。

## 2. `schema.py` 的 EVENT_TYPES 漂移了整整一天没人发现

Day1晚上的对齐提交（97e55c0）改了两个解析器的 `SUPPORTED` 字典，但 `schema.py` 里的 `EVENT_TYPES` 常量漏改了——`login_failure/process_create/network_connect` 三个旧词在里面躺了一夜。**为什么没被发现：这个常量没有任何地方 import，verify_day1 也不校验它**，纯属"给读代码的人看的死声明"，漂移了照样7/7全绿。

**修复**：对齐V2词表（31词），并在 verify_day2 里加了一条"EVENT_TYPES 与 V2 词表逐词一致"的断言——从机制上锁死，下次再漂移秒抓。
**教训**：没用到的常量比没有常量更危险——它是会过期的文档。

## 3. 4728 的 `TargetUserName` 是"组名"，不是用户

4728（成员加入组）的 EventData 里：
- `TargetUserName` = **组名**（如 Administrators）
- `MemberName` = 被加进去的成员（可能是 DN `CN=xx,DC=...`，也可能是 SAM 名，还可能是 `-`）
- `MemberSid` = 成员SID

第一直觉会把 TargetUserName 当"目标用户"——那就把组当成用户写进 `user` 字段了。现在：`user` = MemberName（为`-`时退 MemberSid），`detail.group_name` = TargetUserName，`detail.target_user` = 成员。**Windows事件字段名的"Target"指的是"动作作用的对象"，不一定是用户**——4720的TargetUserName才是新账号。

## 4. 合成测试XML的转义坑

给 4698 造测试数据时直接写了 `TaskContent="<Task><Actions>...</Actions></Task>"`——内容里的 `<`/`>` 直接把整条XML弄成 not well-formed。真实evtx里这类内容是转义过的（`&lt;Task&gt;...`），合成样例必须模拟转义后的形态。**合成数据要模拟"原始字节长什么样"，不是"逻辑上是什么"。**

## 5. 异常规则的两个设计决策（写报告要能说清）

1. **窗口内全部标记，不只标最后一条**：brute_force 5分钟窗口内 ≥3 次失败，3条全打标——D的关联引擎和前端时间线需要完整攻击片段，只标最后一条丢上下文。
2. **幂等性**：规则引擎重复跑结果必须一致（flag去重、severity取max）。全量导入和单文件解析都会调它，将来重跑不叠加。
3. 依赖关系写在了 docstring 里：offhour_login 依赖 Day1 的 UTC→UTC+8 转换（`to_utc8`）；brute_force 必须在**合并后**的整批事件上跑——逐文件跑会漏掉跨文件的爆破（攻击者5分钟内打两台机）。

## 6. `username_enumeration` 的"密集"阈值是自定的

任务清单只写了"SubStatus=0xC0000064 密集出现"没给数。首版按 brute_force 同款阈值：**同 src_ip 5分钟内 ≥3 次"用户不存在"**。已在代码注释和报告素材里标注"待D复核"——D如果要改，改 `anomaly.py` 里的 `ENUM_THRESHOLD` 一个常量即可。

## 7. 工程位置变化

B模块从仓库根 `b_host_parser/` 移到了 `backend/b_host_parser/`（与A的后端同仓）。所有"项目根"路径（`run_parse.py` 的 `PROJECT_ROOT`、`verify_day*.py` 的 `PROJECT`）从"上一级"改成"上两级"——移动目录时最容易漏的就是这种**隐式相对路径**，verify 脚本一跑就现形（Day1的 t2 检查样例文件存在性，路径错了立刻 FAIL）。
