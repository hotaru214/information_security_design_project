# -*- coding: utf-8 -*-
"""
Sysmon/Security JSON-lines 适配器（APT29 day1 manual 数据集专用）
================================================================
输入 : OTRF detection-hackathon-apt29 的 apt29_evals_day1_manual_*.json
       —— NXLog 导出的 JSON 行格式，每行一个"扁平"JSON：
       EventID / Channel / Hostname / @timestamp 直接在顶层，
       EventData 的业务字段（Image/CommandLine/TargetUserName...）也是顶层键。
输出 : Event V2 标准事件列表（19字段，source_event_id 版，
       见 backend/parsers/network/normalize.py 的 EVENT_V2_FIELDS）

为什么单独一个文件：本模块原有的 windows_evtx.py / sysmon.py 只吃 .evtx 二进制
（python-evtx 解码），Linux 日志走 linux_log.py——这个数据集是"已被导成 JSON 行
的 Windows 事件"，走不了 python-evtx，于是单独适配。
字段映射口径与 windows_evtx.py / sysmon.py 完全一致（同一批字段、同一批描述文案），
只是"取字段的方式"从 XML findtext 换成顶层 dict 取键。

映射口径（词表=EVENT_TYPES 冻结枚举；Security 分支照抄 windows_evtx.SUPPORTED，
另加两个"便宜且高价值"的事件，均有现成词表词）:
    Sysmon  1 → process_start          Security 4624 → login_success
    Sysmon  3 → network_connection     Security 4625 → login_failed
    Sysmon 11 → file_create            Security 4634/4647 → logout
    Sysmon 13 → registry_set           Security 4688 → process_start
    Sysmon 22 → dns_query（C2域名证据） Security 1102 → log_cleared
    Sysmon 23 → file_delete            Security 4673 → privilege_change
                                       Security 4720 → user_created
                                       Security 4728 → group_member_added
                                       Security 4697 → service_created（Security
                                                          通道版"服务安装"=7045 的等价事件）
                                       Security 4698 → scheduled_task_created
其余 ID（Sysmon 12/7/9/5/18/2/17、Security 4656/4663/5156/5447...、
PowerShell 4103/4104/800）跳过并计数——大多是没有现成词表词的噪声/审计事件。
（2026-09-12 起 Sysmon 8/10 已支持——任务书第4条"内存行为分析"：
ProcessAccess 掩码/调用栈 + CreateRemoteThread 是注入与反射加载的日志层指纹，
检测规则在 anomaly.py 的 lsass_access / suspicious_memory_access / reflective_load）

⚠️ 时间口径：
  - 优先取事件自己的 UtcTime（Sysmon EventData 自带，毫秒精度，真·UTC）；
  - 取不到退回 @timestamp（WEC 入库时间，比事件发生晚几秒）；
  - 千万别用 EventTime——那是采集机本地时间（本数据集为 UTC-4），不是 UTC。
主机名口径：用 Hostname（被采集主机，如 SCRANTON.dmevals.local），
  别用 host——那是 WEC 采集器自己（wec.internal.cloudapp.net）。
去重口径：数据里 Channel 同时存在 "Security" 和 "security" 两种大小写（两条采集
  管道），已验证二者 (Hostname, EventID, RecordNumber) 无重复，直接合并即可。
"""
import json
from datetime import datetime

from schema import make_event, LOGON_TYPES, SUB_STATUS
from windows_evtx import to_utc8, _clean, _basename, _norm_substatus

# 事件ID → event_type（Sysmon 侧照抄 sysmon.py，另加 22/23；Security 侧照抄
# windows_evtx.py，另加 4697。映射到哪个词表词与对应 .evtx 解析器一致）
SYSMON_SUPPORTED = {
    1: "process_start",
    3: "network_connection",
    8: "remote_thread_create",
    10: "process_access",
    11: "file_create",
    13: "registry_set",
    22: "dns_query",
    23: "file_delete",
}
SECURITY_SUPPORTED = {
    4624: "login_success",
    4625: "login_failed",
    4634: "logout",
    4647: "logout",
    4688: "process_start",
    1102: "log_cleared",
    4720: "user_created",
    4728: "group_member_added",
    4673: "privilege_change",
    4697: "service_created",   # Security 通道的服务安装（7045 在 System 通道）
    4698: "scheduled_task_created",
}

# 伪多级公共后缀（取 base 域名时保 3 段），够用即可，不全列
_CC_SUFFIX = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.cn", "net.cn", "gov.cn",
              "com.hk", "com.tw", "co.jp", "com.au", "co.kr", "com.br"}


def _base_domain(qname: str) -> str | None:
    """'resolver1.opendns.com' → 'opendns.com'（对齐C侧 dns_query detail.domain 口径）"""
    if not qname:
        return None
    labels = qname.rstrip(".").split(".")
    if len(labels) <= 2:
        return qname.rstrip(".")
    tail = ".".join(labels[-2:])
    if tail in _CC_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


def _to_int(value):
    """字符串数字 → int；不是数字（'-'等已被_clean处理，这里兜底）返回 None。"""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip()
    return int(s) if s.isdigit() else None


def _event_ts(ev: dict) -> str | None:
    """行JSON → UTC+8 字符串。优先 UtcTime（事件真实时间），退回 @timestamp。"""
    raw = _clean(ev.get("UtcTime"))
    if raw:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return to_utc8(datetime.strptime(raw, fmt))
            except ValueError:
                continue
    raw = _clean(ev.get("@timestamp"))          # WEC入库时间（ISO8601 UTC，带Z）
    if raw:
        try:
            return to_utc8(datetime.fromisoformat(raw.replace("Z", "+00:00")))
        except ValueError:
            pass
    return None


def _route_channel(channel: str) -> str | None:
    """Channel → 解析路由。认不出的通道（PowerShell等）返回 None。"""
    ch = (channel or "").lower()
    if "sysmon" in ch:
        return "sysmon"
    if ch == "security":
        return "security"
    return None


def _sysmon_event(event_id: int, data: dict, ts, host: str) -> dict | None:
    """Sysmon 分支：字段口径与 sysmon.py（.evtx版）一致。不支持的ID返回None。"""
    event_type = SYSMON_SUPPORTED.get(event_id)
    if event_type is None:
        return None
    image = _basename(_clean(data.get("Image")))
    user = _clean(data.get("User"))
    cmdline = _clean(data.get("CommandLine"))

    if event_id == 1:  # 进程创建
        parent = _basename(_clean(data.get("ParentImage")))
        description = f"进程创建: {image}（父进程: {parent}）"
        detail = {"parent_process": parent,
                  "parent_cmdline": _clean(data.get("ParentCommandLine")),
                  "hashes": _clean(data.get("Hashes")),
                  "process_guid": _clean(data.get("ProcessGuid")),
                  "process_id": _to_int(data.get("ProcessId")),
                  "logon_id": _clean(data.get("LogonId"))}
    elif event_id == 3:  # 网络连接：桥接C的流量数据，src/dst/端口/协议都是顶层键
        src_ip = _clean(data.get("SourceIp"))
        dst_ip = _clean(data.get("DestinationIp"))
        dst_port = _to_int(data.get("DestinationPort"))
        protocol = (_clean(data.get("Protocol")) or "").lower() or None
        dhost = _clean(data.get("DestinationHostname"))
        port_desc = f":{dst_port}" if dst_port else ""
        proc_desc = image or "进程未记录"
        dst_desc = dhost or dst_ip or "未知"
        description = f"进程 {proc_desc} 发起网络连接: {src_ip} → {dst_desc}{port_desc} ({protocol})"
        detail = {"src_port": _to_int(data.get("SourcePort")),
                  "destination_hostname": dhost,
                  "source_hostname": _clean(data.get("SourceHostname")),
                  "initiated": _clean(data.get("Initiated")),
                  "process": _clean(data.get("Image")),
                  "process_guid": _clean(data.get("ProcessGuid"))}
        return make_event(timestamp=ts, host=host, source="sysmon",
                         source_event_id=event_id, event_type=event_type, user=user,
                         process=image, src_ip=src_ip, dst_ip=dst_ip,
                         dst_port=dst_port, protocol=protocol, cmdline=cmdline,
                         detail=detail, description=description,
                         raw_log=data.get("_raw_line"))
    elif event_id == 11:  # 文件创建
        target = _clean(data.get("TargetFilename"))
        description = f"创建文件: {target}（进程: {image}）"
        detail = {"file_path": target,
                  "creation_utc_time": _clean(data.get("CreationUtcTime")),
                  "hashes": _clean(data.get("Hashes")),
                  "process_guid": _clean(data.get("ProcessGuid"))}
    elif event_id == 13:  # 注册表键值修改（Run键等持久化证据由D从这里捞）
        target = _clean(data.get("TargetObject"))
        details = _clean(data.get("Details"))
        description = f"注册表键值修改: {target} = {details}（进程: {image}）"
        detail = {"registry_key": target,
                  "registry_value_name": target.rsplit("\\", 1)[-1] if target else None,
                  "registry_value_data": details,
                  "registry_operation": _clean(data.get("EventType")),
                  "process_guid": _clean(data.get("ProcessGuid"))}
    elif event_id == 10:  # 进程访问内存：内存注入检测的原料（掩码/调用栈进detail供规则判读）
        source_image = _basename(_clean(data.get("SourceImage")))
        target_image = _basename(_clean(data.get("TargetImage")))
        granted = _clean(data.get("GrantedAccess"))
        call_trace = _clean(data.get("CallTrace"))
        description = (f"进程 {source_image or '未知'} 访问 {target_image or '未知'} 内存"
                       f"（GrantedAccess={granted or '未记录'}）")
        detail = {"source_image": source_image,
                  "source_process_guid": _clean(data.get("SourceProcessGUID")),
                  "source_process_id": _to_int(data.get("SourceProcessId")),
                  "target_image": target_image,
                  "target_process_guid": _clean(data.get("TargetProcessGUID")),
                  "target_process_id": _to_int(data.get("TargetProcessId")),
                  "granted_access": granted,
                  "call_trace": call_trace}
        return make_event(timestamp=ts, host=host, source="sysmon",
                         source_event_id=event_id, event_type=event_type,
                         user=user, process=source_image,
                         detail=detail, description=description,
                         raw_log=data.get("_raw_line"))
    elif event_id == 8:  # 跨进程远程线程创建：代码注入的直接动作（StartModule为"-"=无模块起始地址）
        source_image = _basename(_clean(data.get("SourceImage")))
        target_image = _basename(_clean(data.get("TargetImage")))
        start_module = _clean(data.get("StartModule"))
        description = (f"远程线程创建: {source_image or '未知'} → {target_image or '未知'}"
                       f"（起始地址 {_clean(data.get('StartAddress')) or '未记录'}"
                       f"{'，无归属模块' if start_module in (None, '-') else ''}）")
        detail = {"source_image": source_image,
                  "source_process_guid": _clean(data.get("SourceProcessGUID")),
                  "source_process_id": _to_int(data.get("SourceProcessId")),
                  "target_image": target_image,
                  "target_process_guid": _clean(data.get("TargetProcessGUID")),
                  "target_process_id": _to_int(data.get("TargetProcessId")),
                  "new_thread_id": _to_int(data.get("NewThreadId")),
                  "start_address": _clean(data.get("StartAddress")),
                  "start_module": start_module,
                  "start_function": _clean(data.get("StartFunction"))}
        return make_event(timestamp=ts, host=host, source="sysmon",
                         source_event_id=event_id, event_type=event_type,
                         user=user, process=source_image,
                         detail=detail, description=description,
                         raw_log=data.get("_raw_line"))
    elif event_id == 22:  # DNS查询：C2域名解析的主机侧证据
        qname = _clean(data.get("QueryName"))
        description = f"DNS查询: {qname}（进程: {image}）"
        detail = {"domain": _base_domain(qname),
                  "qname": qname,
                  "query_results": _clean(data.get("QueryResults")),
                  "query_status": _clean(data.get("QueryStatus")),
                  "process_guid": _clean(data.get("ProcessGuid"))}
    else:  # 23 文件删除
        target = _clean(data.get("TargetFilename"))
        description = f"删除文件: {target}（进程: {image}）"
        detail = {"file_path": target,
                  "hashes": _clean(data.get("Hashes")),
                  "is_executable": _clean(data.get("IsExecutable")),
                  "archived": _clean(data.get("Archived")),
                  "process_guid": _clean(data.get("ProcessGuid"))}

    return make_event(timestamp=ts, host=host, source="sysmon",
                     source_event_id=event_id, event_type=event_type, user=user,
                     process=image, cmdline=cmdline, detail=detail,
                     description=description, raw_log=data.get("_raw_line"))


def _security_event(event_id: int, data: dict, ts, host: str) -> dict | None:
    """Security 分支：分支逻辑/描述文案照抄 windows_evtx.py（.evtx版），
    只是 EventData 从 XML findtext 换成顶层 dict 取键。不支持的ID返回None。"""
    event_type = SECURITY_SUPPORTED.get(event_id)
    if event_type is None:
        return None

    user = _clean(data.get("TargetUserName"))
    src_ip = _clean(data.get("IpAddress"))
    logon_type = _to_int(data.get("LogonType"))
    logon_id = _clean(data.get("TargetLogonId"))
    subject = _clean(data.get("SubjectUserName"))
    lt_desc = LOGON_TYPES.get(logon_type, f"类型{logon_type}")

    if event_id == 4624:  # 登录成功
        session_id = f"{host}:{logon_id}" if logon_id else None
        src_port = _clean(data.get("IpPort"))
        description = f"用户 {user} 登录成功（{lt_desc}）"
        detail = {"logon_id": logon_id,
                  "domain": _clean(data.get("TargetDomainName")),
                  "src_port": _to_int(src_port) if src_port else None,
                  "workstation": _clean(data.get("WorkstationName")),
                  "auth_package": _clean(data.get("AuthenticationPackageName")),
                  "process_name": _basename(_clean(data.get("ProcessName")))}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=user,
                         process=_basename(_clean(data.get("ProcessName"))),
                         src_ip=src_ip, logon_type=logon_type,
                         session_id=session_id, detail=detail,
                         description=description, raw_log=data.get("_raw_line"))
    if event_id == 4625:  # 登录失败
        sub = _clean(data.get("SubStatus"))
        sub_desc = SUB_STATUS.get(_norm_substatus(sub), sub)
        description = f"用户 {user} 登录失败（{lt_desc}，原因: {sub_desc}）"
        detail = {"substatus": sub, "substatus_desc": sub_desc,
                  "failure_reason": _clean(data.get("FailureReason")),
                  "workstation": _clean(data.get("WorkstationName"))}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=user,
                         process=None, src_ip=src_ip, logon_type=logon_type,
                         session_id=None, detail=detail,
                         description=description, raw_log=data.get("_raw_line"))
    if event_id in (4634, 4647):  # 注销：配对键与4624一致
        session_id = f"{host}:{logon_id}" if logon_id else None
        if event_id == 4634:
            description = f"用户 {user} 注销（{lt_desc}）"
        else:
            description = f"用户 {user} 主动发起注销"
        detail = {"logon_id": logon_id,
                  "domain": _clean(data.get("TargetDomainName"))}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=user,
                         process=None, src_ip=src_ip, logon_type=logon_type,
                         session_id=session_id, detail=detail,
                         description=description, raw_log=data.get("_raw_line"))
    if event_id == 4688:  # 进程创建（4688的发起者是SubjectUserName）
        user = subject
        process = _basename(_clean(data.get("NewProcessName")))
        parent = _basename(_clean(data.get("ParentProcessName")) or _clean(data.get("ProcessName")))
        cmdline = _clean(data.get("CommandLine"))
        parent_desc = parent if parent else "无记录"
        description = f"进程创建: {process}（发起用户: {user}，父进程: {parent_desc}）"
        detail = {"parent_process": parent,
                  "creator_process_id": _to_int(data.get("ProcessId")),
                  "new_process_id": _to_int(data.get("NewProcessId")),
                  "token_elevation": _clean(data.get("TokenElevationType")),
                  "subject_domain": _clean(data.get("SubjectDomainName"))}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=user,
                         process=process, cmdline=cmdline, detail=detail,
                         description=description, raw_log=data.get("_raw_line"))
    if event_id == 1102:  # 审计日志被清除
        user = subject
        actor = f"操作者: {user}" if user else "操作者未记录"
        description = f"审计日志被清除（{actor}）——抹痕迹标志动作"
        detail = {"domain": _clean(data.get("SubjectDomainName"))}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=user,
                         detail=detail, description=description,
                         raw_log=data.get("_raw_line"))
    if event_id == 4720:  # 新建账号
        creator = f"（操作者: {subject}）" if subject else ""
        description = f"新建账号: {user}{creator}"
        detail = {"target_user": user,
                  "target_sid": _clean(data.get("TargetUserSid")),
                  "target_domain": _clean(data.get("TargetDomainName")),
                  "creator": subject}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=user,
                         detail=detail, description=description,
                         raw_log=data.get("_raw_line"))
    if event_id == 4728:  # 成员加入安全组（TargetUserName是组名）
        group = user
        member = _clean(data.get("MemberName")) or _clean(data.get("MemberSid"))
        creator = f"（操作者: {subject}）" if subject else ""
        description = f"用户 {member} 加入组 {group}{creator}"
        detail = {"target_user": member,
                  "group_name": group,
                  "member_sid": _clean(data.get("MemberSid")),
                  "group_domain": _clean(data.get("TargetDomainName"))}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=member,
                         detail=detail, description=description,
                         raw_log=data.get("_raw_line"))
    if event_id == 4673:  # 特权服务调用
        user = subject
        obj_server = _clean(data.get("ObjectServer"))
        proc = _basename(_clean(data.get("ProcessName")))
        proc_desc = proc if proc else "进程未记录"
        description = f"权限使用: {user} 调用 {obj_server or '系统'} 特权服务（进程: {proc_desc}）"
        detail = {"privileges": _clean(data.get("PrivilegeList")),
                  "object_server": obj_server,
                  "object_name": _clean(data.get("ObjectName")),
                  "service_name": _clean(data.get("ServiceName"))}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=user,
                         process=proc, detail=detail, description=description,
                         raw_log=data.get("_raw_line"))
    if event_id == 4697:  # 服务安装（Security通道版，等价于7045）
        service = _clean(data.get("ServiceName"))
        image = _clean(data.get("ImagePath") or data.get("FileName"))
        account = _clean(data.get("AccountName"))
        image_desc = image if image else "路径未记录"
        start_desc = _clean(data.get("StartType")) or "未记录"
        description = f"安装新服务: {service}（程序: {image_desc}，启动类型: {start_desc}）"
        detail = {"service_name": service,
                  "service_file": image,
                  "service_type": _clean(data.get("ServiceType")),
                  "start_type": start_desc,
                  "account": account,
                  "creator": subject}
        return make_event(timestamp=ts, host=host, source="windows_evtx",
                         source_event_id=event_id, event_type=event_type, user=account,
                         process=_basename(image), detail=detail,
                         description=description, raw_log=data.get("_raw_line"))
    # 4698 计划任务创建
    task = _clean(data.get("TaskName"))
    user = subject
    creator = f"（操作者: {user}）" if user else ""
    description = f"创建计划任务: {task}{creator}"
    detail = {"task_name": task,
              "task_content": _clean(data.get("TaskContent"))}
    return make_event(timestamp=ts, host=host, source="windows_evtx",
                     source_event_id=event_id, event_type=event_type, user=user,
                     detail=detail, description=description,
                     raw_log=data.get("_raw_line"))


def _line_to_event(line: str) -> dict | None:
    """单行JSON → 标准事件。不是目标事件返回 None（调用方计 skipped_other）。"""
    ev = json.loads(line)
    route = _route_channel(ev.get("Channel"))
    if route is None:
        return None
    try:
        event_id = int(ev.get("EventID"))
    except (TypeError, ValueError):
        return None

    supported = SYSMON_SUPPORTED if route == "sysmon" else SECURITY_SUPPORTED
    if event_id not in supported:
        return None

    ts = _event_ts(ev)
    host = _clean(ev.get("Hostname")) or _clean(ev.get("host"))
    if ts is None or host is None:
        raise ValueError(f"缺时间戳或主机名: EventID={event_id} Channel={ev.get('Channel')}")

    # _raw_line 供各分支当 raw_log 用（截断对齐 windows_evtx 的 [:2000]）
    ev["_raw_line"] = line[:2000]
    data = ev
    if route == "sysmon":
        return _sysmon_event(event_id, data, ts, host)
    return _security_event(event_id, data, ts, host)


def parse_sysmon_json(file_path: str, stats: dict = None) -> list:
    """解析 JSON 行格式的 Windows 主机日志（APT29 day1 manual 数据集）。

    流式逐行读——文件几百MB也不能整体载入内存；内存里只留映射后的标准事件。
    stats 口径与 parse_windows_evtx/parse_sysmon_evtx 一致：
        {"parsed", "skipped_other", "failed", "by_event_id"}（跳过的也按ID计数）
    try-except 按"条"包：一行坏JSON只丢这一条，绝不中断整个文件。
    """
    events = []
    if stats is None:
        stats = {}
    stats.update(parsed=0, skipped_other=0, failed=0, by_event_id={})

    with open(file_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = _line_to_event(line)
                if ev is None:
                    stats["skipped_other"] += 1
                    # 记录跳过事件的 Channel:ID 分布（写报告有用）
                    try:
                        raw = json.loads(line)
                        key = f"other:{(raw.get('Channel') or '?').split('/')[-1]}:{raw.get('EventID')}"
                        stats["by_event_id"][key] = stats["by_event_id"].get(key, 0) + 1
                    except Exception:
                        pass
                    continue
                events.append(ev)
                stats["parsed"] += 1
                key = str(ev["source_event_id"])
                stats["by_event_id"][key] = stats["by_event_id"].get(key, 0) + 1
            except Exception as e:
                stats["failed"] += 1
                print(f"  [跳过损坏记录] {e}")
    return events


if __name__ == "__main__":
    # 单独调试本文件用：python sysmon_json.py <apt29_manual.json> [--limit N]
    import sys, argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--limit", type=int, default=None, help="只解析前N行（冒烟测试）")
    args = ap.parse_args()
    if args.limit:
        import itertools
        with open(args.file, encoding="utf-8") as fh:
            head = list(itertools.islice((l for l in fh if l.strip()), args.limit))
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        tmp.writelines(head)
        tmp.close()
        st = {}
        result = parse_sysmon_json(tmp.name, st)
        os.unlink(tmp.name)
    else:
        st = {}
        result = parse_sysmon_json(args.file, st)
    print(f"解析出 {len(result)} 条标准事件, 统计: parsed={st['parsed']} "
          f"skipped={st['skipped_other']} failed={st['failed']}")
    print("事件ID分布:", {k: v for k, v in sorted(st['by_event_id'].items())
                          if not k.startswith("other:")})
    if result:
        import json as _json
        print(_json.dumps(result[0], ensure_ascii=False, indent=2))
