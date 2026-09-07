# Information Security Design Project

网络空间安全课程设计：

**基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现**

## 当前后端状态

目前已完成第一版后端数据主干：

- FastAPI 基础服务
- `/health` 健康检查
- Event Pydantic 数据校验
- SQLite Event 存储
- 单条 Event 写入
- 批量 Event 写入
- Event 查询

当前仍处于开发阶段。

## Python 环境

推荐使用 Python 3.12。

在项目根目录创建虚拟环境：

```powershell
python -m venv .venv
```

安装依赖：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

启动后端：

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

Swagger：

```text
http://127.0.0.1:8000/docs
```

健康检查：

```text
http://127.0.0.1:8000/health
```

## 当前 Event V1

网络事件当前统一格式示例：

```json
{
  "timestamp": "2026-09-08T13:05:02+08:00",
  "host": "web-server",
  "event_type": "network_connection",
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "dst_port": 4444,
  "protocol": "TCP",
  "description": "Suspicious outbound to C2"
}
```

Event Schema 后续仍可能根据主机日志与攻击关联模块需要调整。
