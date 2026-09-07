# 解决 pull 冲突（3 个文件）+ 合并 README

## 冲突原因
本地（成员C：网络流量模块）与远端（成员A：FastAPI 后端 + 成员B：主机日志解析）分叉，`.gitignore`/`requirements.txt` 两边都改了，根 `Readme.md` 两边各写了一版。

## 解决方案：三个文件全部做并集合并

### 1. `.gitignore` —— 合并两边所有条目（去重）
```
E/
__pycache__/
*.pyc
.pytest_cache/
out/
tmp/
.zcode/
.venv/
venv/
.env
*.db
*.sqlite
*.sqlite3
data/output/
Thumbs.db
.DS_Store
```
（本地贡献：.pytest_cache/out/tmp；远端贡献：.venv/venv/.env/*.db/data/output/.zcode/Thumbs.db/.DS_Store）

### 2. `requirements.txt` —— 后端依赖(A) + 网络模块依赖(C) 合并
保留 A 的完整 pin 版本列表（fastapi/uvicorn/pydantic 等 13 项），追加网络模块的 scapy 和 pytest（带注释分区）。B 的依赖在 `b_host_parser/requirements.txt` 里独立存在，不受影响。

### 3. `Readme.md` —— 按你之前的要求"合并总结"
写成一版**项目级总览 README**（取代两边的冲突版本）：
- 项目标题（题3）+ 一段系统定位
- 架构图（后端A / 主机解析B / 网络解析C / 关联D / 靶场E / 前端F + 数据流）
- 目录结构说明
- 快速开始：后端启动（uvicorn、/docs、/health）+ 网络解析 CLI + 主机解析入口
- Event V2 契约摘要（19 字段、severity 0-3、UTC+8、null 语义、source 枚举）——A 的旧版还写着 Event V1，合并版统一为已冻结的 V2
- 详细文档链接：`backend/parsers/network/README.md`、`b_host_parser/README.md`、`docs/`

网络模块的详细 README 仍保留在 `backend/parsers/network/README.md`，根 README 只做总览+引用，不丢任何细节。

## 收尾步骤
1. `git add .gitignore requirements.txt Readme.md` 标记冲突已解决
2. `git commit` 完成合并提交（信息：合并远程分支，统一依赖与 README）
3. 验证：`git status` 干净、`python -m pytest tests -q` 全绿、`python -m backend.parsers.network ...` 契约自检通过
4. `git push` 同步回远端（如你想先自己检查再推，最后这步可以跳过）