// ============================================================
// Electron 主进程 —— 桌面版启动器（成员C/F）
// 职责：拉起 Python 后端(uvicorn 8000) -> 等健康检查 -> 打开桌面窗口
// 退出：窗口关闭/Ctrl+Q 时连同后端一起退出
// ============================================================
const { app, BrowserWindow, dialog } = require("electron");
const { spawn, execSync } = require("child_process");
const http = require("http");
const path = require("path");
const fs = require("fs");

const PORT = 8000;
const BASE = `http://127.0.0.1:${PORT}`;
const ROOT = path.join(__dirname, "..");
const NETSTAT = path.join(process.env.SystemRoot || "C:\Windows", "System32", "netstat.exe");
const TASKKILL = path.join(process.env.SystemRoot || "C:\Windows", "System32", "taskkill.exe");

let backendProc = null;
let quitting = false;
let mainWindow = null;

// ---------- 端口清理（孤儿后端残留） ----------
function freePort(port) {
  try {
    const out = execSync(`"${NETSTAT}" -ano`, { encoding: "utf8" });
    const pids = new Set(
      out.split("\n")
         .filter(l => l.includes(`:${port}`) && l.toUpperCase().includes("LISTENING"))
         .map(l => l.trim().split(/\s+/).pop())
    );
    for (const pid of pids) {
      try { execSync(`"${TASKKILL}" /F /PID ${pid}`); } catch (e) { /* 已退出 */ }
    }
    if (pids.size) console.log(`[清理] 端口 ${port} 残留进程 ${pids.size} 个`);
  } catch (e) { console.log("[清理] 跳过:", e.message); }
}

// ---------- 选择 Python 解释器（优先 .venv） ----------
function pythonCmd() {
  const venv = path.join(ROOT, ".venv", "Scripts", "python.exe");
  return fs.existsSync(venv) ? venv : "python";
}

// ---------- 拉起后端 ----------
function startBackend() {
  freePort(PORT);
  const cmd = pythonCmd();
  console.log(`[后端] 启动 ${cmd} -m uvicorn backend.main:app --port ${PORT}`);
  backendProc = spawn(cmd, ["-m", "uvicorn", "backend.main:app", "--port", String(PORT)], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  /* 日志转发：管道断开（后端退出瞬间）时的写入必须吞掉，
   * 否则 EPIPE 会作为主进程未捕获异常弹错误框 */
  const safePipe = (stream) => {
    stream.on("error", () => {});                                   // 管道级错误兜底
    stream.on("data", d => { try { process.stdout.write("[uvicorn] " + d); } catch (e) { /* 断管静默 */ } });
  };
  safePipe(backendProc.stdout);
  safePipe(backendProc.stderr);
  backendProc.on("exit", (code) => {
    console.log(`[后端] 退出 (code=${code})`);
    if (!quitting && mainWindow && !mainWindow.isDestroyed()) {
      dialog.showErrorBox("后端服务已退出", `Python 后端进程意外退出（code=${code}）。\n请确认已安装 requirements.txt 依赖后重新启动。`);
      app.quit();
    }
  });
}

/* 主进程未捕获异常兜底：EPIPE 等管道噪声不再弹窗中断应用 */
process.on("uncaughtException", (err) => {
  console.log("[主进程异常已兜底]", err && err.message ? err.message : err);
});

// ---------- 健康检查轮询 ----------
function waitHealth(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const poll = () => {
      const req = http.get(`${BASE}/health`, { timeout: 2000 }, res => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      req.on("error", () => {
        if (Date.now() < deadline) setTimeout(poll, 500);
        else resolve(false);
      });
      req.setTimeout(2000, () => req.destroy(new Error("timeout")));
    };
    poll();
  });
}

// ---------- 主窗口 ----------
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    title: "恶意攻击行为溯源分析系统",
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true },
  });
  mainWindow.loadURL(BASE);
  mainWindow.on("closed", () => { mainWindow = null; });
}

app.whenReady().then(async () => {
  startBackend();
  const ok = await waitHealth();
  if (!ok) {
    dialog.showErrorBox("后端启动失败", `健康检查超时（${BASE}/health）。\n请确认已执行: python -m pip install -r requirements.txt`);
    app.quit();
    return;
  }
  console.log("[就绪] 平台已启动: " + BASE);
  createWindow();
});

app.on("window-all-closed", () => {
  quitting = true;
  if (backendProc) { try { backendProc.kill(); } catch (e) {} }
  app.quit();
});

app.on("before-quit", () => {
  quitting = true;
  if (backendProc) { try { backendProc.kill(); } catch (e) {} }
});

process.on("exit", () => { if (backendProc) { try { backendProc.kill(); } catch (e) {} } });
