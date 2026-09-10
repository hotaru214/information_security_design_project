# -*- coding: utf-8 -*-
"""
任务4：把解析结果送进系统（与A联调的对接层）
==============================================
两条路：
  1. save_jsonl()      —— 落地成本地 .jsonl 文件（A的接口没就绪之前先走这条，
                          也是跑测试、写《测试分析报告》的数据底稿）
  2. post_to_backend() —— 批量POST给A的后端接口（联调时用）

关于A的接口约定（任务1会议上让A按这个实现）：
  POST /api/events/import
  请求体 = 标准事件数组（一次发一批，别一条一发，几百条时快得多）
  期望响应 = {"imported": 成功条数, "failed": 失败条数}
"""
import json

import requests


def save_jsonl(events: list, out_path: str) -> str:
    """把标准事件列表写成 .jsonl 文件（每行一个JSON对象）。

    为什么用 jsonl 不用 json 数组：可以一行一行写、一行一行读，文件大了不怕内存爆。
    返回输出文件的绝对路径。
    """
    with open(out_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return out_path


def post_to_backend(events: list, api_url: str, batch_size: int = 500,
                    timeout: int = 10) -> int:
    """批量POST给A的后端。返回成功发送的事件条数。

    会抛出 requests.RequestException——让调用方决定怎么提示
    （通常是"A的后端没启动"，这时先用 --out 落jsonl就行，不阻塞开发）。
    """
    imported = 0
    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
        resp = requests.post(api_url, json=batch, timeout=timeout)
        resp.raise_for_status()  # 非2xx直接抛异常
        imported += len(batch)
        print(f"  已发送 {imported}/{len(events)} 条 → {api_url}")
    return imported
