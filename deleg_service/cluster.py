"""启动 N 个共享同一 SQLite 数据库的独立 HTTP 服务进程。

用法：
  python -m deleg_service.cluster --db-dir ./data --ports 8081 8082 8083 8084
可选 --barrier-dir 为子进程注入测试同步点目录。
按 Ctrl+C 终止全部子进程。
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import barriers  # noqa: F401  (保证包可导入)
from . import db as dbmod
from .service import now_epoch


def _spawn(port: int, db_dir: Path, host: str,
           barrier_dir: Path | None) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    if barrier_dir is not None:
        env["DELEG_BARRIER_DIR"] = str(barrier_dir)
    # 注意：不能用 -I —— 隔离模式会从 sys.path 移除 cwd，导致 -m 找不到本包。
    # 这里运行的是本仓库自带代码（非下载的不可信数据），cwd 已固定为项目根。
    cmd = [sys.executable, "-m", "deleg_service.serve_worker",
           "--db-dir", str(db_dir), "--host", host, "--port", str(port)]
    creationflags = 0
    if os.name == "nt":
        # 独立进程组，便于整组终止
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    return subprocess.Popen(
        cmd, env=env, cwd=str(Path(__file__).resolve().parent.parent),
        creationflags=creationflags,
    )


def main() -> int:
    p = argparse.ArgumentParser(description="多进程委托授权服务集群")
    p.add_argument("--db-dir", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--ports", nargs="+", type=int,
                   default=[8081, 8082, 8083, 8084])
    p.add_argument("--barrier-dir", default=None)
    args = p.parse_args()

    db_dir = Path(args.db_dir).resolve()
    barrier_dir = Path(args.barrier_dir).resolve() if args.barrier_dir else None
    if barrier_dir is not None:
        barrier_dir.mkdir(parents=True, exist_ok=True)

    # 幂等初始化：确保数据库结构与服务端密钥在任何工作进程启动前就绪，
    # 否则各进程会因找不到 server.key 而崩溃
    dbmod.initialize(db_dir, now_epoch())

    procs = []
    for port in args.ports:
        proc = _spawn(port, db_dir, args.host, barrier_dir)
        procs.append(proc)
        print(f"[cluster] 已启动端口 {port} pid={proc.pid}", flush=True)
        time.sleep(0.15)

    try:
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for proc in procs:
            if proc.poll() is None:
                if os.name == "nt":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                else:
                    proc.terminate()
        time.sleep(1.0)
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
        print("[cluster] 全部子进程已终止", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
