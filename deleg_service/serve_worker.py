"""服务工作进程入口（被 cluster.py 以 `python -I -m` 方式拉起）。

独立成模块是为了在 -I（隔离模式，忽略 PYTHONPATH）下仍可通过
-c 工作目录 + 包名正常导入。
"""

from __future__ import annotations

import argparse

from .httpapi import serve_forever


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--db-dir", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    args = p.parse_args()
    serve_forever(args.host, args.port, args.db_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
