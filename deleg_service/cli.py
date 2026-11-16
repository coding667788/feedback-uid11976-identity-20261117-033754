"""初始化与管理命令（本地管理员，不经 HTTP）。

用法示例：
  python -m deleg_service.cli init --db-dir ./data
  python -m deleg_service.cli tenant --db-dir ./data --id t1 --name 租户甲
  python -m deleg_service.cli principal --db-dir ./data --id alice --name 爱丽丝
  python -m deleg_service.cli membership --db-dir ./data --tenant t1 --principal alice
  python -m deleg_service.cli resource --db-dir ./data --id doc-1 --name 文档1
  python -m deleg_service.cli root-grant --db-dir ./data --tenant t1 --holder alice \
      --resources doc-1 doc-2 --actions read write --nbf 2026-01-01 --exp 2030-01-01
  python -m deleg_service.cli login --db-dir ./data --tenant t1 --principal alice
  python -m deleg_service.cli revoke --db-dir ./data --auth-id g_xxx
  python -m deleg_service.cli grant --db-dir ./data --auth-id g_xxx
  python -m deleg_service.cli serve --db-dir ./data --port 8081
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .errors import ServiceError
from .httpapi import serve_forever
from .service import DelegationService, now_epoch
from . import db as dbmod


def _parse_time(value: str) -> int:
    """接受 epoch 秒整数或 ISO-8601（如 2030-01-01 / 2030-01-01T08:00:00Z）。"""
    value = value.strip()
    if value.lstrip("-").isdigit():
        return int(value)
    text = value.replace("Z", "+00:00")
    if text.endswith("+00:00"):
        dt = datetime.fromisoformat(text)
    else:
        # 不带时区的输入按 UTC 处理，避免本机时区歧义
        dt = datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
    return int(dt.astimezone(timezone.utc).timestamp())


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deleg_service",
        description="本地可衰减委托授权链服务（Python 3.12 标准库 + SQLite）",
    )
    p.add_argument("--db-dir", default="./data", help="数据库与密钥目录")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="初始化数据库与服务端密钥")

    s = sub.add_parser("tenant", help="创建租户")
    s.add_argument("--id", dest="tenant_id", required=True)
    s.add_argument("--name", required=True)

    s = sub.add_parser("principal", help="创建主体")
    s.add_argument("--id", dest="principal_id", required=True)
    s.add_argument("--name", required=True)

    s = sub.add_parser("membership", help="把主体加入租户（有效成员）")
    s.add_argument("--tenant", dest="tenant_id", required=True)
    s.add_argument("--principal", dest="principal_id", required=True)

    s = sub.add_parser("resource", help="预置资源（有限集合，带版本计数器）")
    s.add_argument("--id", dest="resource_id", required=True)
    s.add_argument("--name", required=True)

    s = sub.add_parser("root-grant", help="管理员创建根授权")
    s.add_argument("--tenant", dest="tenant_id", required=True)
    s.add_argument("--holder", required=True)
    s.add_argument("--resources", nargs="+", required=True)
    s.add_argument("--actions", nargs="+", required=True,
                   choices=["read", "write"])
    s.add_argument("--nbf", required=True, help="生效时间：epoch 秒或 ISO-8601")
    s.add_argument("--exp", required=True, help="过期时间：epoch 秒或 ISO-8601")

    s = sub.add_parser("login", help="登录并打印会话令牌")
    s.add_argument("--tenant", dest="tenant_id", required=True)
    s.add_argument("--principal", dest="principal_id", required=True)

    s = sub.add_parser("revoke", help="管理员撤销授权（整棵子树即刻失效）")
    s.add_argument("--auth-id", required=True)

    s = sub.add_parser("grant", help="查看授权节点状态与链路径")
    s.add_argument("--auth-id", required=True)

    s = sub.add_parser("version", help="查看资源当前版本")
    s.add_argument("--resource-id", required=True)

    s = sub.add_parser("serve", help="启动 HTTP 服务进程")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    db_dir = Path(args.db_dir)
    now = now_epoch()

    try:
        if args.cmd == "init":
            path = dbmod.initialize(db_dir, now)
            _print({"ok": True, "database": str(path),
                    "key_file": str(dbmod.key_path_for(db_dir))})
            return 0

        # 以下命令要求已初始化
        svc = DelegationService(db_dir)

        if args.cmd == "tenant":
            svc.create_tenant(args.tenant_id, args.name, now)
            _print({"ok": True, "tenant_id": args.tenant_id})
        elif args.cmd == "principal":
            svc.create_principal(args.principal_id, args.name, now)
            _print({"ok": True, "principal_id": args.principal_id})
        elif args.cmd == "membership":
            svc.add_membership(args.tenant_id, args.principal_id)
            _print({"ok": True, "tenant_id": args.tenant_id,
                    "principal_id": args.principal_id})
        elif args.cmd == "resource":
            svc.create_resource(args.resource_id, args.name, now)
            _print({"ok": True, "resource_id": args.resource_id})
        elif args.cmd == "root-grant":
            result = svc.create_root_grant(
                args.tenant_id, args.holder,
                list(dict.fromkeys(args.resources)),  # CLI 层也拒绝重复
                list(dict.fromkeys(args.actions)),
                _parse_time(args.nbf), _parse_time(args.exp), now,
            )
            _print(result)
        elif args.cmd == "login":
            token = svc.login(args.tenant_id, args.principal_id, now)
            _print({"token": token, "token_type": "Bearer",
                    "tenant_id": args.tenant_id,
                    "principal_id": args.principal_id})
        elif args.cmd == "revoke":
            _print(svc.revoke(None, args.auth_id, now, admin=True))
        elif args.cmd == "grant":
            _print(svc.get_grant(args.auth_id))
        elif args.cmd == "version":
            _print(svc.get_version(args.resource_id))
        elif args.cmd == "serve":
            serve_forever(args.host, args.port, db_dir)
        else:  # pragma: no cover
            print(f"未知命令: {args.cmd}", file=sys.stderr)
            return 2
        return 0
    except ServiceError as exc:
        print(json.dumps({"allowed": False,
                          "error": {"code": exc.code, "message": exc.message}},
                         ensure_ascii=False),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
