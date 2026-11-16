"""SQLite 存储层：连接配置、建表初始化、仅服务端持有的签名密钥。

- WAL 模式：多个独立服务进程共享同一个数据库文件，读不阻塞写、写串行；
- 所有写事务在 service 层以 BEGIN IMMEDIATE 开启，保证提交顺序即全局顺序；
- 密钥文件与数据库同目录，权限收紧为仅当前用户可读写，从不通过网络暴露。
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from pathlib import Path

SCHEMA_VERSION = "1"
KEY_FILE_NAME = "server.key"
DB_FILE_NAME = "deleg.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id),
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    active       INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    PRIMARY KEY (tenant_id, principal_id)
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_grants (
    auth_id       TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id),
    parent_id     TEXT,                       -- 根授权为 NULL
    parent_digest TEXT,                       -- 根授权为 NULL
    depth         INTEGER NOT NULL CHECK (depth BETWEEN 1 AND 8),
    holder        TEXT NOT NULL,
    issuer        TEXT NOT NULL,              -- 根授权为 '__admin__'
    resources     TEXT NOT NULL,              -- 规范 JSON 数组
    actions       TEXT NOT NULL,              -- 规范 JSON 数组
    nbf           INTEGER NOT NULL,
    exp           INTEGER NOT NULL,
    content_digest TEXT NOT NULL,
    ticket        TEXT NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    revoked_at    INTEGER,
    revoked_by    TEXT,
    created_at    INTEGER NOT NULL,
    UNIQUE (tenant_id, auth_id)
);

CREATE INDEX IF NOT EXISTS idx_grants_parent ON auth_grants(parent_id);
CREATE INDEX IF NOT EXISTS idx_grants_holder ON auth_grants(tenant_id, holder);
CREATE INDEX IF NOT EXISTS idx_grants_revoked ON auth_grants(revoked);

CREATE TABLE IF NOT EXISTS resource_versions (
    resource_id TEXT PRIMARY KEY REFERENCES resources(resource_id),
    version     INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    auth_id    TEXT,
    detail     TEXT NOT NULL
);
"""


class KeyNotFound(RuntimeError):
    pass


def db_path_for(db_dir: str | os.PathLike) -> Path:
    return Path(db_dir) / DB_FILE_NAME


def key_path_for(db_dir: str | os.PathLike) -> Path:
    return Path(db_dir) / KEY_FILE_NAME


def load_or_create_key(db_dir: str | os.PathLike) -> bytes:
    """读取服务端 HMAC 密钥；不存在则生成 32 字节随机密钥并落盘。"""
    db_dir = Path(db_dir)
    db_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_path_for(db_dir)
    if key_path.exists():
        return bytes.fromhex(key_path.read_text(encoding="ascii").strip())
    key = secrets.token_bytes(32)
    key_path.write_text(key.hex(), encoding="ascii")
    _restrict_to_owner(key_path)
    return key


def load_key(db_dir: str | os.PathLike) -> bytes:
    key_path = key_path_for(db_dir)
    if not key_path.exists():
        raise KeyNotFound(f"密钥文件不存在: {key_path}")
    return bytes.fromhex(key_path.read_text(encoding="ascii").strip())


def _restrict_to_owner(path: Path) -> None:
    """Windows: 仅授予当前用户完全控制；POSIX: 0600。

    标准库不含 Windows ACL 封装，这里通过 icacls 实现；若环境不允许
    修改 ACL（例如受控沙箱），保留文件默认权限并告警，绝不把文件锁死。
    """
    if os.name == "nt":
        import getpass
        import subprocess

        domain = os.environ.get("USERDOMAIN", "")
        user = f"{domain}\\{getpass.getuser()}" if domain else getpass.getuser()
        proc = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True, check=False,
        )
        if proc.returncode != 0:
            # icacls 在中文 Windows 上输出 GBK；用替换模式解码避免崩溃
            msg = (proc.stderr or proc.stdout or b"").decode("gbk", "replace").strip()
            print(f"[warn] 密钥文件 ACL 收紧失败，保留默认权限: {msg}",
                  flush=True)
    else:
        os.chmod(path, 0o600)


def connect(db_dir: str | os.PathLike) -> sqlite3.Connection:
    """打开一个新连接。每请求/每命令使用独立连接（线程内不共享）。"""
    path = db_path_for(db_dir)
    conn = sqlite3.connect(
        str(path),
        timeout=15.0,
        isolation_level=None,  # 显式事务，关闭驱动自动 begin
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def initialize(db_dir: str | os.PathLike, now: int) -> Path:
    """创建数据库结构与密钥（幂等），返回数据库文件路径。"""
    db_dir = Path(db_dir)
    db_dir.mkdir(parents=True, exist_ok=True)
    load_or_create_key(db_dir)
    conn = connect(db_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.executescript(_SCHEMA)
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('created_at', ?)",
            (str(now),),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return db_path_for(db_dir)
