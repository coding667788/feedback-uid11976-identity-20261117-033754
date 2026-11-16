"""HTTP 接口层：纯标准库 ThreadingHTTPServer。

路由（全部 POST，除版本查询外）：
  POST /login              登录换取不透明会话令牌
  POST /delegate           当前持有人签发子授权
  POST /check              使用授权（只读校验，默认拒绝）
  POST /revoke             撤销节点（持有人/签发者）
  POST /resource/incr      受保护写入：资源版本递增
  GET  /resource/version   读取资源当前版本（无需授权，便于测试断言最终状态）
  GET  /healthz            存活探针
  GET  /cache/info         签名缓存统计（证明只缓存不可变验签结果）

所有拒绝统一返回 {"allowed": false, "error": {"code", "message"}}，
绝不因异常崩溃而 fail-open。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .errors import (
    ERR_MALFORMED,
    ERR_UNAUTHENTICATED,
    ServiceError,
)
from .service import DelegationService, now_epoch

_MAX_BODY = 1 << 20  # 1 MiB


class _Handler(BaseHTTPRequestHandler):
    server_version = "DelegService/1.0"

    # 由 server 对象注入
    @property
    def svc(self) -> DelegationService:
        return self.server.svc  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):  # 安静日志；错误审计在 service 层
        return

    # ------------------------------------------------------------------ #
    def _send_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _deny(self, exc: ServiceError) -> None:
        self._send_json(exc.http_status, {
            "allowed": False,
            "error": {"code": exc.code, "message": exc.message},
        })

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > _MAX_BODY:
            raise ServiceError(ERR_MALFORMED, "请求体缺失或过大", 400)
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ServiceError(ERR_MALFORMED, f"请求体不是合法 JSON: {exc}", 400)
        if not isinstance(data, dict):
            raise ServiceError(ERR_MALFORMED, "请求体必须是 JSON 对象", 400)
        return data

    def _token(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return header[len("Bearer "):].strip() or None

    # ------------------------------------------------------------------ #
    def do_GET(self) -> None:  # noqa: N802
        try:
            if self.path == "/healthz":
                self._send_json(200, {"ok": True})
            elif self.path == "/cache/info":
                self._send_json(200, self.svc.verifier.cache_info())
            elif self.path.startswith("/resource/version?"):
                params = self._query_params()
                rid = params.get("resource_id")
                if not rid:
                    raise ServiceError(ERR_MALFORMED,
                                       "缺少 resource_id 参数", 400)
                self._send_json(200, self.svc.get_version(rid))
            else:
                self._send_json(404, {"allowed": False,
                                      "error": {"code": "ERR_NOT_FOUND",
                                                "message": "未知路由"}})
        except ServiceError as exc:
            self._deny(exc)
        except Exception as exc:  # 兜底默认拒绝，不暴露堆栈
            self._send_json(500, {"allowed": False,
                                  "error": {"code": "ERR_INTERNAL",
                                            "message": str(exc)}})

    def do_POST(self) -> None:  # noqa: N802
        try:
            data = self._read_body()
            now = now_epoch()
            if self.path == "/login":
                token = self.svc.login(
                    str(data["tenant_id"]), str(data["principal_id"]), now
                )
                self._send_json(200, {"token": token, "token_type": "Bearer"})
                return
            if self.path == "/delegate":
                result = self.svc.delegate(
                    self._token(),
                    data["parent_ticket"],
                    data["holder"],
                    data["resources"],
                    data["actions"],
                    data["nbf"],
                    data["exp"],
                    now,
                )
                self._send_json(200, result)
                return
            if self.path == "/check":
                result = self.svc.check(
                    self._token(),
                    data["ticket"],
                    data["resource_id"],
                    data["action"],
                    now,
                )
                self._send_json(200, result)
                return
            if self.path == "/revoke":
                result = self.svc.revoke(
                    self._token(), str(data["auth_id"]), now, admin=False
                )
                self._send_json(200, result)
                return
            if self.path == "/resource/incr":
                result = self.svc.increment_version(
                    self._token(),
                    data["ticket"],
                    data["resource_id"],
                    now,
                )
                self._send_json(200, result)
                return
            self._send_json(404, {"allowed": False,
                                  "error": {"code": "ERR_NOT_FOUND",
                                            "message": "未知路由"}})
        except ServiceError as exc:
            self._deny(exc)
        except KeyError as exc:
            self._deny(ServiceError(ERR_MALFORMED,
                                    f"缺少请求字段: {exc.args[0]}", 400))
        except Exception as exc:
            self._send_json(500, {"allowed": False,
                                  "error": {"code": "ERR_INTERNAL",
                                            "message": str(exc)}})

    def _query_params(self) -> dict[str, str]:
        from urllib.parse import parse_qs
        query = self.path.split("?", 1)[1]
        parsed = parse_qs(query, strict_parsing=False)
        return {k: v[0] for k, v in parsed.items() if v}


def build_server(host: str, port: int, db_dir: str | Path,
                 key: bytes | None = None) -> ThreadingHTTPServer:
    svc = DelegationService(db_dir, key)
    server = ThreadingHTTPServer((host, port), _Handler)
    server.svc = svc  # type: ignore[attr-defined]
    server.daemon_threads = True
    return server


def serve_forever(host: str, port: int, db_dir: str | Path) -> None:
    httpd = build_server(host, port, db_dir)
    print(f"[deleg-service] 监听 http://{host}:{port}  数据库目录: {db_dir}",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
