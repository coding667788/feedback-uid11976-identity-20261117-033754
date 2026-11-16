"""HTTP 功能测试：经真实 HTTP 栈验证请求/响应、状态码与默认拒绝。"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from urllib.parse import quote

from deleg_service.httpapi import build_server
from deleg_service.service import now_epoch
from tests.helpers import BaseServiceTest


def _wide_window():
    """以真实墙钟为中心的宽窗口，适配 HTTP 层的服务器当前时间。"""
    now = now_epoch()
    return now - 10_000, now + 10_000


class HttpServerThread:
    def __init__(self, db_dir):
        self.httpd = build_server("127.0.0.1", 0, db_dir)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def http_call(port: int, path: str, body: dict | None = None,
              token: str | None = None, method: str | None = None):
    """返回 (status, json_body)。4xx/5xx 不抛异常，交给断言处理。"""
    url = f"http://127.0.0.1:{port}{path}"
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        method = method or "POST"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url, data=data, headers=headers, method=method or "GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class HttpEndToEndTest(BaseServiceTest):
    def test_full_flow_over_http(self):
        with HttpServerThread(self.h.db_dir) as srv:
            port = srv.port
            # 登录
            status, body = http_call(port, "/login", {
                "tenant_id": "t-acme", "principal_id": "alice"
            })
            self.assertEqual(status, 200)
            token_alice = body["token"]

            # 根授权走 CLI/服务层，HTTP 只暴露 delegate
            nbf, exp = _wide_window()
            root = self.h.root_grant(
                holder="alice", resources=["res-0", "res-1"],
                actions=["read", "write"], nbf=nbf, exp=exp,
            )
            nbf, exp = _wide_window()
            # 委托给 bob（read）
            status, body = http_call(port, "/delegate", {
                "parent_ticket": self.h.tickets[root["auth_id"]],
                "holder": "bob",
                "resources": ["res-0"],
                "actions": ["read"],
                "nbf": nbf, "exp": exp,
            }, token=token_alice)
            self.assertEqual(status, 200, body)
            child = body
            child_ticket = child["ticket"]

            # bob 登录并 check
            _, body = http_call(port, "/login", {
                "tenant_id": "t-acme", "principal_id": "bob"
            })
            token_bob = body["token"]
            status, body = http_call(port, "/check", {
                "ticket": child_ticket, "resource_id": "res-0",
                "action": "read",
            }, token=token_bob)
            self.assertEqual(status, 200)
            self.assertTrue(body["allowed"])

            # bob 尝试 write -> 默认拒绝 403
            status, body = http_call(port, "/check", {
                "ticket": child_ticket, "resource_id": "res-0",
                "action": "write",
            }, token=token_bob)
            self.assertEqual(status, 403)
            self.assertFalse(body["allowed"])

            # 无令牌 -> 401
            status, body = http_call(port, "/check", {
                "ticket": child_ticket, "resource_id": "res-0",
                "action": "read",
            })
            self.assertEqual(status, 401)

            # 版本查询初始为 0；bob 无 write，incr 被拒
            status, body = http_call(
                port,
                f"/resource/version?resource_id={quote('res-0')}"
            )
            self.assertEqual(body["version"], 0)
            status, body = http_call(port, "/resource/incr", {
                "ticket": child_ticket, "resource_id": "res-0",
            }, token=token_bob)
            self.assertEqual(status, 403)

            # alice 直接用根授权 incr 成功，版本变 1
            status, body = http_call(port, "/resource/incr", {
                "ticket": self.h.tickets[root["auth_id"]],
                "resource_id": "res-0",
            }, token=token_alice)
            self.assertEqual(status, 200, body)
            self.assertEqual(body["version"], 1)

            # 持有人 alice 撤销 child；bob 随后的 check 立即被拒
            status, _ = http_call(port, "/revoke", {
                "auth_id": child["auth_id"],
            }, token=token_alice)
            self.assertEqual(status, 200)
            status, body = http_call(port, "/check", {
                "ticket": child_ticket, "resource_id": "res-0",
                "action": "read",
            }, token=token_bob)
            self.assertEqual(status, 403)
            self.assertEqual(body["error"]["code"], "ERR_REVOKED")

            # 健康检查与缓存统计
            status, body = http_call(port, "/healthz")
            self.assertEqual(status, 200)
            status, body = http_call(port, "/cache/info")
            self.assertEqual(status, 200)
            self.assertIn("lru_hits", body)

    def test_malformed_bodies_denied(self):
        with HttpServerThread(self.h.db_dir) as srv:
            # 非法 JSON
            req = urllib.request.Request(
                f"http://127.0.0.1:{srv.port}/login",
                data=b"{not-json", headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=10)
                self.fail("应当拒绝非法 JSON")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 400)
