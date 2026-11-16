"""多进程竞争测试：4 个独立 HTTP 服务进程共享同一 SQLite 数据库。

可控同步点（deleg_service.barriers，文件屏障）让我们精确制造两种顺序：
  A. 祖先检查完成后、写事务开启前，另一进程提交撤销；
  B. 同一节点上“撤销”与“再委托”并发，两种提交顺序都必须保证不变量。

不变量（无论谁先提交）：
  1. 撤销一旦返回，其后新开始的 check 一律拒绝；
  2. 被撤销节点下不可能出现“撤销后仍有效”的新分支；
  3. 受保护写入与撤销竞争时，资源版本只能由真正通过全链校验的写入递增。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from deleg_service import barriers, db as dbmod
from deleg_service.cli import main as cli_main
from deleg_service.service import DelegationService, now_epoch
from tests.test_http_flow import http_call

ROOT_DIR = Path(__file__).resolve().parent.parent
NUM_PROCS = 4

# 模块加载时的真实墙钟窗口：服务进程按各自墙钟校验，窗口足够宽以覆盖测试时长
NOW_RT = now_epoch()
W_NBF, W_EXP = NOW_RT - 10_000, NOW_RT + 10_000


def _wide_window() -> tuple[int, int]:
    """以真实墙钟为中心的宽窗口，适配服务进程的当前时间。"""
    now = now_epoch()
    return now - 10_000, now + 10_000


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FourProcessCluster:
    """在临时目录拉起 4 个独立服务进程，注入同一屏障目录。"""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="deleg_race_")
        self.base = Path(self.tmp.name)
        self.db_dir = self.base / "data"
        self.barrier_dir = self.base / "barriers"
        self.barrier_dir.mkdir()
        self.ports = [_free_port() for _ in range(NUM_PROCS)]
        self.procs: list[subprocess.Popen] = []

    def start(self) -> None:
        # 测试进程自身也要通过同一屏障目录与服务子进程握手
        os.environ["DELEG_BARRIER_DIR"] = str(self.barrier_dir)
        env = os.environ.copy()
        env["DELEG_BARRIER_DIR"] = str(self.barrier_dir)
        env["PYTHONIOENCODING"] = "utf-8"
        for port in self.ports:
            # 不用 -I：隔离模式会移除 cwd，-m 无法解析本仓库包
            cmd = [sys.executable, "-m",
                   "deleg_service.serve_worker",
                   "--db-dir", str(self.db_dir),
                   "--host", "127.0.0.1", "--port", str(port)]
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            proc = subprocess.Popen(
                cmd, env=env, cwd=str(ROOT_DIR),
                creationflags=flags,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.procs.append(proc)
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 20
        last_err = None
        while time.monotonic() < deadline:
            if all(p.poll() is None for p in self.procs):
                ok = True
                for port in self.ports:
                    try:
                        status, _ = http_call(port, "/healthz")
                        if status != 200:
                            ok = False
                    except Exception as exc:
                        last_err = exc
                        ok = False
                if ok:
                    return
            time.sleep(0.2)
        self.dump_logs()
        raise RuntimeError(f"服务进程未就绪: {last_err}")

    def dump_logs(self) -> None:
        for proc in self.procs:
            if proc.poll() is not None and proc.stdout is not None:
                try:
                    out = proc.stdout.read().decode("utf-8", "replace")
                    print(f"--- pid={proc.pid} 输出 ---\n{out}")
                except Exception:
                    pass

    def stop(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
        time.sleep(0.8)
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
        for proc in self.procs:
            proc.wait(timeout=10)
        os.environ.pop("DELEG_BARRIER_DIR", None)
        self.tmp.cleanup()


class RaceConditionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cluster = FourProcessCluster()
        # 先用 CLI 初始化库与演示数据（与服务进程共享同一 DB 文件）
        d = str(cls.cluster.db_dir)
        cli_main(["--db-dir", d, "init"])
        cli_main(["--db-dir", d, "tenant", "--id", "t-acme", "--name", "ACME"])
        for p in ("alice", "bob", "carol"):
            cli_main(["--db-dir", d, "principal", "--id", p, "--name", p])
            cli_main(["--db-dir", d, "membership", "--tenant", "t-acme",
                      "--principal", p])
        for r in ("res-0", "res-1"):
            cli_main(["--db-dir", d, "resource", "--id", r, "--name", r])
        cls.cluster.start()
        cls.ports = cls.cluster.ports
        # 管理员视角的服务句柄（同库，用于直接撤销与状态断言）
        cls.admin = DelegationService(cls.cluster.db_dir)

        # 登录令牌（经某个进程换取，令牌存库，全进程通用）
        _, body = http_call(cls.ports[0], "/login", {
            "tenant_id": "t-acme", "principal_id": "alice"})
        cls.token_alice = body["token"]
        _, body = http_call(cls.ports[1], "/login", {
            "tenant_id": "t-acme", "principal_id": "bob"})
        cls.token_bob = body["token"]
        _, body = http_call(cls.ports[2], "/login", {
            "tenant_id": "t-acme", "principal_id": "carol"})
        cls.token_carol = body["token"]

    @classmethod
    def tearDownClass(cls):
        cls.cluster.stop()

    def setUp(self):
        barriers.reset_all()

    def _root_and_child(self, root_holder="alice", child_holder="bob",
                        resources=None, actions=None):
        resources = resources or ["res-0", "res-1"]
        actions = actions or ["read", "write"]
        root = self.admin.create_root_grant(
            "t-acme", root_holder, resources, actions,
            W_NBF, W_EXP, NOW_RT,
        )
        # 子授权通过 HTTP 在进程 0 上正常签发（无屏障竞争时）
        status, body = http_call(self.ports[0], "/delegate", {
            "parent_ticket": root["ticket"],
            "holder": child_holder,
            "resources": resources,
            "actions": actions,
            "nbf": W_NBF, "exp": W_EXP,
        }, token=self.token_alice)
        self.assertEqual(status, 200, body)
        return root, body

    # ------------------------------------------------------------------ #
    def test_revoke_after_ancestor_check_blocks_pending_delegate(self):
        """顺序 A：delegate 完成祖先检查并停在同步点 -> 撤销提交 -> 放行 delegate。

        期望：delegate 在写事务内二次校验发现父已撤销，拒绝；
        数据库中不得出现新子节点；随后所有 check 拒绝。
        """
        root, child = self._root_and_child()
        child_id = child["auth_id"]
        barrier_name = f"delegate:{child_id}:carol"

        # 在进程 1 发起再委托（bob 是 child 的持有人），它会阻塞在屏障上
        import threading
        result_box = {}

        def do_delegate():
            status, body = http_call(self.ports[1], "/delegate", {
                "parent_ticket": child["ticket"],
                "holder": "carol",
                "resources": ["res-0"],
                "actions": ["read"],
                "nbf": W_NBF, "exp": W_EXP,
            }, token=self.token_bob)
            result_box["status"] = status
            result_box["body"] = body

        t = threading.Thread(target=do_delegate, daemon=True)
        barriers.arm(barrier_name)
        t.start()
        barriers.wait_for(barrier_name)  # 等服务端到达“祖先检查之后”同步点

        # 此时在另一进程（进程 2）提交撤销
        status, rev = http_call(self.ports[2], "/revoke",
                                {"auth_id": child_id},
                                token=self.token_alice)
        self.assertEqual(status, 200, rev)
        self.assertTrue(rev["revoked"])

        barriers.release(barrier_name)  # 放行被挂起的 delegate
        t.join(timeout=20)
        self.assertIn("status", result_box, "委托线程未在超时内返回")
        self.assertEqual(result_box["status"], 403, result_box)
        self.assertEqual(result_box["body"]["error"]["code"], "ERR_REVOKED")

        # 数据库中不得出现以 child 为父的新分支
        import sqlite3
        conn = sqlite3.connect(self.cluster.db_dir / "deleg.db")
        row = conn.execute(
            "SELECT COUNT(*) FROM auth_grants WHERE parent_id=?", (child_id,)
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], 0, "撤销后仍产生了新的子授权分支")

        # 撤销返回后新开始的检查（在所有 4 个进程上）一律拒绝
        for port in self.ports:
            status, body = http_call(port, "/check", {
                "ticket": child["ticket"], "resource_id": "res-0",
                "action": "read",
            }, token=self.token_bob)
            self.assertEqual(status, 403)
            self.assertEqual(body["error"]["code"], "ERR_REVOKED")

    def test_delegate_committed_first_then_revoke_kills_new_branch(self):
        """顺序 B：delegate 先提交成功，随后撤销父节点 -> 新分支即刻失效。"""
        root, child = self._root_and_child()
        child_id = child["auth_id"]
        barrier_name = f"delegate:{child_id}:carol"

        import threading
        result_box = {}

        def do_delegate():
            status, body = http_call(self.ports[1], "/delegate", {
                "parent_ticket": child["ticket"],
                "holder": "carol",
                "resources": ["res-0"],
                "actions": ["read"],
                "nbf": W_NBF, "exp": W_EXP,
            }, token=self.token_bob)
            result_box["status"] = status
            result_box["body"] = body

        t = threading.Thread(target=do_delegate, daemon=True)
        barriers.arm(barrier_name)
        t.start()
        barriers.wait_for(barrier_name)
        barriers.release(barrier_name)  # 先放行委托
        t.join(timeout=20)
        self.assertEqual(result_box["status"], 200, result_box)
        grandchild = result_box["body"]

        # 委托已落库且可用
        status, body = http_call(self.ports[3], "/check", {
            "ticket": grandchild["ticket"], "resource_id": "res-0",
            "action": "read",
        }, token=self.token_carol)
        self.assertEqual(status, 200, body)

        # 再撤销 child：新分支（grandchild）必须立即不可用
        status, _ = http_call(self.ports[0], "/revoke",
                              {"auth_id": child_id},
                              token=self.token_alice)
        self.assertEqual(status, 200)
        status, body = http_call(self.ports[2], "/check", {
            "ticket": grandchild["ticket"], "resource_id": "res-0",
            "action": "read",
        }, token=self.token_carol)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "ERR_REVOKED")

    def test_same_node_revoke_vs_redelegate_race_repeated(self):
        """同一节点撤销与再委托竞争，重复 8 轮，两种顺序都不能留下有效新分支。"""
        for round_idx in range(8):
            root, child = self._root_and_child()
            child_id = child["auth_id"]
            barrier_name = f"delegate:{child_id}:carol"

            import threading
            result_box = {}

            def do_delegate():
                status, body = http_call(
                    self.ports[round_idx % NUM_PROCS], "/delegate", {
                        "parent_ticket": child["ticket"],
                        "holder": "carol",
                        "resources": ["res-0"],
                        "actions": ["read"],
                        "nbf": W_NBF, "exp": W_EXP,
                    }, token=self.token_bob)
                result_box["status"] = status
                result_box["body"] = body

            t = threading.Thread(target=do_delegate, daemon=True)
            barriers.arm(barrier_name)
            t.start()
            barriers.wait_for(barrier_name)

            # 偶数轮：先撤销再放行；奇数轮：先放行再撤销
            if round_idx % 2 == 0:
                http_call(self.ports[(round_idx + 1) % NUM_PROCS], "/revoke",
                          {"auth_id": child_id}, token=self.token_alice)
                barriers.release(barrier_name)
                t.join(timeout=20)
                self.assertEqual(result_box["status"], 403, result_box)
            else:
                barriers.release(barrier_name)
                t.join(timeout=20)
                self.assertEqual(result_box["status"], 200, result_box)
                http_call(self.ports[(round_idx + 1) % NUM_PROCS], "/revoke",
                          {"auth_id": child_id}, token=self.token_alice)

            # 不变量：撤销完成后，child 下任何分支都不可用；
            # 若委托曾成功，其票据现在也必须被拒
            if result_box["status"] == 200:
                status, body = http_call(self.ports[3], "/check", {
                    "ticket": result_box["body"]["ticket"],
                    "resource_id": "res-0", "action": "read",
                }, token=self.token_carol)
                self.assertEqual(status, 403,
                                 f"第 {round_idx} 轮：撤销后新分支仍可用 {body}")

            # child 本身在所有进程上都已撤销
            for port in self.ports:
                status, body = http_call(port, "/check", {
                    "ticket": child["ticket"], "resource_id": "res-0",
                    "action": "read",
                }, token=self.token_bob)
                self.assertEqual(status, 403)

    def test_revoke_vs_protected_write_race_freezes_version(self):
        """受保护写入与祖先撤销竞争：失败写入不得改变最终资源版本。"""
        root, child = self._root_and_child(
            actions=["read", "write"], resources=["res-0"]
        )
        # child 持有人改为 bob 且带 write；直接用 child 票据做 incr
        leaf_id = child["auth_id"]
        barrier_name = f"incr:{leaf_id}:res-0"

        version_before = self.admin.get_version("res-0")["version"]

        import threading
        result_box = {}

        def do_incr():
            status, body = http_call(self.ports[1], "/resource/incr", {
                "ticket": child["ticket"], "resource_id": "res-0",
            }, token=self.token_bob)
            result_box["status"] = status
            result_box["body"] = body

        t = threading.Thread(target=do_incr, daemon=True)
        barriers.arm(barrier_name)
        t.start()
        barriers.wait_for(barrier_name)
        # 撤销根（祖先），让挂起的写入在事务内二次校验时失败
        http_call(self.ports[2], "/revoke", {"auth_id": root["auth_id"]},
                  token=self.token_alice)
        barriers.release(barrier_name)
        t.join(timeout=20)
        self.assertEqual(result_box["status"], 403, result_box)
        self.assertEqual(result_box["body"]["error"]["code"], "ERR_REVOKED")

        # 最终版本必须与竞争前完全一致（失败写入没有产生版本号）
        self.assertEqual(
            self.admin.get_version("res-0")["version"], version_before
        )

        # 对照：无竞争时写入成功，版本恰好 +1
        root2 = self.admin.create_root_grant(
            "t-acme", "alice", ["res-1"], ["read", "write"],
            W_NBF, W_EXP, NOW_RT,
        )
        status, body = http_call(self.ports[0], "/resource/incr", {
            "ticket": root2["ticket"], "resource_id": "res-1",
        }, token=self.token_alice)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["version"], 1)
        self.assertEqual(self.admin.get_version("res-1")["version"], 1)

    def test_all_four_processes_share_state(self):
        """4 个进程看到同一份授权与版本数据（共享数据库的直接证据）。"""
        root = self.admin.create_root_grant(
            "t-acme", "alice", ["res-1"], ["read", "write"],
            W_NBF, W_EXP, NOW_RT,
        )
        for idx, port in enumerate(self.ports):
            status, body = http_call(port, "/check", {
                "ticket": root["ticket"], "resource_id": "res-1",
                "action": "read",
            }, token=self.token_alice)
            self.assertEqual(status, 200, f"进程 {idx} 未读到共享授权")
        # 在进程 0 撤销，进程 1/2/3 立刻可见
        http_call(self.ports[0], "/revoke", {"auth_id": root["auth_id"]},
                  token=self.token_alice)
        for port in self.ports[1:]:
            status, body = http_call(port, "/check", {
                "ticket": root["ticket"], "resource_id": "res-1",
                "action": "read",
            }, token=self.token_alice)
            self.assertEqual(status, 403)
            self.assertEqual(body["error"]["code"], "ERR_REVOKED")


if __name__ == "__main__":
    unittest.main()
