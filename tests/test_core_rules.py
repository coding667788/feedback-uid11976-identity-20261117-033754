"""核心规则测试：覆盖题目点名的全部边界与攻击场景。

- 第 8/9 层深度边界
- 叶子身份冒用（登录身份与叶子持有人不一致）
- 缺失中间节点
- 父摘要被改（含换父节点拼接）
- 同名主体跨租户
- 过期祖先
- 已预热签名缓存下的撤销（证明撤销结论不被缓存）
- 票据结构攻击：重复键、错误字段类型、未知版本/算法、重复集合成员
- 衰减/越权/空集/非成员/跨租户委托
- 最终资源版本与授权链状态断言（不是只验票据签名）
"""

from __future__ import annotations

import copy
import json

from deleg_service import crypto
from deleg_service.errors import ServiceError
from deleg_service.service import (
    _canonical_json_str,
    _validate_str_set,
)
from tests.helpers import (
    NOW,
    PRINCIPALS,
    RESOURCES,
    BaseServiceTest,
    WINDOW_EXP,
    WINDOW_NBF,
)


def _re_encode(payload: dict, key: bytes, alg: str | None = None,
               ver: int | None = None) -> str:
    """用给定 header 重新编码票据（用于算法/版本攻击）。"""
    import base64
    import hashlib
    import hmac

    header = {"alg": alg or "HS256", "typ": "DLG-TICKET",
              "ver": 1 if ver is None else ver}
    h = crypto.b64url_encode(
        json.dumps(header, separators=(",", ":")).encode()
    )
    p = crypto.b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{crypto.b64url_encode(sig)}"


class DepthBoundaryTest(BaseServiceTest):
    def _build_chain(self, depth: int):
        """从根开始建到指定深度（根=1），返回每层 {auth_id, ticket, holder}。"""
        holders = PRINCIPALS  # alice,bob,carol,dave,erin 循环使用
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"]
        )
        layers = [root]
        current = root
        for d in range(2, depth + 1):
            holder = holders[(d - 1) % len(holders)]
            current = self.h.delegate(
                current["auth_id"], holder, RESOURCES, ["read", "write"]
            )
            layers.append(current)
        return layers

    def test_depth_8_is_allowed(self):
        layers = self._build_chain(8)
        self.assertEqual(len(layers), 8)
        leaf = layers[-1]
        self.assertEqual(leaf["depth"], 8)
        holder = self.h.ref.grants[self.h.svc_to_ref[leaf["auth_id"]]].holder
        token = self.h.login("t-acme", holder)
        out = self.h.svc.check(
            token, self.h.tickets[leaf["auth_id"]], "res-0", "read", NOW
        )
        self.assertTrue(out["allowed"])
        self.assertEqual(len(out["chain_ids"]), 8)

    def test_depth_9_is_rejected(self):
        layers = self._build_chain(8)
        parent = layers[-1]
        parent_holder = self.h.ref.grants[
            self.h.svc_to_ref[parent["auth_id"]]
        ].holder
        token = self.h.login("t-acme", parent_holder)
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.delegate(
                token, self.h.tickets[parent["auth_id"]], "bob",
                ["res-0"], ["read"], WINDOW_NBF, WINDOW_EXP, NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_DEPTH_LIMIT")
        # 参考模型持相同结论
        with self.assertRaises(Exception):
            self.h.ref.check_delegation_legal(
                self.h.svc_to_ref[parent["auth_id"]], "bob",
                {"res-0"}, {"read"}, WINDOW_NBF, WINDOW_EXP,
            )


class IdentityImpersonationTest(BaseServiceTest):
    def test_leaf_identity_must_match_login(self):
        root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read", "write"]
        )
        child = self.h.delegate(root["auth_id"], "bob", ["res-0"], ["read"])
        # carol 拿着 bob 的票据尝试使用 -> 拒绝
        token_carol = self.h.login("t-acme", "carol")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token_carol, self.h.tickets[child["auth_id"]],
                "res-0", "read", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_HOLDER_MISMATCH")
        # 无令牌 -> 401
        with self.assertRaises(ServiceError) as ctx2:
            self.h.svc.check(
                None, self.h.tickets[child["auth_id"]],
                "res-0", "read", NOW,
            )
        self.assertEqual(ctx2.exception.http_status, 401)
        # 正确持有人 bob 可用
        token_bob = self.h.login("t-acme", "bob")
        self.assertTrue(self.h.svc.check(
            token_bob, self.h.tickets[child["auth_id"]],
            "res-0", "read", NOW,
        )["allowed"])

    def test_non_holder_cannot_delegate(self):
        root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read", "write"]
        )
        token_bob = self.h.login("t-acme", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.delegate(
                token_bob, self.h.tickets[root["auth_id"]], "carol",
                ["res-0"], ["read"], WINDOW_NBF, WINDOW_EXP, NOW,
            )
        # bob 不是叶子持有人，身份不匹配先被拦
        self.assertEqual(ctx.exception.code, "ERR_HOLDER_MISMATCH")


class MissingIntermediateTest(BaseServiceTest):
    def test_missing_parent_node_denied(self):
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"]
        )
        mid = self.h.delegate(root["auth_id"], "bob", RESOURCES, ["read"])
        leaf = self.h.delegate(mid["auth_id"], "carol", ["res-1"], ["read"])

        # 物理删除中间节点（模拟库内缺节点/断链）
        import sqlite3
        conn = sqlite3.connect(
            __import__("pathlib").Path(self.h.db_dir) / "deleg.db"
        )
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("DELETE FROM auth_grants WHERE auth_id=?",
                     (mid["auth_id"],))
        conn.commit()
        conn.close()

        token = self.h.login("t-acme", "carol")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token, self.h.tickets[leaf["auth_id"]],
                "res-1", "read", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_MISSING_NODE")


class ParentDigestTamperTest(BaseServiceTest):
    def test_child_parent_digest_modified_is_rejected(self):
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"]
        )
        child = self.h.delegate(root["auth_id"], "bob", ["res-0"], ["read"])

        # 解码子票据，篡改 parent_digest 后用服务端密钥重签（即使重签有效也拒绝）
        parts = self.h.tickets[child["auth_id"]].split(".")
        payload = json.loads(crypto.b64url_decode_strict(parts[1]))
        payload["parent_digest"] = "0" * 64
        forged = _re_encode(payload, self.h.svc.key)
        token = self.h.login("t-acme", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(token, forged, "res-0", "read", NOW)
        # 篡改票据在“出示票据 vs 库内票据”绑定检查处即被拦，
        # 不会进入后续链校验（防御层更靠前，安全语义等价且更强）
        self.assertIn(ctx.exception.code,
                      ("ERR_PARENT_BINDING", "ERR_PARENT_DIGEST_MISMATCH"))

    def test_reparenting_to_another_grant_is_rejected(self):
        """拼接攻击：把另一棵树的节点改成指向不同父授权。"""
        root_a = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read", "write"]
        )
        root_b = self.h.root_grant(
            holder="alice", resources=["res-1"], actions=["read", "write"]
        )
        child_a = self.h.delegate(
            root_a["auth_id"], "bob", ["res-0"], ["read"]
        )
        # 将 child_a 票据的 parent_id 改指 root_b，并伪填 root_b 的摘要
        parts = self.h.tickets[child_a["auth_id"]].split(".")
        payload = json.loads(crypto.b64url_decode_strict(parts[1]))
        payload["parent_id"] = root_b["auth_id"]
        payload["parent_digest"] = root_b["content_digest"]
        forged = _re_encode(payload, self.h.svc.key)
        token = self.h.login("t-acme", "bob")
        with self.assertRaises(ServiceError):
            # 库行仍绑定 root_a，票据与库行绑定不一致 -> 拒绝
            self.h.svc.check(token, forged, "res-0", "read", NOW)

    def test_direct_db_row_digest_tamper_is_rejected(self):
        """直接改库行里的父绑定（无票据配合）也必须被对账逻辑拦截。"""
        import sqlite3
        from pathlib import Path

        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"]
        )
        child = self.h.delegate(root["auth_id"], "bob", ["res-0"], ["read"])
        conn = sqlite3.connect(Path(self.h.db_dir) / "deleg.db")
        conn.execute(
            "UPDATE auth_grants SET parent_digest=? WHERE auth_id=?",
            ("f" * 64, child["auth_id"]),
        )
        conn.commit()
        conn.close()
        token = self.h.login("t-acme", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token, self.h.tickets[child["auth_id"]],
                "res-0", "read", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_PARENT_DIGEST_MISMATCH")


class CrossTenantTest(BaseServiceTest):
    def test_same_named_principal_across_tenants(self):
        # t-other 租户下也有 alice；两条根授权分属不同租户
        root_acme = self.h.svc.create_root_grant(
            "t-acme", "alice", ["res-0"], ["read", "write"],
            WINDOW_NBF, WINDOW_EXP, NOW,
        )
        root_other = self.h.svc.create_root_grant(
            "t-other", "alice", ["res-1"], ["read"],
            WINDOW_NBF, WINDOW_EXP, NOW,
        )
        token_acme = self.h.login("t-acme", "alice")
        token_other = self.h.login("t-other", "alice")

        # 同名 alice，租户 A 的令牌不能用租户 B 的票据
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token_acme, root_other["ticket"], "res-1", "read", NOW
            )
        self.assertEqual(ctx.exception.code, "ERR_CROSS_TENANT")
        # 反向同样拒绝
        with self.assertRaises(ServiceError):
            self.h.svc.check(
                token_other, root_acme["ticket"], "res-0", "read", NOW
            )
        # 各自租户内正常
        self.assertTrue(self.h.svc.check(
            token_acme, root_acme["ticket"], "res-0", "read", NOW
        )["allowed"])
        self.assertTrue(self.h.svc.check(
            token_other, root_other["ticket"], "res-1", "read", NOW
        )["allowed"])

    def test_cross_tenant_delegation_rejected(self):
        # 构造一个只属于 t-other、不属于 t-acme 的主体
        self.h.svc.create_principal("frank", "FRANK", NOW)
        self.h.svc.add_membership("t-other", "frank")
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"]
        )
        token = self.h.login("t-acme", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.delegate(
                token, self.h.tickets[root["auth_id"]], "frank",
                ["res-0"], ["read"], WINDOW_NBF, WINDOW_EXP, NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_NOT_MEMBER")


class ExpiredAncestorTest(BaseServiceTest):
    def test_expired_ancestor_denies_descendants(self):
        # 根授权在 NOW-100 过期
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"],
            nbf=NOW - 1000, exp=NOW - 100,
        )
        # 子授权自身时间“看起来有效”，但父已过期：初校全链时即被拦，
        # 且其时间区间本也超出父区间（ERR_NOT_SUBSET）。两种拒绝都成立。
        token = self.h.login("t-acme", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.delegate(
                token, self.h.tickets[root["auth_id"]], "bob",
                ["res-0"], ["read"], NOW - 200, NOW + 1000, NOW,
            )
        self.assertIn(ctx.exception.code,
                      ("ERR_EXPIRED", "ERR_NOT_SUBSET"))

    def test_ancestor_expires_after_issuance(self):
        """先合法签发，再把时钟拨到祖先过期之后：叶子立即不可用。"""
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"],
            nbf=NOW - 1000, exp=NOW + 100,
        )
        child = self.h.delegate(
            root["auth_id"], "bob", ["res-0"], ["read"],
            nbf=NOW - 500, exp=NOW + 50,
        )
        token = self.h.login("t-acme", "bob")
        # NOW 时有效
        self.assertTrue(self.h.svc.check(
            token, self.h.tickets[child["auth_id"]],
            "res-0", "read", NOW,
        )["allowed"])
        # NOW+200：根与子均过期
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token, self.h.tickets[child["auth_id"]],
                "res-0", "read", NOW + 200,
            )
        self.assertEqual(ctx.exception.code, "ERR_EXPIRED")
        # 参考模型结论一致
        self.assertFalse(self.h.ref.can_use(
            self.h.svc_to_ref[child["auth_id"]], "bob", "t-acme",
            "res-0", "read", NOW + 200,
        ))


class CachedRevocationTest(BaseServiceTest):
    def test_revocation_takes_effect_under_warm_cache(self):
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"]
        )
        child = self.h.delegate(root["auth_id"], "bob", ["res-0"], ["read"])
        grandchild = self.h.delegate(
            child["auth_id"], "carol", ["res-0"], ["read"]
        )
        token_bob = self.h.login("t-acme", "bob")
        token_carol = self.h.login("t-acme", "carol")

        # 预热：多次校验，签名验证进入 LRU 缓存
        for _ in range(3):
            self.assertTrue(self.h.svc.check(
                token_bob, self.h.tickets[child["auth_id"]],
                "res-0", "read", NOW,
            )["allowed"])
            self.assertTrue(self.h.svc.check(
                token_carol, self.h.tickets[grandchild["auth_id"]],
                "res-0", "read", NOW,
            )["allowed"])
        info = self.h.svc.verifier.cache_info()
        self.assertGreaterEqual(info["lru_hits"], 2)

        # 撤销中间节点 child：整棵子树（含 grandchild）即刻不可用
        self.h.revoke(child["auth_id"])
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token_carol, self.h.tickets[grandchild["auth_id"]],
                "res-0", "read", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_REVOKED")
        with self.assertRaises(ServiceError):
            self.h.svc.check(
                token_bob, self.h.tickets[child["auth_id"]],
                "res-0", "read", NOW,
            )
        # 撤销根：root 自身与全部后代不可用
        self.h.revoke(root["auth_id"])
        token_alice = self.h.login("t-acme", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token_alice, self.h.tickets[root["auth_id"]],
                "res-0", "read", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_REVOKED")

        # 撤销后无法靠重新委托恢复
        with self.assertRaises(ServiceError):
            self.h.svc.delegate(
                token_bob, self.h.tickets[child["auth_id"]], "dave",
                ["res-0"], ["read"], WINDOW_NBF, WINDOW_EXP, NOW,
            )

    def test_revocation_idempotent_and_visible_in_grant_state(self):
        root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read"]
        )
        r1 = self.h.svc.revoke(None, root["auth_id"], NOW, admin=True)
        r2 = self.h.svc.revoke(None, root["auth_id"], NOW, admin=True)
        self.assertFalse(r1["already_revoked"])
        self.assertTrue(r2["already_revoked"])
        state = self.h.svc.get_grant(root["auth_id"])
        self.assertTrue(state["revoked"])


class TicketStructureAttackTest(BaseServiceTest):
    def setUp(self):
        super().setUp()
        self.root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read", "write"]
        )
        self.token = self.h.login("t-acme", "alice")

    def test_duplicate_json_key_rejected(self):
        # 手工构造含重复键的 payload 段
        dup_payload = (
            '{"v":1,"auth_id":"x","tenant":"t-acme","holder":"alice",'
            '"holder":"bob","resources":["res-0"],"actions":["read"],'
            '"nbf":1,"exp":2}'
        )
        seg = crypto.b64url_encode(dup_payload.encode())
        ticket = f"eyJhbGciOiJIUzI1NiJ9.{seg}.AAAA"
        with self.assertRaises(ServiceError) as ctx:
            crypto.parse_ticket(ticket, self.h.svc.key)
        self.assertEqual(ctx.exception.code, "ERR_DUPLICATE_KEY")

    def test_wrong_field_types_rejected(self):
        bad_cases = [
            {"resources": "res-0"},
            {"actions": ["read", 7]},
            {"nbf": "100", "exp": 200},
            {"nbf": True, "exp": 200},   # 布尔冒充整数
            {"holder": 123},
            {"v": "1"},
        ]
        good = {
            "v": 1, "auth_id": "x", "tenant": "t-acme", "holder": "alice",
            "resources": ["res-0"], "actions": ["read"], "nbf": 1, "exp": 2,
        }
        for mutation in bad_cases:
            payload = copy.deepcopy(good)
            payload.update(mutation)
            with self.assertRaises(ServiceError) as ctx:
                self.h.svc._validate_payload_shape(payload, is_root=True)
            self.assertIn(ctx.exception.code,
                          ("ERR_BAD_FIELD_TYPE", "ERR_BAD_ACTION"))

    def test_unknown_version_and_algorithm_rejected(self):
        parts = self.h.tickets[self.root["auth_id"]].split(".")
        payload = json.loads(crypto.b64url_decode_strict(parts[1]))
        # 未知票据版本（即使签名合法）
        bad_ver = _re_encode(payload, self.h.svc.key, ver=99)
        with self.assertRaises(ServiceError) as ctx:
            crypto.parse_ticket(bad_ver, self.h.svc.key)
        self.assertEqual(ctx.exception.code, "ERR_UNKNOWN_VERSION")
        # 其他算法（none / HS512），即使重新签名也拒绝
        for alg in ("none", "HS512"):
            bad_alg = _re_encode(payload, self.h.svc.key, alg=alg)
            with self.assertRaises(ServiceError) as ctx:
                crypto.parse_ticket(bad_alg, self.h.svc.key)
            self.assertEqual(ctx.exception.code, "ERR_UNKNOWN_ALG")

    def test_bad_signature_rejected(self):
        ticket = self.h.tickets[self.root["auth_id"]]
        head, payload, _sig = ticket.split(".")
        forged = f"{head}.{payload}.{crypto.b64url_encode(b'x' * 32)}"
        with self.assertRaises(ServiceError) as ctx:
            crypto.parse_ticket(forged, self.h.svc.key)
        self.assertEqual(ctx.exception.code, "ERR_BAD_SIGNATURE")

    def test_duplicate_set_members_rejected(self):
        with self.assertRaises(ServiceError) as ctx:
            _validate_str_set(["a", "a"], "resources")
        self.assertEqual(ctx.exception.code, "ERR_DUPLICATE_KEY")
        with self.assertRaises(ServiceError):
            self.h.svc.create_root_grant(
                "t-acme", "alice", ["res-0", "res-0"], ["read", "read"],
                WINDOW_NBF, WINDOW_EXP, NOW,
            )

    def test_unknown_fields_rejected(self):
        payload = {
            "v": 1, "auth_id": "x", "tenant": "t-acme", "holder": "alice",
            "resources": ["res-0"], "actions": ["read"],
            "nbf": 1, "exp": 2, "admin": True,
        }
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc._validate_payload_shape(payload, is_root=True)
        self.assertEqual(ctx.exception.code, "ERR_UNKNOWN_FIELD")

    def test_non_canonical_order_still_same_digest(self):
        # 乱序字段/集合顺序不改变摘要含义
        a = {"v": 1, "auth_id": "x", "tenant": "t", "holder": "h",
             "resources": ["r1", "r2"], "actions": ["read"],
             "nbf": 1, "exp": 2}
        b = dict(a)
        b["resources"] = ["r2", "r1"]
        self.assertEqual(crypto.canonical_digest(a),
                         crypto.canonical_digest(b))


class AttenuationTest(BaseServiceTest):
    def test_resource_action_escalation_rejected(self):
        root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read"]
        )
        token = self.h.login("t-acme", "alice")
        # 资源越权
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.delegate(
                token, self.h.tickets[root["auth_id"]], "bob",
                ["res-1"], ["read"], WINDOW_NBF, WINDOW_EXP, NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_NOT_SUBSET")
        # 动作越权（read-only 不能委托 write）
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.delegate(
                token, self.h.tickets[root["auth_id"]], "bob",
                ["res-0"], ["write"], WINDOW_NBF, WINDOW_EXP, NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_NOT_SUBSET")

    def test_time_window_escalation_rejected(self):
        root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read"],
            nbf=NOW - 100, exp=NOW + 100,
        )
        token = self.h.login("t-acme", "alice")
        for nbf, exp in [(NOW - 200, NOW + 50), (NOW - 50, NOW + 200)]:
            with self.assertRaises(ServiceError) as ctx:
                self.h.svc.delegate(
                    token, self.h.tickets[root["auth_id"]], "bob",
                    ["res-0"], ["read"], nbf, exp, NOW,
                )
            self.assertEqual(ctx.exception.code, "ERR_NOT_SUBSET")

    def test_empty_sets_and_unknown_resource_rejected(self):
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.create_root_grant(
                "t-acme", "alice", [], ["read"], WINDOW_NBF, WINDOW_EXP, NOW
            )
        self.assertEqual(ctx.exception.code, "ERR_EMPTY_SET")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.create_root_grant(
                "t-acme", "alice", ["nope-9"], ["read"],
                WINDOW_NBF, WINDOW_EXP, NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_UNKNOWN_RESOURCE")

    def test_root_expansion_uses_new_root_id(self):
        """根授权扩权必须新建根 ID，旧链含义保持不变。"""
        root1 = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read"]
        )
        child = self.h.delegate(root1["auth_id"], "bob", ["res-0"], ["read"])
        # 扩权：新根带 write，ID 必须不同
        root2 = self.h.svc.create_root_grant(
            "t-acme", "alice", ["res-0", "res-1"], ["read", "write"],
            WINDOW_NBF, WINDOW_EXP, NOW,
        )
        self.assertNotEqual(root1["auth_id"], root2["auth_id"])
        # 旧链仍是 read-only，不会因新根而扩权
        token_bob = self.h.login("t-acme", "bob")
        with self.assertRaises(ServiceError):
            self.h.svc.check(
                token_bob, self.h.tickets[child["auth_id"]],
                "res-0", "write", NOW,
            )
        self.assertEqual(
            _canonical_json_str(["res-0"]),
            '["res-0"]',
        )


class ResourceVersionTest(BaseServiceTest):
    def test_protected_increment_and_final_version(self):
        root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read", "write"]
        )
        # 只有 read 的子授权不能递增版本
        child_read = self.h.delegate(
            root["auth_id"], "bob", ["res-0"], ["read"]
        )
        token_bob = self.h.login("t-acme", "bob")
        self.assertEqual(self.h.svc.get_version("res-0")["version"], 0)
        with self.assertRaises(ServiceError):
            self.h.svc.increment_version(
                token_bob, self.h.tickets[child_read["auth_id"]],
                "res-0", NOW,
            )
        # 版本没有被失败的写入改变
        self.assertEqual(self.h.svc.get_version("res-0")["version"], 0)

        # write 授权可以递增，且连续递增反映最终版本号
        child_write = self.h.delegate(
            root["auth_id"], "carol", ["res-0"], ["write"]
        )
        token_carol = self.h.login("t-acme", "carol")
        for expected in (1, 2, 3):
            out = self.h.svc.increment_version(
                token_carol, self.h.tickets[child_write["auth_id"]],
                "res-0", NOW,
            )
            self.assertEqual(out["version"], expected)
        self.assertEqual(self.h.svc.get_version("res-0")["version"], 3)

        # 撤销后写入立即失败且版本冻结
        self.h.revoke(root["auth_id"])
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.increment_version(
                token_carol, self.h.tickets[child_write["auth_id"]],
                "res-0", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_REVOKED")
        self.assertEqual(self.h.svc.get_version("res-0")["version"], 3)

    def test_check_denies_uncovered_resource_and_action(self):
        root = self.h.root_grant(
            holder="alice", resources=["res-0"], actions=["read"]
        )
        token = self.h.login("t-acme", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token, self.h.tickets[root["auth_id"]],
                "res-1", "read", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_RESOURCE_MISMATCH")
        with self.assertRaises(ServiceError) as ctx:
            self.h.svc.check(
                token, self.h.tickets[root["auth_id"]],
                "res-0", "write", NOW,
            )
        self.assertEqual(ctx.exception.code, "ERR_NOT_SUBSET")
