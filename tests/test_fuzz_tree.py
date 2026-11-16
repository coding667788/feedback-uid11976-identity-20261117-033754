"""随机委托树模糊测试：真实服务与独立参考实现逐节点交叉验证。

覆盖：随机深度/扇出的委托树、随机子集衰减、随机撤销（含祖先撤销）、
撤销后重新委托必须被双模型同时拒绝、全资源×全动作×全主体的判定矩阵。
"""

from __future__ import annotations

import random

from deleg_service.errors import ServiceError
from tests.helpers import (
    NOW,
    PRINCIPALS,
    RESOURCES,
    BaseServiceTest,
    WINDOW_EXP,
    WINDOW_NBF,
)
from tests.reference_model import RefViolation


class FuzzDelegationTreeTest(BaseServiceTest):
    def _random_subset(self, values, rng, keep_min=1):
        k = rng.randint(keep_min, len(values))
        return sorted(rng.sample(list(values), k))

    def _grow_tree(self, rng, rounds=40):
        """双模型并行生长：合法委托两边都成功，非法委托两边都拒绝。"""
        root = self.h.root_grant(
            holder="alice", resources=RESOURCES, actions=["read", "write"]
        )
        leaves = [root["auth_id"]]

        for _ in range(rounds):
            parent_id = rng.choice(leaves)
            parent_ref = self.h.ref.grants[self.h.svc_to_ref[parent_id]]
            child_holder = rng.choice(PRINCIPALS)
            # 50% 概率构造合法子集，50% 概率随机（可能越权/空集）
            if rng.random() < 0.7:
                res = self._random_subset(parent_ref.resources, rng)
                act = self._random_subset(parent_ref.actions, rng)
                # 时间窗口必须是父区间子集，且严格覆盖 NOW（nbf<=NOW<exp）
                low = max(parent_ref.nbf, NOW - 1)
                high = min(parent_ref.exp - 2, NOW + 1)
                nbf = rng.randint(low, min(high, NOW - 1))
                exp = rng.randint(NOW + 1, max(NOW + 1, high))
            else:
                res = self._random_subset(RESOURCES, rng)
                act = rng.sample(["read", "write", "execute", "delete"],
                                 k=rng.randint(1, 2))
                nbf, exp = WINDOW_NBF, WINDOW_EXP

            ref_parent = self.h.ref.grants[self.h.svc_to_ref[parent_id]]
            legal = True
            try:
                # 先用参考模型的纯校验判断这一委托是否应合法（不修改模型）
                self.h.ref.check_delegation_legal(
                    ref_parent.auth_id, child_holder, set(res), set(act),
                    nbf, exp,
                )
            except RefViolation:
                legal = False

            if legal:
                out = self.h.delegate(parent_id, child_holder, res, act,
                                      nbf, exp)
                leaves.append(out["auth_id"])
            else:
                self.h.delegate_expect_error(
                    parent_id, child_holder, res, act, nbf, exp
                )
        return root

    def test_fuzz_tree_permissions_match_reference(self):
        rng = random.Random(20261117)
        for trial in range(5):
            self.h = type(self.h)()  # 每轮全新库
            try:
                self._grow_tree(rng, rounds=30)
                self.h.assert_matches_reference()

                # 随机撤销 5 个节点，每次撤销后全矩阵重新比对
                all_ids = list(self.h.svc_to_ref.keys())
                for victim in rng.sample(all_ids, k=min(5, len(all_ids))):
                    self.h.revoke(victim)
                    self.h.assert_matches_reference()

                # 撤销后尝试在被撤销节点下重新委托：必须拒绝，
                # 且不得留下任何“撤销后仍有效”的新分支
                revoked_ids = list(self.h.ref.revoked)
                for ref_victim in revoked_ids[:3]:
                    svc_victim = self.h.ref_to_svc[ref_victim]
                    holder = self.h.ref.grants[ref_victim].holder
                    token = self.h.login("t-acme", holder)
                    with self.assertRaises(ServiceError):
                        self.h.svc.delegate(
                            token, self.h.tickets[svc_victim], "bob",
                            ["res-0"], ["read"], WINDOW_NBF, WINDOW_EXP, NOW,
                        )
                    self.h.assert_matches_reference()
            finally:
                self.h.cleanup()

    def test_fuzz_write_versions_match_reference(self):
        rng = random.Random(424242)
        root = self.h.root_grant(
            holder="alice", resources=["res-0", "res-1"],
            actions=["read", "write"],
        )
        child = self.h.delegate(root["auth_id"], "bob",
                                ["res-0"], ["write"])
        token_bob = self.h.login("t-acme", "bob")
        token_alice = self.h.login("t-acme", "alice")

        for i in range(20):
            res = rng.choice(["res-0", "res-1"])
            use_ticket = self.h.tickets[child["auth_id"]]
            token = rng.choice([token_bob, token_alice])
            caller = "bob" if token is token_bob else "alice"
            ref_before = self.h.ref.versions[res]
            svc_before = self.h.svc.get_version(res)["version"]
            self.assertEqual(ref_before, svc_before)

            ref_ok = self.h.ref.increment(
                self.h.svc_to_ref[child["auth_id"]], caller, "t-acme",
                res, NOW,
            )
            try:
                out = self.h.svc.increment_version(
                    token, use_ticket, res, NOW
                )
                svc_ok = True
            except ServiceError:
                svc_ok = False
                out = None
            self.assertEqual(svc_ok, ref_ok)
            if ref_ok:
                self.assertEqual(out["version"],
                                 self.h.ref.versions[res])
            self.assertEqual(self.h.svc.get_version(res)["version"],
                             self.h.ref.versions[res])
