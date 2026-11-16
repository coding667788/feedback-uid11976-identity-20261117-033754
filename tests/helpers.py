"""测试公共工具：隔离临时数据库、双模型（真实服务 + 参考模型）联动。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from deleg_service import db as dbmod
from deleg_service.service import DelegationService

# 测试窗口：所有授权时间都落在这个大区间内，过期用例单独构造更早/更晚边界
NOW = 1_800_000_000          # 固定“当前时间”，保证测试可重复
WINDOW_NBF = NOW - 10_000
WINDOW_EXP = NOW + 10_000

RESOURCES = [f"res-{i}" for i in range(6)]
TENANT = "t-acme"
TENANT2 = "t-other"
# 注意 alice 同时是两个租户的成员，用于“同名主体跨租户”用例
PRINCIPALS = ["alice", "bob", "carol", "dave", "erin"]


class ServiceHarness:
    """持有一个真实服务实例和一个独立参考模型，并保持二者同步演进。"""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="deleg_test_")
        self.db_dir = Path(self.tmp.name)
        dbmod.initialize(self.db_dir, NOW)
        self.svc = DelegationService(self.db_dir)
        self._bootstrap()

    def cleanup(self):
        self.tmp.cleanup()

    def _bootstrap(self):
        from tests.reference_model import RefModel

        self.ref = RefModel()
        self.svc.create_tenant(TENANT, "ACME", NOW)
        self.svc.create_tenant(TENANT2, "OTHER", NOW)
        self.ref.members.setdefault(TENANT, set())
        self.ref.members.setdefault(TENANT2, set())
        for p in PRINCIPALS:
            self.svc.create_principal(p, p.upper(), NOW)
        for p in PRINCIPALS:
            self.svc.add_membership(TENANT, p)
            self.ref.add_member(TENANT, p)
        # alice 同时加入第二个租户（同名跨租户）
        self.svc.add_membership(TENANT2, "alice")
        self.ref.add_member(TENANT2, "alice")
        for r in RESOURCES:
            self.svc.create_resource(r, r, NOW)
            self.ref.add_resource(r)

        # auth_id(服务) -> auth_id(参考) 与反向映射
        self.svc_to_ref: dict[str, str] = {}
        self.ref_to_svc: dict[str, str] = {}
        # auth_id(服务) -> 票据
        self.tickets: dict[str, str] = {}
        self.tokens: dict[tuple[str, str], str] = {}

    # ----- 会话 --------------------------------------------------------- #
    def login(self, tenant: str, principal: str) -> str:
        key = (tenant, principal)
        if key not in self.tokens:
            self.tokens[key] = self.svc.login(tenant, principal, NOW)
        return self.tokens[key]

    # ----- 双模型联动操作 ----------------------------------------------- #
    def root_grant(self, holder: str, resources, actions,
                   nbf=WINDOW_NBF, exp=WINDOW_EXP, tenant=TENANT):
        out = self.svc.create_root_grant(
            tenant, holder, list(resources), list(actions), nbf, exp, NOW
        )
        ref_g = self.ref.add_root(tenant, holder, set(resources),
                                  set(actions), nbf, exp)
        self._bind(out["auth_id"], ref_g.auth_id, out["ticket"])
        return out

    def delegate(self, parent_svc_id: str, child_holder: str,
                 resources, actions, nbf=WINDOW_NBF, exp=WINDOW_EXP):
        parent_ref_id = self.svc_to_ref[parent_svc_id]
        parent = self.ref.grants[parent_ref_id]
        token = self.login(TENANT, parent.holder)
        out = self.svc.delegate(
            token, self.tickets[parent_svc_id], child_holder,
            list(resources), list(actions), nbf, exp, NOW,
        )
        ref_g = self.ref.delegate(
            parent_ref_id, child_holder, set(resources), set(actions),
            nbf, exp,
        )
        self._bind(out["auth_id"], ref_g.auth_id, out["ticket"])
        return out

    def delegate_expect_error(self, parent_svc_id, child_holder,
                              resources, actions, nbf=WINDOW_NBF,
                              exp=WINDOW_EXP):
        """非法委托：服务必须拒绝，参考模型也必须判违规。"""
        parent_ref_id = self.svc_to_ref[parent_svc_id]
        parent = self.ref.grants[parent_ref_id]
        token = self.login(TENANT, parent.holder)
        from deleg_service.errors import ServiceError
        try:
            self.svc.delegate(
                token, self.tickets[parent_svc_id], child_holder,
                list(resources), list(actions), nbf, exp, NOW,
            )
        except ServiceError:
            pass
        else:
            raise AssertionError("真实服务接受了参考模型认为非法的委托")
        from tests.reference_model import RefViolation
        try:
            self.ref.delegate(parent_ref_id, child_holder,
                              set(resources), set(actions), nbf, exp)
        except RefViolation:
            return
        raise AssertionError("参考模型与真实服务对非法委托的判定不一致")

    def revoke(self, svc_id: str):
        self.svc.revoke(None, svc_id, NOW, admin=True)
        self.ref.revoke(self.svc_to_ref[svc_id])

    def _bind(self, svc_id: str, ref_id: str, ticket: str):
        self.svc_to_ref[svc_id] = ref_id
        self.ref_to_svc[ref_id] = svc_id
        self.tickets[svc_id] = ticket

    # ----- 全量交叉比对 ------------------------------------------------- #
    def assert_matches_reference(self, now: int = NOW):
        """对参考模型中的每个授权、每个主体、每个资源/动作比对判定结果。"""
        from deleg_service.errors import ServiceError

        principals = sorted(self.ref.members[TENANT])
        for ref_id, ref_g in self.ref.grants.items():
            svc_id = self.ref_to_svc[ref_id]
            ticket = self.tickets[svc_id]
            for principal in principals:
                token = self.login(TENANT, principal)
                for resource in RESOURCES:
                    for action in ("read", "write"):
                        ref_allow = self.ref.can_use(
                            ref_id, principal, TENANT,
                            resource, action, now,
                        )
                        try:
                            out = self.svc.check(
                                token, ticket, resource, action, now
                            )
                            svc_allow = bool(out.get("allowed"))
                        except ServiceError:
                            svc_allow = False
                        assert svc_allow == ref_allow, (
                            f"判定分歧 grant={svc_id}(ref={ref_id}) "
                            f"caller={principal} res={resource} act={action} "
                            f"now={now}: service={svc_allow} ref={ref_allow}"
                        )


class BaseServiceTest(unittest.TestCase):
    def setUp(self):
        self.h = ServiceHarness()

    def tearDown(self):
        self.h.cleanup()
