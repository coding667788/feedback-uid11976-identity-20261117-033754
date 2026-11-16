"""独立参考实现：用朴素“集合 + 委托树”模型重述题目规则。

本模块刻意不 import deleg_service 包中的任何代码，数据结构与判定逻辑
独立编写，作为测试中的“第二真相源”，与真实服务的结论交叉比对。

模型：
- RefGrant：不可变授权节点（资源集合、动作集合、时间区间、父绑定）；
- RefModel：委托森林 + 撤销标记 + 资源版本；
- can_use / can_write：沿父链走根，逐跳验证成员、衰减、撤销、时间。
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_DEPTH = 8
ACTIONS = ("read", "write")


class RefViolation(Exception):
    """参考模型判定为非法的操作。"""


@dataclass(frozen=True)
class RefGrant:
    auth_id: str
    tenant: str
    holder: str
    resources: frozenset[str]
    actions: frozenset[str]
    nbf: int
    exp: int
    parent_id: str | None
    parent_digest: str | None
    depth: int
    digest: str


@dataclass
class RefModel:
    members: dict[str, set[str]] = field(default_factory=dict)
    grants: dict[str, RefGrant] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    versions: dict[str, int] = field(default_factory=dict)
    _seq: int = 0

    # ----- 基础数据 ----------------------------------------------------- #
    def add_member(self, tenant: str, principal: str) -> None:
        self.members.setdefault(tenant, set()).add(principal)

    def add_resource(self, resource_id: str) -> None:
        self.versions.setdefault(resource_id, 0)

    def _next_id(self) -> str:
        self._seq += 1
        return f"ref-g{self._seq:04d}"

    def _is_member(self, tenant: str, principal: str) -> bool:
        return principal in self.members.get(tenant, set())

    # ----- 参考版签发规则（与服务端规则逐条对应） ----------------------- #
    def add_root(self, tenant: str, holder: str,
                 resources: set[str], actions: set[str],
                 nbf: int, exp: int) -> RefGrant:
        if not self._is_member(tenant, holder):
            raise RefViolation("root holder 不是租户成员")
        if not resources or not actions:
            raise RefViolation("空集合")
        if not actions <= set(ACTIONS):
            raise RefViolation("非法动作")
        if any(r not in self.versions for r in resources):
            raise RefViolation("未知资源")
        if nbf >= exp:
            raise RefViolation("时间区间非法")
        gid = self._next_id()
        digest = f"digest-root:{gid}"
        grant = RefGrant(
            auth_id=gid, tenant=tenant, holder=holder,
            resources=frozenset(resources), actions=frozenset(actions),
            nbf=nbf, exp=exp, parent_id=None, parent_digest=None,
            depth=1, digest=digest,
        )
        self.grants[gid] = grant
        return grant

    def check_delegation_legal(self, parent_id: str, child_holder: str,
                               resources: set[str], actions: set[str],
                               nbf: int, exp: int) -> None:
        """纯校验（不修改模型）：非法即抛 RefViolation。"""
        parent = self.grants.get(parent_id)
        if parent is None:
            raise RefViolation("父授权不存在")
        if parent.auth_id in self.revoked:
            raise RefViolation("父授权已撤销")
        if parent.depth >= MAX_DEPTH:
            raise RefViolation("超过 8 层")
        if not self._is_member(parent.tenant, child_holder):
            raise RefViolation("子持有人不是同租户成员")
        if not resources or not actions:
            raise RefViolation("空集合")
        if not resources <= parent.resources:
            raise RefViolation("资源不是子集")
        if not actions <= parent.actions:
            raise RefViolation("动作不是子集")
        if nbf < parent.nbf or exp > parent.exp:
            raise RefViolation("时间区间不是子集")
        if nbf >= exp:
            raise RefViolation("时间区间非法")
        if any(r not in self.versions for r in resources):
            raise RefViolation("未知资源")
        if not actions <= set(ACTIONS):
            raise RefViolation("非法动作")

    def delegate(self, parent_id: str, child_holder: str,
                 resources: set[str], actions: set[str],
                 nbf: int, exp: int) -> RefGrant:
        self.check_delegation_legal(
            parent_id, child_holder, resources, actions, nbf, exp
        )
        parent = self.grants[parent_id]
        gid = self._next_id()
        digest = f"digest-child:{gid}:of:{parent_id}"
        grant = RefGrant(
            auth_id=gid, tenant=parent.tenant, holder=child_holder,
            resources=frozenset(resources), actions=frozenset(actions),
            nbf=nbf, exp=exp, parent_id=parent.auth_id,
            parent_digest=parent.digest, depth=parent.depth + 1,
            digest=digest,
        )
        self.grants[gid] = grant
        return grant

    def revoke(self, auth_id: str) -> None:
        if auth_id not in self.grants:
            raise RefViolation("撤销目标不存在")
        self.revoked.add(auth_id)  # 幂等

    # ----- 参考版使用判定（全链） --------------------------------------- #
    def _chain(self, auth_id: str) -> list[RefGrant]:
        """根 -> 叶；缺失中间节点直接判非法。"""
        leaf_to_root: list[RefGrant] = []
        cur = self.grants.get(auth_id)
        seen: set[str] = set()
        while cur is not None:
            if cur.auth_id in seen:
                raise RefViolation("链存在环")
            seen.add(cur.auth_id)
            leaf_to_root.append(cur)
            if cur.parent_id is None:
                break
            nxt = self.grants.get(cur.parent_id)
            if nxt is None:
                raise RefViolation("缺失中间节点")
            # 父摘要绑定
            if cur.parent_digest != nxt.digest:
                raise RefViolation("父摘要绑定不匹配")
            if cur.tenant != nxt.tenant:
                raise RefViolation("跨租户链")
            if cur.depth != nxt.depth + 1:
                raise RefViolation("深度不连续")
            cur = nxt
        if not leaf_to_root or leaf_to_root[-1].parent_id is not None:
            raise RefViolation("链未抵达根")
        return list(reversed(leaf_to_root))

    def can_use(self, auth_id: str, caller: str, caller_tenant: str,
                resource_id: str, action: str, now: int) -> bool:
        try:
            chain = self._chain(auth_id)
        except RefViolation:
            return False
        leaf = chain[-1]
        if leaf.holder != caller or leaf.tenant != caller_tenant:
            return False
        for node in chain:
            if node.auth_id in self.revoked:
                return False  # 任一祖先（含自身）撤销 -> 全后代不可用
            if not (node.nbf <= now < node.exp):
                return False  # 过期祖先同样不可用
            if not self._is_member(node.tenant, node.holder):
                return False
        # 逐跳衰减
        for parent, child in zip(chain, chain[1:]):
            if not child.resources <= parent.resources:
                return False
            if not child.actions <= parent.actions:
                return False
            if child.nbf < parent.nbf or child.exp > parent.exp:
                return False
        if resource_id not in leaf.resources:
            return False
        if action not in leaf.actions:
            return False
        if action not in ACTIONS:
            return False
        return True

    def can_write(self, auth_id: str, caller: str, caller_tenant: str,
                  resource_id: str, now: int) -> bool:
        return self.can_use(auth_id, caller, caller_tenant,
                            resource_id, "write", now)

    def increment(self, auth_id: str, caller: str, caller_tenant: str,
                  resource_id: str, now: int) -> bool:
        """受保护写入：只有参考模型判定可写时版本才允许递增。"""
        if not self.can_write(auth_id, caller, caller_tenant,
                              resource_id, now):
            return False
        self.versions[resource_id] += 1
        return True

    def subtree_ids(self, auth_id: str) -> set[str]:
        """撤销影响面：节点本身 + 全部后代。"""
        result = {auth_id}
        changed = True
        while changed:
            changed = False
            for g in self.grants.values():
                if g.parent_id in result and g.auth_id not in result:
                    result.add(g.auth_id)
                    changed = True
        return result
