"""核心领域服务：授权签发、委托、全链校验、祖先撤销、资源版本递增。

一致性策略（对应题目第 3 点）：
1. 委托 / 受保护写入先在只读快照中完成“祖先检查”，随后在可预测的同步点
   （barriers.wait_at）阻塞；测试端可在此时提交撤销。
2. 服务端被放行后开启 BEGIN IMMEDIATE 写事务，在事务内重新加载并重跑
   整条链的全部校验（含撤销状态）。SQLite 的写锁使撤销与签发/写入串行提交：
   - 撤销先提交 -> 后到的写事务重新校验时必然看到 revoked -> 拒绝；
   - 签发先提交 -> 之后的撤销照常使该新分支失效。
3. check 为只读事务；撤销一旦提交，其后新开始的检查必然读到新状态并拒绝。
4. 只缓存“不可变的签名验证结果”；撤销/时间/成员等动态结论每次查库，绝不缓存。
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time as _time
from functools import lru_cache
from hmac import compare_digest as hmac_compare
from pathlib import Path

from . import MAX_DEPTH, VALID_ACTIONS
from . import barriers, crypto, db as dbmod
from .errors import (
    ERR_BAD_ACTION,
    ERR_BAD_FIELD_TYPE,
    ERR_BAD_TIME,
    ERR_CROSS_TENANT,
    ERR_DEPTH_LIMIT,
    ERR_DUPLICATE_KEY,
    ERR_EMPTY_SET,
    ERR_EXPIRED,
    ERR_FORBIDDEN,
    ERR_HOLDER_MISMATCH,
    ERR_MALFORMED,
    ERR_MISSING_FIELD,
    ERR_MISSING_NODE,
    ERR_NOT_HOLDER,
    ERR_NOT_MEMBER,
    ERR_NOT_SUBSET,
    ERR_NODE_NOT_FOUND,
    ERR_PARENT_BINDING,
    ERR_PARENT_DIGEST_MISMATCH,
    ERR_RESOURCE_MISMATCH,
    ERR_REVOKED,
    ERR_UNAUTHENTICATED,
    ERR_UNKNOWN_FIELD,
    ERR_UNKNOWN_RESOURCE,
    ERR_UNKNOWN_VERSION,
    ServiceError,
)

_ROOT_PAYLOAD_KEYS = frozenset(
    ("v", "auth_id", "tenant", "holder", "resources", "actions", "nbf", "exp")
)
_CHILD_PAYLOAD_KEYS = _ROOT_PAYLOAD_KEYS | frozenset(
    ("parent_id", "parent_digest")
)
_SESSION_TTL_SECONDS = 12 * 3600


# --------------------------------------------------------------------------- #
# 基础类型/结构校验
# --------------------------------------------------------------------------- #
def _require_type(value, expected: type, field: str) -> None:
    # bool 是 int 的子类，语义上必须显式排除（防 True 冒充 1）
    if expected is int and type(value) is bool:
        raise ServiceError(
            ERR_BAD_FIELD_TYPE, f"字段 {field} 不能是布尔值", http_status=400
        )
    if not isinstance(value, expected):
        names = {int: "整数", str: "字符串", list: "数组"}
        raise ServiceError(
            ERR_BAD_FIELD_TYPE,
            f"字段 {field} 必须是 {names.get(expected, expected.__name__)}",
            http_status=400,
        )


def _validate_str_set(value, field: str) -> list[str]:
    _require_type(value, list, field)
    if not value:
        raise ServiceError(ERR_EMPTY_SET, f"字段 {field} 不能为空集", http_status=400)
    result, seen = [], set()
    for item in value:
        if type(item) is not str or not item:
            raise ServiceError(
                ERR_BAD_FIELD_TYPE,
                f"字段 {field} 的成员必须是非空字符串",
                http_status=400,
            )
        if item in seen:
            raise ServiceError(
                ERR_DUPLICATE_KEY,
                f"字段 {field} 存在重复成员 {item!r}",
                http_status=400,
            )
        seen.add(item)
        result.append(item)
    return result


def _validate_actions(actions: list[str]) -> None:
    for a in actions:
        if a not in VALID_ACTIONS:
            raise ServiceError(
                ERR_BAD_ACTION,
                f"未知动作 {a!r}，只允许 {list(VALID_ACTIONS)}",
                http_status=400,
            )


def _validate_time(nbf, exp) -> None:
    _require_type(nbf, int, "nbf")
    _require_type(exp, int, "exp")
    if nbf >= exp:
        raise ServiceError(ERR_BAD_TIME, "要求 nbf < exp", http_status=400)


def _canonical_json_str(values: list[str]) -> str:
    return json.dumps(sorted(values), separators=(",", ":"))


# --------------------------------------------------------------------------- #
# 签名缓存：仅缓存“不可变”的密码学验签结果
# --------------------------------------------------------------------------- #
class _Verifier:
    def __init__(self, key: bytes):
        self._key = key
        self.cache_hits = 0
        self.cache_misses = 0

        @lru_cache(maxsize=4096)
        def _cached(ticket: str) -> dict:
            self.cache_misses += 1
            return crypto.parse_ticket(ticket, self._key)

        self._cached = _cached

    def verify(self, ticket: str) -> dict:
        payload = self._cached(ticket)  # 验签失败抛 ServiceError，不缓存结论以外状态
        self.cache_hits += 1
        return payload

    def cache_info(self) -> dict:
        info = self._cached.cache_info()
        return {
            "verify_calls_hits": self.cache_hits,
            "verify_calls_misses": self.cache_misses,
            "lru_hits": info.hits,
            "lru_misses": info.misses,
            "size": info.currsize,
            "maxsize": info.maxsize,
        }

    def clear_cache(self) -> None:
        self._cached.cache_clear()


# --------------------------------------------------------------------------- #
# 主服务
# --------------------------------------------------------------------------- #
class DelegationService:
    def __init__(self, db_dir: str | Path, key: bytes | None = None):
        self.db_dir = str(db_dir)
        self.key = key if key is not None else dbmod.load_key(db_dir)
        self.verifier = _Verifier(self.key)

    # ----- 连接与审计 ----------------------------------------------------- #
    def _connect(self) -> sqlite3.Connection:
        return dbmod.connect(self.db_dir)

    def _audit(self, conn: sqlite3.Connection, now: int, actor: str,
               action: str, detail: str, auth_id: str | None = None) -> None:
        conn.execute(
            "INSERT INTO audit_log(ts, actor, action, auth_id, detail)"
            " VALUES (?, ?, ?, ?, ?)",
            (now, actor, action, auth_id, detail),
        )

    # ----- 管理类操作（CLI 本地管理员） ----------------------------------- #
    def create_tenant(self, tenant_id: str, name: str, now: int) -> None:
        with self._write_tx() as conn:
            conn.execute(
                "INSERT INTO tenants(tenant_id, name, created_at) VALUES (?, ?, ?)",
                (tenant_id, name, now),
            )

    def create_principal(self, principal_id: str, name: str, now: int) -> None:
        with self._write_tx() as conn:
            conn.execute(
                "INSERT INTO principals(principal_id, name, created_at)"
                " VALUES (?, ?, ?)",
                (principal_id, name, now),
            )

    def add_membership(self, tenant_id: str, principal_id: str) -> None:
        with self._write_tx() as conn:
            self._require_tenant_principal_exist(conn, tenant_id, principal_id)
            conn.execute(
                "INSERT INTO memberships(tenant_id, principal_id, active)"
                " VALUES (?, ?, 1)",
                (tenant_id, principal_id),
            )

    def create_resource(self, resource_id: str, name: str, now: int) -> None:
        with self._write_tx() as conn:
            conn.execute(
                "INSERT INTO resources(resource_id, name, created_at)"
                " VALUES (?, ?, ?)",
                (resource_id, name, now),
            )
            conn.execute(
                "INSERT INTO resource_versions(resource_id, version, updated_at)"
                " VALUES (?, 0, ?)",
                (resource_id, now),
            )

    class _Tx:
        def __init__(self, conn):
            self.conn = conn

        def __enter__(self):
            self.conn.execute("BEGIN IMMEDIATE")
            return self.conn

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
            return False

    def _write_tx(self) -> "DelegationService._Tx":
        return self._Tx(self._connect())

    @staticmethod
    def _require_tenant_principal_exist(
        conn: sqlite3.Connection, tenant_id: str, principal_id: str
    ) -> None:
        if conn.execute(
            "SELECT 1 FROM tenants WHERE tenant_id=?", (tenant_id,)
        ).fetchone() is None:
            raise ServiceError(ERR_FORBIDDEN, f"租户不存在: {tenant_id}", 400)
        if conn.execute(
            "SELECT 1 FROM principals WHERE principal_id=?", (principal_id,)
        ).fetchone() is None:
            raise ServiceError(ERR_FORBIDDEN, f"主体不存在: {principal_id}", 400)

    def _require_active_member(self, conn: sqlite3.Connection,
                               tenant_id: str, principal_id: str) -> None:
        row = conn.execute(
            "SELECT 1 FROM memberships WHERE tenant_id=? AND principal_id=?"
            " AND active=1",
            (tenant_id, principal_id),
        ).fetchone()
        if row is None:
            raise ServiceError(
                ERR_NOT_MEMBER,
                f"主体 {principal_id!r} 不是租户 {tenant_id!r} 的有效成员",
            )

    def _require_known_resources(self, conn: sqlite3.Connection,
                                 resources: list[str]) -> None:
        # 资源是全局预置的有限集合；跨租户隔离通过委托时的租户一致性校验保证
        for rid in resources:
            if conn.execute(
                "SELECT 1 FROM resources WHERE resource_id=?", (rid,)
            ).fetchone() is None:
                raise ServiceError(
                    ERR_UNKNOWN_RESOURCE, f"未知资源: {rid}", http_status=400
                )

    # ----- 登录会话 ------------------------------------------------------- #
    def login(self, tenant_id: str, principal_id: str, now: int) -> str:
        """签发不透明登录令牌；成员关系在签发时确认。"""
        conn = self._connect()
        try:
            self._require_tenant_principal_exist(conn, tenant_id, principal_id)
            self._require_active_member(conn, tenant_id, principal_id)
            token = secrets.token_urlsafe(32)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO sessions(token, tenant_id, principal_id,"
                " created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (token, tenant_id, principal_id, now,
                 now + _SESSION_TTL_SECONDS),
            )
            conn.commit()
            return token
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _authenticate(self, conn: sqlite3.Connection, token: str | None,
                      now: int) -> sqlite3.Row:
        if not token or not isinstance(token, str):
            raise ServiceError(ERR_UNAUTHENTICATED, "缺少登录令牌", 401)
        row = conn.execute(
            "SELECT tenant_id, principal_id, expires_at FROM sessions"
            " WHERE token=?",
            (token,),
        ).fetchone()
        if row is None or now >= row["expires_at"]:
            raise ServiceError(ERR_UNAUTHENTICATED, "登录令牌无效或已过期", 401)
        return row

    # ----- 根授权（管理员，CLI） ------------------------------------------ #
    def create_root_grant(self, tenant_id: str, holder: str,
                          resources: list[str], actions: list[str],
                          nbf: int, exp: int, now: int) -> dict:
        resources = _validate_str_set(resources, "resources")
        actions = _validate_str_set(actions, "actions")
        _validate_actions(actions)
        _validate_time(nbf, exp)

        with self._write_tx() as conn:
            self._require_tenant_principal_exist(conn, tenant_id, holder)
            self._require_active_member(conn, tenant_id, holder)
            self._require_known_resources(conn, resources)

            auth_id = "g_" + secrets.token_hex(16)
            payload = {
                "v": 1,
                "auth_id": auth_id,
                "tenant": tenant_id,
                "holder": holder,
                "resources": sorted(resources),
                "actions": sorted(actions),
                "nbf": nbf,
                "exp": exp,
            }
            self._validate_payload_shape(payload, is_root=True)
            digest = crypto.canonical_digest(payload)
            ticket = crypto.sign_ticket(payload, self.key)
            conn.execute(
                "INSERT INTO auth_grants(auth_id, tenant_id, parent_id,"
                " parent_digest, depth, holder, issuer, resources, actions,"
                " nbf, exp, content_digest, ticket, revoked, created_at)"
                " VALUES (?, ?, NULL, NULL, 1, ?, '__admin__', ?, ?, ?, ?, ?,"
                " ?, 0, ?)",
                (auth_id, tenant_id, holder,
                 _canonical_json_str(resources), _canonical_json_str(actions),
                 nbf, exp, digest, ticket, now),
            )
            self._audit(conn, now, "__admin__", "create_root",
                        f"tenant={tenant_id} holder={holder}", auth_id)
        return {"auth_id": auth_id, "content_digest": digest,
                "ticket": ticket, "depth": 1}

    # ----- payload 结构严格校验 ------------------------------------------- #
    def _validate_payload_shape(self, payload: dict, is_root: bool) -> None:
        if not isinstance(payload, dict):
            raise ServiceError(ERR_MALFORMED, "payload 必须是对象", 400)
        allowed = _ROOT_PAYLOAD_KEYS if is_root else _CHILD_PAYLOAD_KEYS
        keys = set(payload.keys())
        missing = allowed - keys
        if missing:
            raise ServiceError(ERR_MISSING_FIELD,
                               f"缺少字段: {sorted(missing)}", 400)
        unknown = keys - allowed
        if unknown:
            raise ServiceError(ERR_UNKNOWN_FIELD,
                               f"未知字段: {sorted(unknown)}", 400)
        _require_type(payload["v"], int, "v")
        if payload["v"] != 1:
            raise ServiceError(ERR_UNKNOWN_VERSION,
                               f"未知 payload 版本: {payload['v']}", 400)
        for f in ("auth_id", "tenant", "holder"):
            _require_type(payload[f], str, f)
        _validate_str_set(payload["resources"], "resources")
        _validate_str_set(payload["actions"], "actions")
        _validate_actions(payload["actions"])
        _validate_time(payload["nbf"], payload["exp"])
        if not is_root:
            _require_type(payload["parent_id"], str, "parent_id")
            _require_type(payload["parent_digest"], str, "parent_digest")

    # ----- 委托 ----------------------------------------------------------- #
    def delegate(self, token: str | None, parent_ticket: str,
                 child_holder: str, resources: list[str],
                 actions: list[str], nbf: int, exp: int,
                 now: int) -> dict:
        """当前持有人签发子授权。写事务内做最终全量校验。"""
        resources = _validate_str_set(resources, "resources")
        actions = _validate_str_set(actions, "actions")
        _validate_actions(actions)
        _validate_time(nbf, exp)

        # 1) 只读初校：在写锁之外完成整条祖先链检查
        pre_conn = self._connect()
        try:
            session = self._authenticate(pre_conn, token, now)
            parent_payload = self.verifier.verify(parent_ticket)
            self._validate_payload_shape(
                parent_payload, is_root="parent_id" not in parent_payload
            )
            parent_row = self._load_grant_for_ticket(
                pre_conn, parent_ticket, parent_payload
            )
            chain = self._load_and_check_chain(
                pre_conn, parent_row, now,
                expected_holder=session["principal_id"],
                expected_tenant=session["tenant_id"],
            )
            parent = chain[-1]
            if parent["holder"] != session["principal_id"]:
                raise ServiceError(ERR_NOT_HOLDER, "只有当前持有人可签发子授权")
            if parent["tenant_id"] != session["tenant_id"]:
                raise ServiceError(ERR_CROSS_TENANT, "登录租户与授权租户不一致")
            if parent["depth"] >= MAX_DEPTH:
                raise ServiceError(
                    ERR_DEPTH_LIMIT,
                    f"委托深度上限为 {MAX_DEPTH} 层，不能在第 {parent['depth']} 层下再签",
                )
            self._check_delegation_constraints(
                pre_conn, parent, child_holder, resources, actions, nbf, exp
            )
            parent_id = parent["auth_id"]
        finally:
            pre_conn.close()

        # 2) 可控同步点：祖先检查已完成、写事务尚未开启。竞争测试在此窗口撤销。
        barriers.wait_at(f"delegate:{parent_id}:{child_holder}")

        # 3) 写事务内重新加载、重新全量校验（首提交者获胜的关键）
        with self._write_tx() as conn:
            session2 = self._authenticate(conn, token, now)
            parent_row2 = self._load_grant_for_ticket(
                conn, parent_ticket, parent_payload
            )
            chain2 = self._load_and_check_chain(
                conn, parent_row2, now,
                expected_holder=session2["principal_id"],
                expected_tenant=session2["tenant_id"],
            )
            parent2 = chain2[-1]
            if parent2["depth"] >= MAX_DEPTH:
                raise ServiceError(
                    ERR_DEPTH_LIMIT,
                    f"委托深度上限为 {MAX_DEPTH} 层",
                )
            self._check_delegation_constraints(
                conn, parent2, child_holder, resources, actions, nbf, exp
            )

            auth_id = "g_" + secrets.token_hex(16)
            child_payload = {
                "v": 1,
                "auth_id": auth_id,
                "tenant": parent2["tenant_id"],
                "holder": child_holder,
                "resources": sorted(resources),
                "actions": sorted(actions),
                "nbf": nbf,
                "exp": exp,
                "parent_id": parent2["auth_id"],
                "parent_digest": parent2["content_digest"],
            }
            self._validate_payload_shape(child_payload, is_root=False)
            digest = crypto.canonical_digest(child_payload)
            ticket = crypto.sign_ticket(child_payload, self.key)
            conn.execute(
                "INSERT INTO auth_grants(auth_id, tenant_id, parent_id,"
                " parent_digest, depth, holder, issuer, resources, actions,"
                " nbf, exp, content_digest, ticket, revoked, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (auth_id, parent2["tenant_id"], parent2["auth_id"],
                 parent2["content_digest"], parent2["depth"] + 1, child_holder,
                 session2["principal_id"], _canonical_json_str(resources),
                 _canonical_json_str(actions), nbf, exp, digest, ticket, now),
            )
            self._audit(conn, now, session2["principal_id"], "delegate",
                        f"parent={parent2['auth_id']} child={auth_id}", auth_id)
        return {"auth_id": auth_id, "content_digest": digest, "ticket": ticket,
                "depth": parent2["depth"] + 1, "parent_id": parent2["auth_id"]}

    def _check_delegation_constraints(self, conn: sqlite3.Connection,
                                      parent: sqlite3.Row, child_holder: str,
                                      resources: list[str], actions: list[str],
                                      nbf: int, exp: int) -> None:
        # 子持有人必须是同一租户的有效成员（跨租户委托在此被拦）
        self._require_active_member(conn, parent["tenant_id"], child_holder)
        self._require_known_resources(conn, resources)

        parent_resources = set(json.loads(parent["resources"]))
        parent_actions = set(json.loads(parent["actions"]))
        if not set(resources) <= parent_resources:
            raise ServiceError(
                ERR_NOT_SUBSET,
                f"资源集合不是父授权子集: 越权 "
                f"{sorted(set(resources) - parent_resources)}",
            )
        if not set(actions) <= parent_actions:
            raise ServiceError(
                ERR_NOT_SUBSET,
                f"动作集合不是父授权子集: 越权 "
                f"{sorted(set(actions) - parent_actions)}",
            )
        # 有效时间区间必须是父授权区间的子集
        if nbf < parent["nbf"] or exp > parent["exp"]:
            raise ServiceError(
                ERR_NOT_SUBSET,
                f"时间区间 [{nbf},{exp}) 不是父区间 "
                f"[{parent['nbf']},{parent['exp']}) 的子集",
            )

    # ----- 链条加载与全量校验 --------------------------------------------- #
    def _load_grant(self, conn: sqlite3.Connection, auth_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM auth_grants WHERE auth_id=?", (auth_id,)
        ).fetchone()
        if row is None:
            raise ServiceError(ERR_NODE_NOT_FOUND, f"授权节点不存在: {auth_id}")
        return row

    def _load_grant_for_ticket(self, conn: sqlite3.Connection,
                               ticket: str, payload: dict) -> sqlite3.Row:
        """按票据 auth_id 取库行，并强制出示票据与库内票据逐字节一致。

        攻击者即使持有服务端密钥重签了篡改内容（或拿另一张同 auth_id 的
        伪造票据），也无法通过这道绑定；随后链校验再核对摘要与父子绑定。
        """
        row = self._load_grant(conn, payload["auth_id"])
        if not hmac_compare(row["ticket"], ticket):
            raise ServiceError(
                ERR_PARENT_BINDING,
                "出示票据与库内登记票据不一致（疑似篡改或换票）",
            )
        return row

    def _load_and_check_chain(self, conn: sqlite3.Connection,
                              leaf_row: sqlite3.Row, now: int,
                              expected_holder: str | None = None,
                              expected_tenant: str | None = None
                              ) -> list[sqlite3.Row]:
        """从叶子沿 parent_id 走到根，逐节点全量校验，返回根->叶行列表。

        每节点校验：
        - 票据签名（不可变结果可走缓存）；
        - 票据 payload 与库行完全一致（防库外票据/换票/改内容）；
        - 父子指针与 parent_digest 绑定（防改父、拼接不同父授权）；
        - 深度连续、租户一致、每跳权限衰减；
        - 当前撤销状态（每次查库，绝不缓存）；
        - 当前时间落在 [nbf, exp) 内（过期祖先在此被拦）。
        """
        rows_by_id: dict[str, sqlite3.Row] = {}
        leaf_to_root: list[sqlite3.Row] = []
        current = leaf_row
        guard = 0
        while True:
            guard += 1
            if guard > MAX_DEPTH + 1:
                raise ServiceError(ERR_DEPTH_LIMIT, "授权链超长或存在环")
            if current["auth_id"] in rows_by_id:
                raise ServiceError(ERR_PARENT_BINDING, "授权链存在环")
            rows_by_id[current["auth_id"]] = current
            leaf_to_root.append(current)

            payload = self.verifier.verify(current["ticket"])
            self._assert_row_matches_payload(current, payload)

            # ---- 动态状态：每次实时查库，不允许缓存“未撤销”结论 ----
            if current["revoked"] == 1:
                raise ServiceError(
                    ERR_REVOKED,
                    f"授权 {current['auth_id']} 已撤销，其全部后代不可用",
                )
            if not (current["nbf"] <= now < current["exp"]):
                raise ServiceError(
                    ERR_EXPIRED,
                    f"授权 {current['auth_id']} 不在有效时间区间 "
                    f"[{current['nbf']},{current['exp']})，当前 {now}",
                )
            if expected_tenant is not None \
                    and current["tenant_id"] != expected_tenant:
                raise ServiceError(ERR_CROSS_TENANT, "链条中存在跨租户节点")

            if current["parent_id"] is None:
                if current["depth"] != 1:
                    raise ServiceError(ERR_PARENT_BINDING, "根节点深度必须为 1")
                break

            parent = conn.execute(
                "SELECT * FROM auth_grants WHERE auth_id=?",
                (current["parent_id"],),
            ).fetchone()
            if parent is None:
                # 缺失中间节点：无法证明链条合法，默认拒绝
                raise ServiceError(
                    ERR_MISSING_NODE,
                    f"授权 {current['auth_id']} 的父节点 "
                    f"{current['parent_id']} 缺失",
                )
            # 显式父绑定：票据中的父 ID/摘要必须与库行指针一致，
            # 且必须等于父节点不可变内容摘要（父摘要被改/换父节点即拒）
            if payload.get("parent_id") != current["parent_id"]:
                raise ServiceError(ERR_PARENT_BINDING,
                                   "票据 parent_id 与库内绑定不一致")
            if payload.get("parent_digest") != current["parent_digest"]:
                raise ServiceError(ERR_PARENT_DIGEST_MISMATCH,
                                   "票据 parent_digest 与库内绑定不一致")
            if current["parent_digest"] != parent["content_digest"]:
                raise ServiceError(
                    ERR_PARENT_DIGEST_MISMATCH,
                    f"父授权内容摘要不匹配：节点 {current['auth_id']} 绑定的"
                    " 父摘要与父节点当前摘要不同",
                )
            if parent["tenant_id"] != current["tenant_id"]:
                raise ServiceError(ERR_CROSS_TENANT, "父子节点跨租户")
            if parent["depth"] + 1 != current["depth"]:
                raise ServiceError(ERR_PARENT_BINDING, "深度序列不连续")
            # 权限衰减：每一跳都必须是父的子集（资源/动作/时间）
            self._assert_child_subset(parent, current)
            current = parent

        chain = list(reversed(leaf_to_root))  # 根 -> 叶
        if expected_holder is not None and chain[-1]["holder"] != expected_holder:
            raise ServiceError(
                ERR_HOLDER_MISMATCH,
                f"叶子持有人 {chain[-1]['holder']!r} 与登录身份 "
                f"{expected_holder!r} 不一致",
            )
        return chain

    @staticmethod
    def _assert_row_matches_payload(row: sqlite3.Row, payload: dict) -> None:
        if row["auth_id"] != payload["auth_id"]:
            raise ServiceError(ERR_PARENT_BINDING, "票据 auth_id 与库行不一致")
        if row["tenant_id"] != payload["tenant"]:
            raise ServiceError(ERR_CROSS_TENANT, "票据租户与库行不一致")
        if row["holder"] != payload["holder"]:
            raise ServiceError(ERR_HOLDER_MISMATCH, "票据持有人与库行不一致")
        if json.loads(row["resources"]) != sorted(payload["resources"]):
            raise ServiceError(ERR_NOT_SUBSET, "票据资源与库行不一致")
        if json.loads(row["actions"]) != sorted(payload["actions"]):
            raise ServiceError(ERR_NOT_SUBSET, "票据动作与库行不一致")
        if row["nbf"] != payload["nbf"] or row["exp"] != payload["exp"]:
            raise ServiceError(ERR_BAD_TIME, "票据时间与库行不一致")
        if row["parent_id"] != payload.get("parent_id"):
            raise ServiceError(ERR_PARENT_BINDING, "票据父绑定与库行不一致")
        if row["parent_digest"] != payload.get("parent_digest"):
            raise ServiceError(ERR_PARENT_DIGEST_MISMATCH,
                               "票据父摘要与库行不一致")
        if crypto.canonical_digest(payload) != row["content_digest"]:
            raise ServiceError(ERR_PARENT_DIGEST_MISMATCH,
                               "票据内容摘要与库行不一致")

    @staticmethod
    def _assert_child_subset(parent: sqlite3.Row, child: sqlite3.Row) -> None:
        p_res = set(json.loads(parent["resources"]))
        c_res = set(json.loads(child["resources"]))
        p_act = set(json.loads(parent["actions"]))
        c_act = set(json.loads(child["actions"]))
        if not c_res <= p_res:
            raise ServiceError(ERR_NOT_SUBSET, "资源衰减校验失败")
        if not c_act <= p_act:
            raise ServiceError(ERR_NOT_SUBSET, "动作衰减校验失败")
        if child["nbf"] < parent["nbf"] or child["exp"] > parent["exp"]:
            raise ServiceError(ERR_NOT_SUBSET, "时间区间衰减校验失败")

    # ----- 使用授权：check ------------------------------------------------ #
    def check(self, token: str | None, ticket: str, resource_id: str,
              action: str, now: int) -> dict:
        """只读校验：身份一致 + 全链合法 + 票据覆盖该资源/动作。默认拒绝。"""
        if type(resource_id) is not str or not resource_id:
            raise ServiceError(ERR_RESOURCE_MISMATCH, "resource_id 非法", 400)
        if action not in VALID_ACTIONS:
            raise ServiceError(ERR_BAD_ACTION,
                               f"动作只允许 {list(VALID_ACTIONS)}", 400)
        conn = self._connect()
        try:
            conn.execute("BEGIN")  # 只读快照事务
            session = self._authenticate(conn, token, now)
            payload = self.verifier.verify(ticket)
            self._validate_payload_shape(
                payload, is_root="parent_id" not in payload
            )
            leaf = self._load_grant_for_ticket(conn, ticket, payload)
            chain = self._load_and_check_chain(
                conn, leaf, now,
                expected_holder=session["principal_id"],
                expected_tenant=session["tenant_id"],
            )
            leaf_row = chain[-1]
            covered_resources = set(json.loads(leaf_row["resources"]))
            covered_actions = set(json.loads(leaf_row["actions"]))
            if resource_id not in covered_resources:
                raise ServiceError(
                    ERR_RESOURCE_MISMATCH, f"叶子授权不覆盖资源 {resource_id!r}"
                )
            if action not in covered_actions:
                raise ServiceError(
                    ERR_NOT_SUBSET, f"叶子授权不覆盖动作 {action!r}"
                )
            conn.commit()
            return {
                "allowed": True,
                "auth_id": leaf_row["auth_id"],
                "tenant": leaf_row["tenant_id"],
                "holder": leaf_row["holder"],
                "depth": leaf_row["depth"],
                "resource": resource_id,
                "action": action,
                "root_id": chain[0]["auth_id"],
                "chain_ids": [r["auth_id"] for r in chain],
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ----- 撤销 ----------------------------------------------------------- #
    def revoke(self, token: str | None, auth_id: str, now: int,
               admin: bool = False) -> dict:
        """撤销节点：其整棵子树即刻不可用。幂等。

        权限：管理员（CLI, admin=True）可撤销任意节点；HTTP 调用者须为
        节点持有人或其签发者，且属于同一租户。
        """
        with self._write_tx() as conn:
            row = self._load_grant(conn, auth_id)
            actor = "__admin__"
            if not admin:
                session = self._authenticate(conn, token, now)
                actor = session["principal_id"]
                if session["tenant_id"] != row["tenant_id"]:
                    raise ServiceError(ERR_CROSS_TENANT,
                                       "不能撤销其他租户的授权")
                if actor not in (row["holder"], row["issuer"]):
                    raise ServiceError(
                        ERR_FORBIDDEN,
                        "只有持有人、签发者或管理员可撤销该授权",
                    )
            already = row["revoked"] == 1
            if not already:
                conn.execute(
                    "UPDATE auth_grants SET revoked=1, revoked_at=?, revoked_by=?"
                    " WHERE auth_id=? AND revoked=0",
                    (now, actor, auth_id),
                )
            self._audit(conn, now, actor,
                        "revoke_idempotent" if already else "revoke",
                        f"auth_id={auth_id}", auth_id)
        return {"auth_id": auth_id, "revoked": True,
                "already_revoked": already}

    # ----- 受保护资源版本递增 --------------------------------------------- #
    def increment_version(self, token: str | None, ticket: str,
                          resource_id: str, now: int) -> dict:
        """受保护写入：叶子授权须对该资源具备 write，且全链当前有效。

        与 delegate 相同的同步点 + 写事务内二次校验模式，
        保证“撤销先提交则写入必被拒；写入先提交则版本号真实递增”。
        """
        if type(resource_id) is not str or not resource_id:
            raise ServiceError(ERR_RESOURCE_MISMATCH, "resource_id 非法", 400)

        pre_conn = self._connect()
        try:
            session = self._authenticate(pre_conn, token, now)
            payload = self.verifier.verify(ticket)
            self._validate_payload_shape(
                payload, is_root="parent_id" not in payload
            )
            leaf = self._load_grant_for_ticket(pre_conn, ticket, payload)
            chain = self._load_and_check_chain(
                pre_conn, leaf, now,
                expected_holder=session["principal_id"],
                expected_tenant=session["tenant_id"],
            )
            self._assert_write_covered(chain[-1], resource_id)
            leaf_id = chain[-1]["auth_id"]
        finally:
            pre_conn.close()

        barriers.wait_at(f"incr:{leaf_id}:{resource_id}")

        with self._write_tx() as conn:
            session2 = self._authenticate(conn, token, now)
            leaf2 = self._load_grant_for_ticket(conn, ticket, payload)
            chain2 = self._load_and_check_chain(
                conn, leaf2, now,
                expected_holder=session2["principal_id"],
                expected_tenant=session2["tenant_id"],
            )
            self._assert_write_covered(chain2[-1], resource_id)
            cur = conn.execute(
                "SELECT version FROM resource_versions WHERE resource_id=?",
                (resource_id,),
            ).fetchone()
            if cur is None:
                raise ServiceError(ERR_UNKNOWN_RESOURCE,
                                   f"未知资源: {resource_id}")
            new_version = cur["version"] + 1
            conn.execute(
                "UPDATE resource_versions SET version=?, updated_at=?"
                " WHERE resource_id=?",
                (new_version, now, resource_id),
            )
            self._audit(conn, now, session2["principal_id"], "increment",
                        f"resource={resource_id} v{new_version}",
                        chain2[-1]["auth_id"])
        return {"resource": resource_id, "version": new_version,
                "auth_id": chain2[-1]["auth_id"]}

    @staticmethod
    def _assert_write_covered(leaf_row: sqlite3.Row, resource_id: str) -> None:
        if resource_id not in set(json.loads(leaf_row["resources"])):
            raise ServiceError(ERR_RESOURCE_MISMATCH,
                               f"叶子授权不覆盖资源 {resource_id!r}")
        if "write" not in set(json.loads(leaf_row["actions"])):
            raise ServiceError(ERR_NOT_SUBSET, "叶子授权不含 write 动作")

    # ----- 查询接口 ------------------------------------------------------- #
    def get_version(self, resource_id: str) -> dict:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT version, updated_at FROM resource_versions"
                " WHERE resource_id=?",
                (resource_id,),
            ).fetchone()
            if row is None:
                raise ServiceError(ERR_UNKNOWN_RESOURCE,
                                   f"未知资源: {resource_id}", 404)
            return {"resource": resource_id, "version": row["version"],
                    "updated_at": row["updated_at"]}
        finally:
            conn.close()

    def get_grant(self, auth_id: str) -> dict:
        """管理/排障：返回节点原始状态与链路径；即使已撤销也能展示。"""
        conn = self._connect()
        try:
            row = self._load_grant(conn, auth_id)
            # 结构走链（不触发撤销/时间拒绝），用于展示链路径
            chain_ids = self._walk_chain_ids(conn, row)
            return {
                "auth_id": row["auth_id"],
                "tenant": row["tenant_id"],
                "parent_id": row["parent_id"],
                "parent_digest": row["parent_digest"],
                "depth": row["depth"],
                "holder": row["holder"],
                "issuer": row["issuer"],
                "resources": json.loads(row["resources"]),
                "actions": json.loads(row["actions"]),
                "nbf": row["nbf"],
                "exp": row["exp"],
                "content_digest": row["content_digest"],
                "revoked": bool(row["revoked"]),
                "revoked_at": row["revoked_at"],
                "revoked_by": row["revoked_by"],
                "chain_ids": chain_ids,
            }
        finally:
            conn.close()

    def _walk_chain_ids(self, conn: sqlite3.Connection,
                        leaf_row: sqlite3.Row) -> list[str]:
        ids, current, seen = [], leaf_row, set()
        while True:
            if current["auth_id"] in seen:
                raise ServiceError(ERR_PARENT_BINDING, "授权链存在环")
            seen.add(current["auth_id"])
            ids.append(current["auth_id"])
            if current["parent_id"] is None:
                break
            parent = conn.execute(
                "SELECT * FROM auth_grants WHERE auth_id=?",
                (current["parent_id"],),
            ).fetchone()
            if parent is None:
                ids.append(f"<missing:{current['parent_id']}>")
                break
            current = parent
        ids.reverse()
        return ids


def now_epoch() -> int:
    return int(_time.time())
