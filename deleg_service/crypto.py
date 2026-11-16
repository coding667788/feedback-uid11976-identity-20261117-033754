"""票据密码学：严格 JSON 解析、规范内容摘要、固定 HS256 签名/验签。

设计约束（对应题目第 1 点）：
- 只接受 HS256，header 中出现其他算法 / 未知版本 / 未知字段一律拒绝；
- JSON 解析拒绝重复成员键、拒绝非对象顶层结构；
- 签名密钥仅由服务端持有，调用方永远拿不到密钥；
- 摘要对“规范 JSON”（键排序、无多余空白）取 SHA-256，
  使集合顺序、空白差异无法改变或伪装票据含义。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from .errors import (
    ERR_BAD_ENCODING,
    ERR_BAD_FIELD_TYPE,
    ERR_BAD_SIGNATURE,
    ERR_DUPLICATE_KEY,
    ERR_MALFORMED,
    ERR_UNKNOWN_ALG,
    ERR_UNKNOWN_FIELD,
    ERR_UNKNOWN_VERSION,
    ServiceError,
)
from . import ALG, TICKET_TYP, TICKET_VERSION

_HEADER_KEYS = frozenset(("alg", "typ", "ver"))
_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
)


class _RejectDuplicates(json.JSONDecoder):
    """object_pairs_hook 钩子：同一对象内出现重复键直接报错。"""

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._hook)

    @staticmethod
    def _hook(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise ServiceError(
                    ERR_DUPLICATE_KEY, f"JSON 对象存在重复键: {key!r}"
                )
            seen.add(key)
        return dict(pairs)


def strict_json_loads(raw: bytes | str):
    """严格解析 JSON：拒绝重复键；任何语法错误统一记为 ERR_MALFORMED。"""
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw, cls=_RejectDuplicates)
    except ServiceError:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise ServiceError(ERR_MALFORMED, f"JSON 解析失败: {exc}") from exc


def canonical_digest(payload: dict) -> str:
    """对票据 payload 计算不可变内容摘要（SHA-256 hex）。

    先把集合字段归一化为排序数组，再以 sort_keys + 紧凑分隔符序列化，
    保证同一逻辑内容只有唯一字节序列——集合顺序、空白差异无法改变
    或伪装票据含义，“乱序链条改变含义”的攻击因此不成立。
    """
    normalized = dict(payload)
    for field in ("resources", "actions"):
        if field in normalized and isinstance(normalized[field], list):
            normalized[field] = sorted(normalized[field])
    canonical = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode_strict(segment: str) -> bytes:
    """严格 base64url 解码：拒绝非字母表字符（含标准 base64 的 + /）。"""
    if not segment or any(ch not in _B64URL_ALPHABET for ch in segment):
        raise ServiceError(ERR_BAD_ENCODING, "票据段不是合法 base64url")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # 理论上字母表检查后不会发生，仍按默认拒绝处理
        raise ServiceError(ERR_BAD_ENCODING, f"base64url 解码失败: {exc}") from exc


def _build_header() -> dict:
    return {"alg": ALG, "typ": TICKET_TYP, "ver": TICKET_VERSION}


def sign_ticket(payload: dict, key: bytes) -> str:
    """用服务端密钥签发 HS256 票据，返回 header.payload.signature。"""
    header_b = json.dumps(_build_header(), separators=(",", ":")).encode("utf-8")
    payload_b = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signing_input = b64url_encode(header_b) + "." + b64url_encode(payload_b)
    sig = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + b64url_encode(sig)


def _validate_header(header: dict) -> None:
    if not isinstance(header, dict):
        raise ServiceError(ERR_MALFORMED, "票据 header 必须是 JSON 对象")
    if set(header.keys()) != _HEADER_KEYS:
        raise ServiceError(ERR_UNKNOWN_FIELD, "票据 header 字段集合不合法")
    if type(header["alg"]) is not str or header["alg"] != ALG:
        raise ServiceError(ERR_UNKNOWN_ALG, "只接受固定算法 HS256")
    if type(header["typ"]) is not str or header["typ"] != TICKET_TYP:
        raise ServiceError(ERR_MALFORMED, "票据 typ 不匹配")
    # 明确拒绝未知版本；bool 不是合法 int（type 检查防 True 冒充 1）
    if type(header["ver"]) is not int or header["ver"] != TICKET_VERSION:
        raise ServiceError(ERR_UNKNOWN_VERSION, f"未知票据版本: {header.get('ver')!r}")


def parse_ticket(ticket: str, key: bytes) -> dict:
    """完整验签并返回 payload。任何一步失败都抛 ServiceError（默认拒绝）。

    仅做“结构 + 签名 + header”校验；payload 的业务字段语义由 service 层校验。
    """
    if not isinstance(ticket, str):
        raise ServiceError(ERR_BAD_FIELD_TYPE, "票据必须是字符串")
    parts = ticket.split(".")
    if len(parts) != 3 or not all(parts):
        raise ServiceError(ERR_MALFORMED, "票据必须是 header.payload.signature 三段")
    header_seg, payload_seg, sig_seg = parts

    header = strict_json_loads(b64url_decode_strict(header_seg))
    payload = strict_json_loads(b64url_decode_strict(payload_seg))
    _validate_header(header)
    if not isinstance(payload, dict):
        raise ServiceError(ERR_MALFORMED, "票据 payload 必须是 JSON 对象")

    signing_input = (header_seg + "." + payload_seg).encode("ascii")
    try:
        sig = b64url_decode_strict(sig_seg)
    except ServiceError:
        raise
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ServiceError(ERR_BAD_SIGNATURE, "票据签名校验失败")
    return payload
