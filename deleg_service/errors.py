"""统一错误类型与拒绝原因码。

服务遵循“默认拒绝”：任何无法被明确证明合法的请求一律拒绝。
"""


class ServiceError(Exception):
    """业务错误。http_status 给出对应 HTTP 状态码，code 为机器可读原因码。"""

    def __init__(self, code: str, message: str, http_status: int = 403):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


# 原因码集中定义，便于测试与审计对齐
ERR_INTERNAL = "ERR_INTERNAL"
ERR_MALFORMED = "ERR_MALFORMED"                # JSON/请求体格式错误
ERR_UNAUTHENTICATED = "ERR_UNAUTHENTICATED"    # 缺失/失效登录会话
ERR_UNKNOWN_VERSION = "ERR_UNKNOWN_VERSION"    # 票据版本未知
ERR_UNKNOWN_ALG = "ERR_UNKNOWN_ALG"            # 算法不是固定 HS256
ERR_BAD_SIGNATURE = "ERR_BAD_SIGNATURE"
ERR_DUPLICATE_KEY = "ERR_DUPLICATE_KEY"        # JSON 重复键 / 集合重复成员
ERR_BAD_FIELD_TYPE = "ERR_BAD_FIELD_TYPE"
ERR_UNKNOWN_FIELD = "ERR_UNKNOWN_FIELD"
ERR_MISSING_FIELD = "ERR_MISSING_FIELD"
ERR_BAD_ENCODING = "ERR_BAD_ENCODING"
ERR_UNKNOWN_RESOURCE = "ERR_UNKNOWN_RESOURCE"
ERR_BAD_ACTION = "ERR_BAD_ACTION"
ERR_EMPTY_SET = "ERR_EMPTY_SET"
ERR_BAD_TIME = "ERR_BAD_TIME"
ERR_DEPTH_LIMIT = "ERR_DEPTH_LIMIT"
ERR_NOT_MEMBER = "ERR_NOT_MEMBER"              # 持有人不是租户有效成员
ERR_CROSS_TENANT = "ERR_CROSS_TENANT"
ERR_NOT_SUBSET = "ERR_NOT_SUBSET"              # 资源/动作/时间区间不是父授权子集
ERR_PARENT_NOT_FOUND = "ERR_PARENT_NOT_FOUND"
ERR_MISSING_NODE = "ERR_MISSING_NODE"          # 链条中间节点缺失
ERR_PARENT_DIGEST_MISMATCH = "ERR_PARENT_DIGEST_MISMATCH"
ERR_PARENT_BINDING = "ERR_PARENT_BINDING"
ERR_NOT_HOLDER = "ERR_NOT_HOLDER"              # 只有当前持有人可签发子授权
ERR_REVOKED = "ERR_REVOKED"                    # 命中撤销节点（含祖先）
ERR_EXPIRED = "ERR_EXPIRED"                    # 节点不在有效时间区间
ERR_HOLDER_MISMATCH = "ERR_HOLDER_MISMATCH"    # 调用者身份与叶子持有人不一致
ERR_NODE_NOT_FOUND = "ERR_NODE_NOT_FOUND"
ERR_FORBIDDEN = "ERR_FORBIDDEN"
ERR_BARRIER_TIMEOUT = "ERR_BARRIER_TIMEOUT"
ERR_RESOURCE_MISMATCH = "ERR_RESOURCE_MISMATCH"
