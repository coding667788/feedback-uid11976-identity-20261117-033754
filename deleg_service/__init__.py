"""本地可衰减委托授权链服务（仅依赖 Python 3.12 标准库 + SQLite）。

模块划分：
- crypto:   严格 JSON 解析、规范摘要、固定 HS256 票据签名/验签
- db:       SQLite 连接、建表、密钥文件管理
- barriers: 跨进程文件屏障（仅测试用可控同步点）
- service:  核心领域逻辑（签发、委托、校验、撤销、版本递增）
- httpapi:  ThreadingHTTPServer 实现的 HTTP 接口
- cli:      初始化与管理命令
"""

__version__ = "1.0.0"
TICKET_VERSION = 1
TICKET_TYP = "DLG-TICKET"
ALG = "HS256"
MAX_DEPTH = 8
VALID_ACTIONS = ("read", "write")
