"""跨进程文件屏障：为竞争测试提供“可控同步点”。

仅当环境变量 DELEG_BARRIER_DIR 指向一个目录时启用；未设置时所有钩子为空操作，
因此生产运行路径完全不受影响。

显式布防协议（文件即信号，文件名经 Windows 安全转义）：
- 测试端 arm(name)：创建 <name>.arm，表示“该操作到达同步点时必须阻塞”；
- 服务端 wait_at(name)：未布防则直接通过；已布防则原子创建 <name>.wait，
  然后轮询等待 <name>.release；
- 测试端 wait_for(name)：等 <name>.wait 出现，确认服务端已到达同步点；
- 测试端 release(name)：创建 <name>.release，放行服务端；
- reset/reset_all：清理三类信号文件。

未布防的操作零阻塞，因此同一集群里的普通请求不受竞争测试影响。
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .errors import ERR_BARRIER_TIMEOUT, ServiceError

_POLL_INTERVAL = 0.02
# Windows 文件名非法字符统一转义，冒号也在其中
_BAD_CHARS = '<>:"/\\|?*'


def _sanitize(name: str) -> str:
    out = []
    for ch in name:
        if ch in _BAD_CHARS or ord(ch) < 32:
            out.append(f"_{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def barrier_dir() -> Path | None:
    raw = os.environ.get("DELEG_BARRIER_DIR")
    return Path(raw) if raw else None


def _files(name: str) -> tuple[Path, Path, Path]:
    base = barrier_dir()
    assert base is not None
    safe = _sanitize(name)
    return base / f"{safe}.arm", base / f"{safe}.wait", base / f"{safe}.release"


def enabled() -> bool:
    return barrier_dir() is not None


def arm(name: str) -> None:
    """测试端：对指定同步点布防（服务端到达时将阻塞）。"""
    base = barrier_dir()
    if base is None:
        raise RuntimeError("DELEG_BARRIER_DIR 未设置，屏障不可用")
    arm_file, _, _ = _files(name)
    arm_file.touch()


def wait_at(name: str, timeout: float = 20.0) -> None:
    """服务端在同步点阻塞：仅当测试端已 arm 时才等待，否则直接通过。"""
    base = barrier_dir()
    if base is None:
        return
    arm_file, wait_file, release_file = _files(name)
    if not arm_file.exists():
        return  # 未布防：生产/普通请求路径零影响
    try:
        with open(wait_file, "x"):
            pass
    except FileExistsError:
        pass  # 重入：视为已到达
    deadline = time.monotonic() + timeout
    while not release_file.exists():
        if time.monotonic() > deadline:
            raise ServiceError(
                ERR_BARRIER_TIMEOUT, f"等待屏障 {name!r} 超时", http_status=500
            )
        time.sleep(_POLL_INTERVAL)


def wait_for(name: str, timeout: float = 20.0) -> None:
    """测试端：等待服务端到达同步点。"""
    base = barrier_dir()
    if base is None:
        raise RuntimeError("DELEG_BARRIER_DIR 未设置，屏障不可用")
    _, wait_file, _ = _files(name)
    deadline = time.monotonic() + timeout
    while not wait_file.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"服务端未在 {timeout}s 内到达屏障 {name!r}")
        time.sleep(_POLL_INTERVAL)


def release(name: str) -> None:
    """测试端：放行阻塞在同步点的服务端。"""
    base = barrier_dir()
    if base is None:
        raise RuntimeError("DELEG_BARRIER_DIR 未设置，屏障不可用")
    _, _, release_file = _files(name)
    release_file.touch()


def reset(name: str) -> None:
    base = barrier_dir()
    if base is None:
        return
    for f in _files(name):
        try:
            f.unlink()
        except FileNotFoundError:
            pass


def reset_all() -> None:
    base = barrier_dir()
    if base is None:
        return
    for suffix in (".arm", ".wait", ".release"):
        for f in base.glob(f"*{suffix}"):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
