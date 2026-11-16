"""测试总入口。

推荐（隔离模式，防目录内同名文件遮蔽标准库）：
    python -I run_tests.py
可选：
    python -I run_tests.py --verbosity 2
    python -I run_tests.py --pattern test_core_rules.py
"""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

# -I 模式下 sys.path 不含脚本目录，需要显式加入项目根
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbosity", type=int, default=2)
    parser.add_argument("--pattern", default="test_*.py")
    parser.add_argument("--start", default="tests",
                        help="测试发现目录")
    args = parser.parse_args()

    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=str(ROOT / args.start),
        pattern=args.pattern,
        top_level_dir=str(ROOT),
    )
    result = unittest.TextTestRunner(verbosity=args.verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
