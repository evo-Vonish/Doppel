# 测试引导：把 core/ 目录加入 sys.path，使 `import tishen` 在
# 未 pip install 的开发场景（python3 -m pytest core/tests）下也可用。
import sys
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
