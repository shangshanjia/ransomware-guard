# simulate_attack_honey.py：诱饵文件触发测试脚本
# 作用：直接篡改系统部署的诱饵文件，用于演示动态诱饵文件防御模块

import os
import stat
import time
import subprocess
from pathlib import Path

target_dir = Path(r"C:\Users\root\Desktop\Ransomware_Guard\test_data")

# 等待 main.py 完成诱饵文件部署，并避开 main.py 中的 2 秒保护窗口
time.sleep(3)

# 查找系统自动部署的诱饵文件
traps = [
    p for p in target_dir.iterdir()
    if p.name.startswith("_财务备份_")
]

if not traps:
    print("[诱饵测试] 未找到诱饵文件，请确认 main.py 已启动并完成诱饵部署。")
    time.sleep(10)
    exit()

trap = traps[0]
print(f"[诱饵测试] 已找到诱饵文件：{trap.name}")

# 清除隐藏、系统、只读属性，避免 Permission denied
subprocess.run(
    ["attrib", "-h", "-s", "-r", str(trap)],
    shell=True,
    capture_output=True,
    text=True
)

try:
    os.chmod(trap, stat.S_IWRITE | stat.S_IREAD)
except Exception:
    pass

# 直接修改原诱饵文件内容，不改变文件名
# 这样 main.py 捕获到的路径仍然是原诱饵文件路径，更容易触发 honeyfile 检测
try:
    with open(trap, "wb") as f:
        f.write(os.urandom(4096))

    print(f"[诱饵测试] 已篡改诱饵文件：{trap.name}")

except PermissionError as e:
    print(f"[诱饵测试] 权限不足，无法写入诱饵文件：{trap}")
    print(e)

# 保持进程存活，便于 main.py 的 precision_traceback 定位 PID
time.sleep(10)
