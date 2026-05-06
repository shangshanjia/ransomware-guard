# simulate_ransomware_behavior.py
# 安全版勒索行为模拟器（升级版）
# 特性：
# 1. 批量文件处理
# 2. 多模式行为（覆盖、重命名、删除、移动）
# 3. 高频高熵操作
# 4. 文件扩展名模拟真实勒索（.locked/.encrypted/.conti）
# 5. 操作在 ransom_sim_area 内，不影响系统

import os
import random
import time
import shutil
from pathlib import Path

BASE_DIR = r"C:\Users\root\Desktop\Ransomware_Guard"
RANSOM_AREA = os.path.join(BASE_DIR, "sample_workspace", "ransom_sim_area")
ENCRYPTED_DIR = os.path.join(RANSOM_AREA, "encrypted")
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

EXT_LOCKED = ['.locked', '.encrypted', '.wncry', '.conti']

def list_files():
    return [p for p in Path(RANSOM_AREA).rglob("*") if p.is_file()]

def batch_overwrite(files):
    for f in files:
        size = random.randint(4*1024, 256*1024)
        try:
            with open(f, "wb") as file:
                file.write(os.urandom(size))
        except Exception:
            pass

def batch_rename(files):
    for f in files:
        ext = random.choice(EXT_LOCKED)
        try:
            f.rename(f.with_name(f"{f.stem}{ext}"))
        except Exception:
            pass

def batch_delete(files):
    for f in files:
        try:
            os.remove(f)
        except Exception:
            pass

def batch_move(files):
    for f in files:
        try:
            shutil.move(str(f), ENCRYPTED_DIR)
        except Exception:
            pass

def simulate_one_action():
    all_files = list_files()
    if not all_files:
        return

    mode = random.choices(
        ['overwrite','rename','delete','move','mixed'],
        weights=[3,3,2,2,1], k=1)[0]

    # 随机选择 5~30 个文件一次性处理
    files = random.sample(all_files, min(len(all_files), random.randint(5,30)))

    if mode == 'overwrite':
        batch_overwrite(files)
    elif mode == 'rename':
        batch_rename(files)
    elif mode == 'delete':
        batch_delete(files)
    elif mode == 'move':
        batch_move(files)
    else:  # mixed
        batch_overwrite(files)
        batch_rename(files)
        batch_move(files)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--actions', type=int, default=8000, help="操作次数")
    parser.add_argument('--sleep', type=float, default=0.05, help="操作间隔秒")
    args = parser.parse_args()

    print("[+] 开始升级版勒索行为模拟器")
    for i in range(args.actions):
        simulate_one_action()
        if (i+1) % 100 == 0:
            print(f"[RANSOM] 已执行 {i+1}/{args.actions} 操作")
        time.sleep(random.uniform(args.sleep*0.5, args.sleep*1.5))  # 随机化操作节奏
    print("[+] 模拟勒索行为完成")

if __name__ == "__main__":
    main()
