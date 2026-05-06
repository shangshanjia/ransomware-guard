# collect_ransomware_samples.py
# 用于采集升级版勒索模拟行为特征
# 输出 CSV 文件，特征：write_count, rename_count, delete_count, setinfo_count, entropy, entropy_risk, label

import os
import csv
import time
from pathlib import Path
from collections import Counter
import math

RANSOM_AREA = r"C:\Users\root\Desktop\Ransomware_Guard\sample_workspace\ransom_sim_area"
OUTPUT_CSV = r"C:\Users\root\Desktop\Ransomware_Guard\data\ransomware_samples.csv"

def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        count = Counter(data)
        ent = -sum((v/len(data))*math.log2(v/len(data)) for v in count.values())
        return round(ent, 4)
    except Exception:
        return 0.0

def collect_window_features():
    files = [p for p in Path(RANSOM_AREA).rglob("*") if p.is_file()]

    write_count = len(files)
    rename_count = sum(1 for f in files if f.suffix in ['.locked', '.encrypted', '.wncry', '.conti'])
    delete_count = 0  # 真实删除操作只能通过跟踪窗口事件，这里暂置为0
    setinfo_count = 0

    entropy_val = calculate_entropy(files[-1]) if files else 0.0
    entropy_risk = 1 if entropy_val > 7.5 else 0
    label = 1  # 勒索样本

    return [write_count, rename_count, delete_count, setinfo_count, entropy_val, entropy_risk, label]

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=int, default=1000, help="采集目标样本数")
    parser.add_argument("--window", type=int, default=3, help="采集窗口秒数")
    parser.add_argument("--output", type=str, default=OUTPUT_CSV)
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["write_count","rename_count","delete_count","setinfo_count","entropy","entropy_risk","label"])

        collected = 0
        while collected < args.target:
            time.sleep(args.window)
            sample = collect_window_features()
            writer.writerow(sample)
            collected += 1
            if collected % 50 == 0:
                print(f"[+] 已采集 {collected}/{args.target} 条勒索样本")

    print(f"[+] 勒索样本采集完成，输出: {args.output}")

if __name__ == "__main__":
    main()
