# collect_ransomware_samples.py
# 稳定版勒索式行为样本采集器
# 通过快照差分统计写入、重命名、删除、高熵等特征
# 输出字段：
# write_count, rename_count, delete_count, setinfo_count, entropy, entropy_risk, label

import argparse
import csv
import math
import os
import time
from collections import Counter
from pathlib import Path


BASE_DIR = Path(r"C:\Users\root\Desktop\Ransomware_Guard")

RANSOM_AREA = BASE_DIR / "sample_workspace" / "ransom_sim_area"
WORK_AREA = RANSOM_AREA / "work_area"
ENCRYPTED_DIR = RANSOM_AREA / "encrypted"

OUTPUT_CSV = BASE_DIR / "data" / "ransomware_samples.csv"

RANSOM_EXTS = [".locked", ".encrypted", ".wncry", ".conti"]

CSV_HEADER = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
    "entropy",
    "entropy_risk",
    "label"
]


def calculate_entropy(file_path: Path, max_bytes=65536):
    """
    计算文件信息熵。
    只读取前 max_bytes，避免大文件拖慢采集。
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)

        if not data:
            return 0.0

        count = Counter(data)
        length = len(data)

        entropy = -sum((v / length) * math.log2(v / length) for v in count.values())
        return round(entropy, 4)

    except Exception:
        return 0.0


def is_ransom_named(path: Path):
    name = path.name.lower()
    return any(name.endswith(ext) for ext in RANSOM_EXTS)


def scan_files():
    """
    扫描 work_area 和 encrypted。
    不扫描 template_files，避免模板文件影响采集。
    """
    files = []

    for root in [WORK_AREA, ENCRYPTED_DIR]:
        root.mkdir(parents=True, exist_ok=True)

        for p in root.rglob("*"):
            if p.is_file():
                try:
                    stat = p.stat()
                    files.append({
                        "path": str(p),
                        "name": p.name,
                        "size": stat.st_size,
                        "mtime_ns": stat.st_mtime_ns,
                        "is_ransom_named": is_ransom_named(p)
                    })
                except Exception:
                    pass

    return files


def build_snapshot(files):
    """
    path -> 文件状态
    """
    return {
        item["path"]: {
            "name": item["name"],
            "size": item["size"],
            "mtime_ns": item["mtime_ns"],
            "is_ransom_named": item["is_ransom_named"]
        }
        for item in files
    }


def collect_window_features(prev_snapshot):
    """
    基于前后快照差分构造一个行为窗口样本。
    """
    current_files = scan_files()
    current_snapshot = build_snapshot(current_files)

    prev_paths = set(prev_snapshot.keys())
    current_paths = set(current_snapshot.keys())

    added_paths = current_paths - prev_paths
    removed_paths = prev_paths - current_paths
    common_paths = prev_paths & current_paths

    modified_paths = set()

    for path in common_paths:
        old = prev_snapshot[path]
        new = current_snapshot[path]

        if old["size"] != new["size"] or old["mtime_ns"] != new["mtime_ns"]:
            modified_paths.add(path)

    # 新增的勒索扩展名文件通常来自重命名或移动后的结果。
    new_ransom_named_paths = [
        p for p in added_paths
        if current_snapshot[p]["is_ransom_named"]
    ]

    rename_count = len(new_ransom_named_paths)

    # 写入：新增文件 + 修改文件。
    # 但重命名产生的新路径不全部算写入，避免重复放大。
    write_count = len(modified_paths) + max(0, len(added_paths) - rename_count)

    # 删除：路径消失数量扣除重命名造成的旧路径消失。
    delete_count = max(0, len(removed_paths) - rename_count)

    setinfo_count = 0

    changed_paths = list(modified_paths | added_paths)

    entropy_val = 0.0

    # 优先对发生变化的文件计算熵。
    entropy_candidates = [
        Path(p) for p in changed_paths
        if Path(p).exists() and Path(p).is_file()
    ]

    if entropy_candidates:
        entropies = [calculate_entropy(p) for p in entropy_candidates[:10]]
        if entropies:
            entropy_val = round(max(entropies), 4)
    else:
        # 如果本窗口没有变化，不强行取已有文件熵。
        entropy_val = 0.0

    entropy_risk = 1 if entropy_val > 7.5 else 0
    label = 1

    sample = [
        int(write_count),
        int(rename_count),
        int(delete_count),
        int(setinfo_count),
        float(entropy_val),
        int(entropy_risk),
        int(label)
    ]

    return sample, current_snapshot


def is_empty_window(sample):
    """
    判断是否为空窗口。
    空窗口不应进入训练集，否则会污染勒索样本。
    """
    write_count, rename_count, delete_count, setinfo_count, entropy, entropy_risk, label = sample

    return (
        write_count == 0
        and rename_count == 0
        and delete_count == 0
        and setinfo_count == 0
        and entropy == 0.0
        and entropy_risk == 0
    )


def prepare_writer(output_path: Path, append=False):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    file_exists = output_path.exists()
    need_header = True

    if append and file_exists and output_path.stat().st_size > 0:
        need_header = False

    mode = "a" if append else "w"

    f = open(output_path, mode, newline="", encoding="utf-8-sig")
    writer = csv.writer(f)

    if need_header:
        writer.writerow(CSV_HEADER)
        f.flush()
        os.fsync(f.fileno())

    return f, writer


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--target", type=int, default=1000, help="目标有效样本数")
    parser.add_argument("--window", type=float, default=2.0, help="采集窗口秒数")
    parser.add_argument("--output", type=str, default=str(OUTPUT_CSV), help="输出 CSV 文件")
    parser.add_argument("--append", action="store_true", help="追加写入，不覆盖旧文件")
    parser.add_argument("--keep-empty", action="store_true", help="保留空窗口。默认跳过空窗口")

    args = parser.parse_args()

    output_path = Path(args.output)

    print("[+] 勒索式行为采集器启动")
    print(f"[+] 监控目录：{WORK_AREA}")
    print(f"[+] 输出文件：{output_path}")
    print(f"[+] 目标有效样本数：{args.target}")
    print(f"[+] 采集窗口：{args.window} 秒")

    previous_snapshot = build_snapshot(scan_files())

    f, writer = prepare_writer(output_path, append=args.append)

    collected = 0
    skipped_empty = 0

    try:
        while collected < args.target:
            time.sleep(args.window)

            sample, previous_snapshot = collect_window_features(previous_snapshot)

            if is_empty_window(sample) and not args.keep_empty:
                skipped_empty += 1

                if skipped_empty % 20 == 0:
                    print(f"[*] 已跳过空窗口：{skipped_empty}")

                continue

            writer.writerow(sample)

            # 每条样本立即落盘，避免中途停止导致有效数据丢失。
            f.flush()
            os.fsync(f.fileno())

            collected += 1

            if collected % 50 == 0:
                print(f"[+] 已采集有效勒索样本 {collected}/{args.target}，跳过空窗口 {skipped_empty}")

    finally:
        f.close()

    print(f"[+] 采集完成：{output_path}")
    print(f"[+] 有效样本：{collected}")
    print(f"[+] 跳过空窗口：{skipped_empty}")


if __name__ == "__main__":
    main()
