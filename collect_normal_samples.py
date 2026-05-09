# collect_normal_samples.py
# 功能：监听 normal_area 目录中的真实正常文件操作，并按时间窗口保存为训练样本 label=0

import os
import time
import math
import csv
import argparse
from collections import deque

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


BASE_DIR = r"C:\Users\root\Desktop\Ransomware_Guard"
DEFAULT_WATCH_DIR = os.path.join(BASE_DIR, "sample_workspace", "normal_area")
DEFAULT_OUTPUT = os.path.join(BASE_DIR, "data", "normal_samples.csv")

FEATURE_COLUMNS = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
    "entropy",
    "entropy_risk",
    "label"
]


def calculate_entropy(file_path, max_read_size=1024 * 1024):
    """
    计算文件 Shannon 信息熵。
    只读取前 1MB，避免大文件导致采集开销过高。
    """
    if not file_path:
        return 0.0

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return 0.0

    try:
        with open(file_path, "rb") as f:
            data = f.read(max_read_size)

        if not data:
            return 0.0

        counts = [0] * 256
        for b in data:
            counts[b] += 1

        entropy = 0.0
        length = len(data)

        for count in counts:
            if count:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    except Exception:
        return 0.0


def ensure_workspace():
    """
    自动创建正常样本采集目录。
    """
    dirs = [
        DEFAULT_WATCH_DIR,
        os.path.join(DEFAULT_WATCH_DIR, "docs"),
        os.path.join(DEFAULT_WATCH_DIR, "images"),
        os.path.join(DEFAULT_WATCH_DIR, "archives"),
        os.path.join(DEFAULT_WATCH_DIR, "temp"),
        os.path.join(BASE_DIR, "data"),
    ]

    for d in dirs:
        os.makedirs(d, exist_ok=True)


def ensure_csv(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_COLUMNS)


def is_ignored_file(path):
    """
    过滤临时文件、系统文件和无意义文件。
    """
    if not path:
        return True

    name = os.path.basename(path).lower()

    ignored_prefixes = ["~$", "."]
    ignored_suffixes = [".tmp", ".part", ".crdownload", ".lnk"]

    if any(name.startswith(prefix) for prefix in ignored_prefixes):
        return True

    if any(name.endswith(suffix) for suffix in ignored_suffixes):
        return True

    return False


class NormalSampleHandler(FileSystemEventHandler):
    def __init__(self):
        self.events = deque()
        self.last_file = None

    def on_created(self, event):
        if not event.is_directory and not is_ignored_file(event.src_path):
            self.events.append(("write", event.src_path))
            self.last_file = event.src_path

    def on_modified(self, event):
        if not event.is_directory and not is_ignored_file(event.src_path):
            self.events.append(("write", event.src_path))
            self.last_file = event.src_path

    def on_deleted(self, event):
        if not event.is_directory and not is_ignored_file(event.src_path):
            self.events.append(("delete", event.src_path))
            self.last_file = event.src_path

    def on_moved(self, event):
        if not event.is_directory and not is_ignored_file(event.dest_path):
            self.events.append(("rename", event.dest_path))
            self.last_file = event.dest_path

    def collect_window_features(self):
        write_count = 0
        rename_count = 0
        delete_count = 0
        setinfo_count = 0

        while self.events:
            op, path = self.events.popleft()

            if op == "write":
                write_count += 1
            elif op == "rename":
                rename_count += 1
            elif op == "delete":
                delete_count += 1
            elif op == "setinfo":
                setinfo_count += 1

        entropy = calculate_entropy(self.last_file)
        entropy_risk = 1 if entropy > 7.5 else 0

        return [
            write_count,
            rename_count,
            delete_count,
            setinfo_count,
            entropy,
            entropy_risk,
            0
        ]


def main():
    parser = argparse.ArgumentParser(description="正常样本采集脚本")
    parser.add_argument("--watch_dir", default=DEFAULT_WATCH_DIR, help="监听目录")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="输出CSV路径")
    parser.add_argument("--window", type=int, default=3, help="统计窗口，单位秒")
    parser.add_argument("--target", type=int, default=1000, help="目标采集样本数")
    parser.add_argument("--duration", type=int, default=7200, help="最长采集时长，单位秒")
    args = parser.parse_args()

    ensure_workspace()
    ensure_csv(args.output)

    handler = NormalSampleHandler()
    observer = Observer()
    observer.schedule(handler, args.watch_dir, recursive=True)
    observer.start()

    print("[+] 正常样本采集器已启动")
    print(f"[+] 监听目录：{args.watch_dir}")
    print(f"[+] 输出文件：{args.output}")
    print(f"[+] 时间窗口：{args.window} 秒")
    print(f"[+] 目标样本数：{args.target}")
    print("[+] 请同时运行 simulate_normal_behavior.py，或手动进行正常文件操作")

    collected = 0
    start = time.time()

    try:
        while collected < args.target and time.time() - start < args.duration:
            time.sleep(args.window)

            row = handler.collect_window_features()

            # 空窗口不记录
            if sum(row[:4]) == 0:
                continue

            with open(args.output, "a", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(row)

            collected += 1
            print(f"[NORMAL {collected}/{args.target}] {row}")

    except KeyboardInterrupt:
        print("\n[!] 用户中断采集")

    finally:
        observer.stop()
        observer.join()
        print(f"[+] 正常样本采集结束，共采集 {collected} 条")
        print(f"[+] 保存位置：{args.output}")


if __name__ == "__main__":
    main()
