# -*- coding: utf-8 -*-

import argparse
import csv
import json
import random
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path


# =========================
# 项目固定路径配置
# =========================

PROJECT_ROOT = Path(r"C:\Users\root\Desktop\Ransomware_Guard")

LOG_FILE = PROJECT_ROOT / "logs" / "alerts.csv"
CONFIG_FILE = PROJECT_ROOT / "config.json"
WATCH_DIR = PROJECT_ROOT / "test_data_blackbox"
HELPER_DIR = PROJECT_ROOT / "blackbox_helpers"


# =========================
# 基础工具函数
# =========================

def ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True)


def clear_watch_dir():
    """
    只清空普通测试文件，不删除诱饵文件。
    原因：main.py 已经运行时，诱饵文件属于受保护对象。
    如果清理脚本删除诱饵文件，main.py 会认为诱饵受损。
    """
    ensure_dir(WATCH_DIR)

    for item in WATCH_DIR.iterdir():
        try:
            # 跳过 main.py 部署的诱饵文件
            if item.is_file() and item.name.startswith("_财务备份_"):
                continue

            if item.is_file() or item.is_symlink():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(str(item), ignore_errors=True)

        except Exception:
            pass


def clear_alert_log():
    ensure_dir(LOG_FILE.parent)
    LOG_FILE.write_text("", encoding="utf-8")


def read_alert_rows():
    """
    读取 alerts.csv。
    每一行视为一次系统告警。
    """
    if not LOG_FILE.exists():
        return []

    rows = []
    with open(str(LOG_FILE), "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                rows.append(row)
    return rows


def sync_config_to_main():
    """
    写入 config.json，让已经手动运行的 main.py 热加载测试目录。
    前提：main.py 从 PROJECT_ROOT 目录启动。
    """
    ensure_dir(WATCH_DIR)

    config = {
        "watch_dirs": [str(WATCH_DIR.resolve())]
    }

    CONFIG_FILE.write_text(
        json.dumps(config, ensure_ascii=False, indent=4),
        encoding="utf-8"
    )

    print("[配置同步] 已写入监控目录到 config.json：{}".format(WATCH_DIR))
    print("[等待] 等待 main.py 热加载配置与部署诱饵文件...")
    time.sleep(5)


def wait_for_alert_since(before_count, timeout):
    """
    等待 timeout 秒，判断 alerts.csv 是否新增告警。
    """
    start = time.time()

    while time.time() - start < timeout:
        current_count = len(read_alert_rows())
        if current_count > before_count:
            return True
        time.sleep(0.3)

    return False


def random_name(prefix, suffix):
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return "{}_{}{}".format(prefix, token, suffix)


def make_helper_script(script_name, content):
    ensure_dir(HELPER_DIR)
    script_path = HELPER_DIR / script_name
    script_path.write_text(content, encoding="utf-8")
    return script_path


def run_child_script(script_path, args):
    """
    异常行为用子进程执行。
    原因：main.py 可能会阻断可疑进程，如果由本测试脚本亲自执行异常行为，
    这个统计脚本可能会被误杀，导致无法输出准确率。
    """
    return subprocess.Popen(
        [sys.executable, str(script_path)] + args,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )


# =========================
# 黑盒测试操作
# =========================

def op_normal_create(index):
    """
    正常文件创建。
    期望：不产生告警。
    """
    file_path = WATCH_DIR / random_name("normal_create", ".txt")
    file_path.write_text(
        "这是正常文件创建测试，第 {} 次。\n".format(index),
        encoding="utf-8"
    )
    time.sleep(0.2)


def op_normal_edit(index):
    """
    正常文件编辑。
    每次测试编辑一个不同文件。
    期望：不产生告警。
    """
    file_path = WATCH_DIR / "normal_edit_target_{}.txt".format(index)

    # 第一步：创建一个普通文本文件
    file_path.write_text(
        "正常编辑测试初始内容，第 {} 个文件。\n".format(index),
        encoding="utf-8"
    )

    time.sleep(0.2)

    # 第二步：模拟用户编辑/保存
    with open(str(file_path), "a", encoding="utf-8") as f:
        f.write("正常追加编辑内容，第 {} 次。\n".format(index))

    time.sleep(0.2)


def op_normal_rename(index):
    """
    正常文件重命名。
    期望：不产生告警。
    """
    src = WATCH_DIR / random_name("normal_rename_src", ".txt")
    dst = WATCH_DIR / random_name("normal_rename_dst", ".txt")

    src.write_text("正常重命名测试内容。\n", encoding="utf-8")
    time.sleep(0.2)
    src.rename(dst)
    time.sleep(0.2)


def op_high_entropy_batch(index):
    """
    高频高熵写入模拟。
    期望：产生告警。

    注意：
    这里只在 test_data_blackbox 下创建随机字节文件，不会加密真实文件。
    """
    helper_code = r'''
import os
import sys
import time
from pathlib import Path

watch_dir = Path(sys.argv[1])
case_index = sys.argv[2]

for i in range(10):
    p1 = watch_dir / "crypt_blackbox_{}_{}.docx".format(case_index, i)
    p2 = watch_dir / "crypt_blackbox_{}_{}.locked".format(case_index, i)

    with open(str(p1), "wb") as f:
        f.write(os.urandom(4096))

    time.sleep(0.08)

    try:
        p1.rename(p2)
    except FileNotFoundError:
        pass

    time.sleep(0.08)

# 保持进程短暂存活，方便 main.py 的 precision_traceback 扫描到该进程
time.sleep(6)
'''

    script_path = make_helper_script("simulate_attack_blackbox.py", helper_code)

    proc = run_child_script(
        script_path,
        [str(WATCH_DIR.resolve()), str(index)]
    )

    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            proc.terminate()
        except Exception:
            pass


def find_honeyfiles():
    """
    查找 main.py 部署的诱饵文件。
    honeyfile_manager.py 中的文件名前缀是 _财务备份_。
    """
    if not WATCH_DIR.exists():
        return []

    honeyfiles = []

    for p in WATCH_DIR.iterdir():
        if p.is_file() and p.name.startswith("_财务备份_"):
            honeyfiles.append(p)

    return honeyfiles


def op_honeyfile_touch(index):
    """
    诱饵文件触碰。
    期望：产生告警。
    """
    honeyfiles = find_honeyfiles()

    if not honeyfiles:
        raise RuntimeError(
            "没有找到诱饵文件。请确认 main.py 已经启动，并且已热加载 test_data_blackbox。"
        )

    target = honeyfiles[index % len(honeyfiles)]

    helper_code = r'''
import sys
import time
from pathlib import Path

target = Path(sys.argv[1])

with open(str(target), "ab") as f:
    f.write(b"\nblackbox honeyfile tamper\n")

# 保持进程短暂存活，方便 main.py 溯源
time.sleep(6)
'''

    script_path = make_helper_script("simulate_attack_honey.py", helper_code)

    proc = run_child_script(
        script_path,
        [str(target.resolve())]
    )

    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            proc.terminate()
        except Exception:
            pass


# =========================
# 测试用例定义
# =========================

TEST_CASES = {
    "normal_create": {
        "desc": "正常文件创建",
        "func": op_normal_create,
        "expected_alert": False,
        "default_count": 20,
        "wait_timeout": 2.0
    },
    "normal_edit": {
        "desc": "正常文件编辑",
        "func": op_normal_edit,
        "expected_alert": False,
        "default_count": 20,
        "wait_timeout": 2.0
    },
    "normal_rename": {
        "desc": "正常文件重命名",
        "func": op_normal_rename,
        "expected_alert": False,
        "default_count": 20,
        "wait_timeout": 2.0
    },
    "high_entropy_batch": {
        "desc": "高频高熵批量写入模拟",
        "func": op_high_entropy_batch,
        "expected_alert": True,
        "default_count": 10,
        "wait_timeout": 6.0
    },
    "honeyfile_touch": {
        "desc": "诱饵文件触碰",
        "func": op_honeyfile_touch,
        "expected_alert": True,
        "default_count": 5,
        "wait_timeout": 6.0
    }
}


# =========================
# 测试执行逻辑
# =========================

def run_one_case(case_name, count):
    case = TEST_CASES[case_name]

    if count is None:
        count = case["default_count"]

    expected_alert = case["expected_alert"]
    wait_timeout = case["wait_timeout"]
    op_func = case["func"]

    correct = 0

    print("\n" + "=" * 70)
    print("黑盒测试项目：{}".format(case_name))
    print("测试说明：{}".format(case["desc"]))
    print("测试次数：{}".format(count))
    print("期望结果：{}".format("应产生告警" if expected_alert else "不应产生告警"))
    print("=" * 70)

    for i in range(1, count + 1):
        before_count = len(read_alert_rows())

        try:
            op_func(i)
        except Exception as e:
            print("[{}/{}] 操作失败：{}".format(i, count, e))
            continue

        has_new_alert = wait_for_alert_since(before_count, wait_timeout)
        is_correct = has_new_alert == expected_alert

        if is_correct:
            correct += 1

        print(
            "[{}/{}] 新增告警：{} | 判定：{}".format(
                i,
                count,
                "是" if has_new_alert else "否",
                "正确" if is_correct else "错误"
            )
        )

        # 每次之间稍微间隔，避免上一轮告警延迟影响下一轮
        time.sleep(0.8)

    accuracy = correct / count * 100 if count else 0.0

    print("\n" + "-" * 70)
    print("测试项目：{}".format(case_name))
    print("正确次数：{}".format(correct))
    print("总次数：{}".format(count))
    print("准确率：{:.2f}%".format(accuracy))
    print("-" * 70)

    return correct, count


def run_all_cases(count_override):
    total_correct = 0
    total_count = 0

    for case_name in TEST_CASES:
        correct, count = run_one_case(case_name, count_override)
        total_correct += correct
        total_count += count

    total_accuracy = total_correct / total_count * 100 if total_count else 0.0

    print("\n" + "=" * 70)
    print("黑盒测试总结果")
    print("总正确次数：{}".format(total_correct))
    print("总测试次数：{}".format(total_count))
    print("总体准确率：{:.2f}%".format(total_accuracy))
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Guard 黑盒准确率测试脚本；main.py 需手动提前启动。"
    )

    parser.add_argument(
        "--case",
        choices=list(TEST_CASES.keys()) + ["all"],
        required=True,
        help="测试类型"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="测试次数；不填则使用每类默认次数"
    )

    parser.add_argument(
        "--clean",
        action="store_true",
        help="测试前清空 test_data_blackbox 内容和 logs/alerts.csv"
    )

    parser.add_argument(
        "--no-sync-config",
        action="store_true",
        help="不写入 config.json；仅当你已经手动设置 main.py 监控目录时使用"
    )

    args = parser.parse_args()

    print("[项目根目录] {}".format(PROJECT_ROOT))
    print("[测试目录] {}".format(WATCH_DIR))
    print("[告警日志] {}".format(LOG_FILE))
    print("[配置文件] {}".format(CONFIG_FILE))

    ensure_dir(WATCH_DIR)
    ensure_dir(LOG_FILE.parent)
    ensure_dir(HELPER_DIR)

    if args.clean:
        print("[清理] 清空测试目录内容和告警日志...")
        clear_watch_dir()
        clear_alert_log()

    if not args.no_sync_config:
        sync_config_to_main()
    else:
        print("[提示] 已跳过 config.json 同步，请确认 main.py 正在监听测试目录。")

    print("\n[重要] 请确认 main.py 已经手动启动。")
    print("推荐启动方式：")
    print(r"cd C:\Users\root\Desktop\Ransomware_Guard")
    print(r"python main.py --watch-dirs C:\Users\root\Desktop\Ransomware_Guard\test_data_blackbox")
    print()

    time.sleep(2)

    if args.case == "all":
        run_all_cases(args.count)
    else:
        run_one_case(args.case, args.count)


if __name__ == "__main__":
    main()
