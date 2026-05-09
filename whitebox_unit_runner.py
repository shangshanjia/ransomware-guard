# -*- coding: utf-8 -*-

import os
import sys
import csv
import time
import queue
import shutil
import random
import string
import traceback
from pathlib import Path


# =========================
# 项目路径配置
# =========================

PROJECT_ROOT = Path(r"C:\Users\root\Desktop\Ransomware_Guard")
WHITEBOX_DIR = PROJECT_ROOT / "test_data_whitebox"
WHITEBOX_LOG = PROJECT_ROOT / "logs" / "whitebox_alerts.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "rf_ransomware_model.joblib"

sys.path.insert(0, str(PROJECT_ROOT))


# =========================
# 导入被测模块
# =========================

from main import IntegratedSystem
from src.features.integrated_feature_engine import IntegratedFeatureEngine
from src.protection.detector_engine import RansomwareEngine
from src.protection.honeyfile_manager import HoneyfileManager


# =========================
# 基础工具函数
# =========================

def ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True)


def clean_whitebox_dir():
    ensure_dir(WHITEBOX_DIR)

    for item in WHITEBOX_DIR.iterdir():
        try:
            if item.is_file() or item.is_symlink():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(str(item), ignore_errors=True)
        except Exception:
            pass


def random_name(prefix, suffix):
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return "{}_{}{}".format(prefix, token, suffix)


def make_text_file(name, content):
    ensure_dir(WHITEBOX_DIR)
    path = WHITEBOX_DIR / name
    path.write_text(content, encoding="utf-8")
    return path


def make_high_entropy_file(name, size=4096):
    ensure_dir(WHITEBOX_DIR)
    path = WHITEBOX_DIR / name
    with open(str(path), "wb") as f:
        f.write(os.urandom(size))
    return path


def clear_whitebox_log():
    ensure_dir(WHITEBOX_LOG.parent)
    WHITEBOX_LOG.write_text("", encoding="utf-8")


def read_csv_rows(path):
    if not path.exists():
        return []

    rows = []
    with open(str(path), "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                rows.append(row)

    return rows


# =========================
# 测试记录器
# =========================

class TestRecorder:
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.details = []

    def check(self, case_id, case_name, condition, message):
        self.total += 1

        if condition:
            self.passed += 1
            result = "通过"
        else:
            self.failed += 1
            result = "未通过"

        self.details.append({
            "case_id": case_id,
            "case_name": case_name,
            "result": result,
            "message": message
        })

        print("[{}] {} - {} | {}".format(case_id, case_name, result, message))

    def summary(self):
        rate = self.passed / self.total * 100 if self.total else 0.0

        print("\n" + "=" * 70)
        print("白盒测试总结果")
        print("测试用例总数：{}".format(self.total))
        print("通过用例数：{}".format(self.passed))
        print("未通过用例数：{}".format(self.failed))
        print("总体通过率：{:.2f}%".format(rate))
        print("=" * 70)

        return rate


# =========================
# W1 文件事件过滤与入队测试
# =========================

def test_w1_event_filter_and_queue(recorder):
    """
    测试 IntegratedSystem.is_noisy_file() 与 on_event_captured()。
    注意：
    这里不调用 IntegratedSystem.__init__，避免启动真实监听线程。
    """
    case_id = "W1"
    case_name = "文件事件过滤与入队模块"

    system = object.__new__(IntegratedSystem)
    system.event_queue = queue.Queue(maxsize=100)

    normal_file = str(WHITEBOX_DIR / "normal_event.txt")
    tmp_file = str(WHITEBOX_DIR / "noise.tmp")
    log_file = str(WHITEBOX_DIR / "noise.log")

    try:
        is_normal_noise = system.is_noisy_file(normal_file)
        is_tmp_noise = system.is_noisy_file(tmp_file)
        is_log_noise = system.is_noisy_file(log_file)

        recorder.check(
            case_id,
            case_name,
            is_normal_noise is False,
            "普通文件不应被判定为噪声"
        )

        recorder.check(
            case_id,
            case_name,
            is_tmp_noise is True,
            ".tmp 文件应被过滤"
        )

        recorder.check(
            case_id,
            case_name,
            is_log_noise is True,
            ".log 文件应被过滤"
        )

        before_size = system.event_queue.qsize()
        system.on_event_captured(1001, "FileWrite", normal_file)
        after_size = system.event_queue.qsize()

        recorder.check(
            case_id,
            case_name,
            after_size == before_size + 1,
            "普通文件事件应进入事件队列"
        )

        before_size = system.event_queue.qsize()
        system.on_event_captured(1001, "FileWrite", tmp_file)
        after_size = system.event_queue.qsize()

        recorder.check(
            case_id,
            case_name,
            after_size == before_size,
            "噪声文件事件不应进入事件队列"
        )

    except Exception as e:
        recorder.check(case_id, case_name, False, "模块异常：{}".format(e))


# =========================
# W2 异步事件队列测试
# =========================

def test_w2_event_queue(recorder):
    case_id = "W2"
    case_name = "异步事件队列模块"

    try:
        q = queue.Queue(maxsize=100)

        events = [
            (2001, "FileWrite", "a.txt"),
            (2001, "FileRename", "b.txt"),
            (2001, "FileDelete", "c.txt"),
            (2001, "SetInfo", "d.txt")
        ]

        for event in events:
            q.put_nowait(event)

        recorder.check(
            case_id,
            case_name,
            q.qsize() == len(events),
            "事件写入队列数量正确"
        )

        output_events = []
        while not q.empty():
            output_events.append(q.get_nowait())

        recorder.check(
            case_id,
            case_name,
            output_events == events,
            "事件读取顺序与写入顺序一致"
        )

    except Exception as e:
        recorder.check(case_id, case_name, False, "模块异常：{}".format(e))


# =========================
# W3 特征提取测试
# =========================

def test_w3_feature_engine(recorder):
    case_id = "W3"
    case_name = "特征提取模块"

    try:
        engine = IntegratedFeatureEngine()

        normal_path = make_text_file(
            "feature_normal.txt",
            "this is a normal text file\n" * 20
        )

        high_entropy_path = make_high_entropy_file(
            "feature_high_entropy.bin",
            size=4096
        )

        sequence = [
            "FileWrite",
            "FileWrite",
            "FileRename",
            "FileDelete",
            "SetInfo"
        ]

        features, entropy = engine.get_feature_vector(sequence, str(normal_path))

        recorder.check(
            case_id,
            case_name,
            features.shape == (1, 6),
            "特征向量维度应为 1×6"
        )

        recorder.check(
            case_id,
            case_name,
            features[0][0] == 2 and features[0][1] == 1 and features[0][2] == 1 and features[0][3] == 1,
            "行为操作次数统计正确"
        )

        recorder.check(
            case_id,
            case_name,
            entropy >= 0,
            "普通文件熵值计算结果有效"
        )

        high_features, high_entropy = engine.get_feature_vector(
            ["FileWrite"] * 5 + ["FileRename"] * 2,
            str(high_entropy_path)
        )

        recorder.check(
            case_id,
            case_name,
            high_entropy > 7.0,
            "随机字节文件应具有较高信息熵"
        )

        recorder.check(
            case_id,
            case_name,
            high_features[0][5] == 1,
            "高熵风险标志应为 1"
        )

    except Exception as e:
        recorder.check(case_id, case_name, False, "模块异常：{}".format(e))


# =========================
# W4 模型与 Watchdog 判定测试
# =========================

def test_w4_model_and_watchdog(recorder):
    case_id = "W4"
    case_name = "模型与 Watchdog 判定模块"

    try:
        if not MODEL_PATH.exists():
            recorder.check(
                case_id,
                case_name,
                False,
                "模型文件不存在：{}".format(MODEL_PATH)
            )
            return

        engine = RansomwareEngine(model_path=str(MODEL_PATH))

        # 安全替换阻断函数，避免白盒测试真的终止进程
        def fake_block(pid, reason):
            return None

        engine._async_execute_block = fake_block

        normal_features = [[2, 0, 0, 0, 3.2, 0]]
        risk_features = [[180, 80, 20, 30, 7.9, 1]]

        normal_prob = engine.model.predict_proba(normal_features)[0][1]
        risk_prob = engine.model.predict_proba(risk_features)[0][1]

        recorder.check(
            case_id,
            case_name,
            normal_prob < engine.malicious_prob_threshold,
            "正常特征风险概率应低于阈值"
        )

        recorder.check(
            case_id,
            case_name,
            risk_prob > engine.malicious_prob_threshold,
            "高风险特征风险概率应高于阈值"
        )

        normal_result = engine.judge_and_protect(
            pid=999999,
            features=normal_features,
            current_op="FileWrite",
            current_entropy=3.2
        )

        recorder.check(
            case_id,
            case_name,
            normal_result is False,
            "正常特征不应触发阻断"
        )

        watchdog_result = engine.judge_and_protect(
            pid=999999,
            features=normal_features,
            current_op="FileRename",
            current_entropy=8.0
        )

        recorder.check(
            case_id,
            case_name,
            watchdog_result is True,
            "高熵重命名应触发 Watchdog 规则"
        )

        try:
            engine.kill_executor.shutdown(wait=False)
        except Exception:
            pass

    except Exception as e:
        recorder.check(case_id, case_name, False, "模块异常：{}".format(e))


# =========================
# W5 诱饵文件识别测试
# =========================

def test_w5_honeyfile_manager(recorder):
    case_id = "W5"
    case_name = "诱饵文件识别模块"

    try:
        honey_dir = WHITEBOX_DIR / "honey_test"
        ensure_dir(honey_dir)

        manager = HoneyfileManager(target_dirs=[str(honey_dir)])
        manager.deploy()

        traps = list(manager.deployed_traps)

        recorder.check(
            case_id,
            case_name,
            len(traps) >= 1,
            "诱饵文件应成功部署"
        )

        if traps:
            trap_path = traps[0]

            recorder.check(
                case_id,
                case_name,
                manager.is_tampered(trap_path) is True,
                "诱饵文件路径应被识别为受损目标"
            )

        normal_path = honey_dir / "normal_document.txt"
        normal_path.write_text("normal file", encoding="utf-8")

        recorder.check(
            case_id,
            case_name,
            manager.is_tampered(str(normal_path)) is False,
            "普通文件不应触发诱饵规则"
        )

    except Exception as e:
        recorder.check(case_id, case_name, False, "模块异常：{}".format(e))


# =========================
# W6 告警日志写入测试
# =========================

def test_w6_alert_log(recorder):
    case_id = "W6"
    case_name = "告警日志写入模块"

    try:
        clear_whitebox_log()

        system = object.__new__(IntegratedSystem)
        system.log_file = str(WHITEBOX_LOG)

        system.log_alert(
            trigger_type="白盒测试",
            pid=12345,
            detail="日志写入测试",
            target="whitebox_target.txt"
        )

        rows = read_csv_rows(WHITEBOX_LOG)

        recorder.check(
            case_id,
            case_name,
            len(rows) == 1,
            "告警日志应新增 1 条记录"
        )

        if rows:
            row = rows[0]

            recorder.check(
                case_id,
                case_name,
                len(row) == 6,
                "告警日志字段数量应为 6"
            )

            recorder.check(
                case_id,
                case_name,
                row[2] == "12345" and row[3] == "白盒测试",
                "PID 和触发机制字段应正确"
            )

            recorder.check(
                case_id,
                case_name,
                row[4] == "whitebox_target.txt",
                "目标文件字段应正确"
            )

    except Exception as e:
        recorder.check(case_id, case_name, False, "模块异常：{}".format(e))


# =========================
# 主函数
# =========================

def main():
    print("=" * 70)
    print("Ransomware Guard 白盒测试脚本")
    print("项目目录：{}".format(PROJECT_ROOT))
    print("测试目录：{}".format(WHITEBOX_DIR))
    print("测试日志：{}".format(WHITEBOX_LOG))
    print("=" * 70)

    clean_whitebox_dir()
    clear_whitebox_log()

    recorder = TestRecorder()

    test_w1_event_filter_and_queue(recorder)
    test_w2_event_queue(recorder)
    test_w3_feature_engine(recorder)
    test_w4_model_and_watchdog(recorder)
    test_w5_honeyfile_manager(recorder)
    test_w6_alert_log(recorder)

    recorder.summary()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n[严重错误] 白盒测试脚本异常退出：")
        traceback.print_exc()
