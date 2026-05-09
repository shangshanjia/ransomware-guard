# -*- coding: utf-8 -*-

import os
import sys
import time
import csv
import json
import threading
import argparse
import psutil
import queue
import wmi
import warnings
from datetime import datetime

try:
    import pythoncom
except ImportError:
    pythoncom = None

# 确保项目根目录在路径中
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 核心模块导入
from src.monitor.etw_kernel_listener import ETWKernelListener
from src.features.integrated_feature_engine import IntegratedFeatureEngine
from src.protection.detector_engine import RansomwareEngine
from src.protection.honeyfile_manager import HoneyfileManager


class IntegratedSystem(ETWKernelListener):
    def __init__(self, watch_dirs):
        super().__init__(watch_dirs=watch_dirs)#把用户指定的保护目录传给监听模块

        print("\n" + "=" * 50)
        print("🛡️  勒索病毒实时阻断系统 (异步队列解耦版) 已启动")
        print(f"[*] 监控保护目录: {self.watch_dirs}")
        print("=" * 50 + "\n")

        self.feature_engine = IntegratedFeatureEngine()
        self.engine = RansomwareEngine(model_path="models/rf_ransomware_model.joblib")

        self.honey_mgr = HoneyfileManager(target_dirs=self.watch_dirs)
        self.honey_mgr.deploy()
        self._deploy_time = time.time()

        os.makedirs("logs", exist_ok=True)
        self.log_file = "logs/alerts.csv"
        self.config_file = "config.json"
        self.last_config_mtime = os.path.getmtime(self.config_file) if os.path.exists(self.config_file) else 0
        self.config_lock = threading.Lock()

        # 高并发异步消息队列
        self.event_queue = queue.Queue(maxsize=20000)

        # 策略热加载线程
        threading.Thread(target=self._watch_config_change, daemon=True).start()

        # 文件事件消费线程
        threading.Thread(target=self._event_consumer_worker, daemon=True).start()

        # WMI 事前防线线程
        threading.Thread(target=self._pre_radar_worker, daemon=True).start()

    def is_noisy_file(self, file_path):
        """
        自适应降噪：过滤系统缓存、临时文件、IDE 文件等噪声。
        """
        lower_path = file_path.lower()

        noise_keywords = [
            "appdata",
            "temp",
            ".git",
            ".vscode",
            "__pycache__",
            "prefetch",
            "blackbox_helpers"
        ]

        if any(k in lower_path for k in noise_keywords):
            return True

        _, ext = os.path.splitext(lower_path)

        if ext in [".tmp", ".log", ".sys", ".ini", ".db"]:
            return True

        return False

    def precision_traceback(self, target_file):
        """
        精准溯源：根据命令行关键词或打开文件句柄寻找真实进程 PID。
        """
        try:
            attack_keywords = [
                "simulate_attack",
                "simulate_ransomware_behavior",
                "simulate_attack2",
                "simulate_attack_honey",
                "simulate_attack_blackbox"
            ]

            for proc in psutil.process_iter(["pid", "cmdline"]):
                try:
                    cmd = proc.info.get("cmdline")
                    if cmd and any(kw in " ".join(cmd) for kw in attack_keywords):
                        return proc.info["pid"]
                except Exception:
                    pass

            # 兜底：根据打开文件句柄寻找目标进程
            for proc in psutil.process_iter(["pid"]):
                try:
                    for item in proc.open_files():
                        if target_file in item.path:
                            return proc.info["pid"]
                except Exception:
                    pass

        except Exception:
            pass

        return None

    def on_event_captured(self, mock_pid, operation, file_path):
        """
        生产者：底层监听器捕获事件后，只写入队列，不执行重逻辑。
        """
        if self.is_noisy_file(file_path):
            return

        try:
            self.event_queue.put_nowait((mock_pid, operation, file_path))
        except queue.Full:
            pass

    def _event_consumer_worker(self):
        """
        消费者：从队列中读取文件事件，进行诱饵检测、特征提取、模型判定和阻断。
        """
        while True:
            mock_pid = None
            operation = None
            file_path = None

            try:
                mock_pid, operation, file_path = self.event_queue.get()

                # 第一防线：诱饵文件检测
                if time.time() - self._deploy_time > 2.0:
                    if self.honey_mgr.is_tampered(file_path):
                        print(f"\n[!!!] 🚨 触发第一防线：诱饵陷阱受损！目标: {os.path.basename(file_path)}")
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass

                        self.honey_mgr.deploy()
                        self._deploy_time = time.time()

                        real_pid = self.precision_traceback(file_path)

                        if real_pid:
                            self.engine._async_execute_block(real_pid, "诱饵文件陷阱 (Honeyfile)")
                            self.log_alert("诱饵防线", real_pid, "诱饵文件受损", os.path.basename(file_path))

                        self.event_queue.task_done()
                        continue

                # 第二防线：特征聚合 + 模型/Watchdog 双轨判定
                sequence = self.process_behaviors[mock_pid]

                if len(sequence) >= 5:
                    features, current_entropy = self.feature_engine.get_feature_vector(sequence, file_path)

                    prob = self.engine.predict_malicious_probability(features)

                    write_count = features[0][0]
                    rename_count = features[0][1]
                    delete_count = features[0][2]

                    is_watchdog = (
                        current_entropy > self.engine.entropy_threshold
                        and (
                            rename_count > 0
                            or write_count >= 10
                        )
                    )

                    print(
                        f"[调试] write={write_count}, rename={rename_count}, delete={delete_count}, "
                        f"op={operation}, entropy={current_entropy:.4f}, "
                        f"检测概率={prob:.4f}, Watchdog={is_watchdog}, "
                        f"file={os.path.basename(file_path)}"
                    )

                    if prob > self.engine.malicious_prob_threshold or is_watchdog:
                        real_pid = self.precision_traceback(file_path)
                        if real_pid:
                            self.engine.judge_and_protect(real_pid, features, operation, current_entropy)
                            self.log_alert("双轨决策引擎", real_pid, "检测模型/Watchdog 联合判定", os.path.basename(file_path))
                            self.process_behaviors[mock_pid] = []
                        else:
                            print(f"\n[👻 幽灵逃逸] AI 已锁定高危目标: {os.path.basename(file_path)}")
                            print("  └─ 溯源失败：可疑进程可能已经退出。")
                            self.process_behaviors[mock_pid] = []

                self.event_queue.task_done()

            except Exception as e:
                try:
                    if mock_pid is not None:
                        self.event_queue.task_done()
                except Exception:
                    pass

                # 不让后台线程静默死亡
                print(f"[-] 事件消费线程异常: {e}")

    def log_alert(self, trigger_type, pid, detail, target):
        """
        记录拦截日志，供黑盒测试脚本和 Streamlit 大屏读取。
        """
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with open(self.log_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    current_time,
                    f"进程_{pid}",
                    pid,
                    trigger_type,
                    target,
                    "已阻断 🛑"
                ])
        except Exception as e:
            print(f"[-] 写入告警日志失败: {e}")

    def _watch_config_change(self):
        """
        策略热加载：读取 config.json 中的 watch_dirs。
        """
        while True:
            if os.path.exists(self.config_file):
                try:
                    mtime = os.path.getmtime(self.config_file)

                    if mtime > self.last_config_mtime:
                        self.last_config_mtime = mtime

                        with open(self.config_file, "r", encoding="utf-8") as f:
                            new_dirs = [
                                os.path.abspath(d)
                                for d in json.load(f).get("watch_dirs", [])
                            ]

                        if new_dirs:
                            with self.config_lock:
                                self.watch_dirs = new_dirs
                                self.honey_mgr.target_dirs = new_dirs
                                self.honey_mgr.deploy()
                                self._deploy_time = time.time()

                            print(f"[*] 监控策略已热重载，当前保护路径: {len(self.watch_dirs)} 个")
                            print(f"[*] 监控策略已热重载，当前保护路径: {len(self.watch_dirs)} 个")
                            for d in self.watch_dirs:
                                print(f"    - {d}")

                except Exception as e:
                    print(f"[-] 策略热加载失败: {e}")

            time.sleep(2)

    def _pre_radar_worker(self):
        """
        事前防线：基于 WMI 的进程创建与命令行监控。
        """
        print("[*] 📡 事前防线 (WMI 前置雷达) 守护线程已启动...")

        if pythoncom is None:
            print("[-] pythoncom 未安装，WMI 前置雷达已跳过。")
            return

        pythoncom.CoInitialize()

        try:
            high_risk_keywords = [
                "vssadmin.exe delete shadows",
                "bcdedit /set {default} recoveryenabled no",
                "wbadmin delete catalog",
                "wevtutil cl security",
                "taskkill /f /im sqlservr.exe"
            ]

            c = wmi.WMI()

            process_watcher = c.ExecNotificationQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 "
                "WHERE TargetInstance ISA 'Win32_Process'"
            )

            while True:
                new_event = process_watcher.NextEvent()
                process = new_event.TargetInstance

                pid = process.ProcessId
                name = process.Name
                cmdline = process.CommandLine

                if not cmdline:
                    continue

                cmdline_lower = cmdline.lower()
                is_malicious = any(keyword in cmdline_lower for keyword in high_risk_keywords)

                if is_malicious:
                    print(f"\n[🚨 事前防线触发] 发现勒索病毒高危前置指令: {cmdline}")

                    try:
                        p = psutil.Process(pid)
                        p.kill()

                        print(f"[🔥 斩首成功] 进程 {name} (PID:{pid}) 已被终止。")

                        self.log_alert(
                            "事前防御 (WMI雷达)",
                            pid,
                            "执行高危破坏指令",
                            cmdline
                        )

                    except psutil.NoSuchProcess:
                        pass
                    except psutil.AccessDenied:
                        print("[!] 权限不足，请以管理员身份运行 main.py")

        except Exception as e:
            print(f"[-] WMI 前置雷达异常退出: {e}")

        finally:
            pythoncom.CoUninitialize()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ransomware Guard CLI")
    parser.add_argument(
        "--watch-dirs",
        nargs="+",
        default=None,
        help="需要保护的目录，可输入一个或多个路径"
    )
    args = parser.parse_args()

    config_file = "config.json"

    # 1. 命令行指定路径：优先使用，并保存到 config.json
    if args.watch_dirs:
        watch_dirs = [os.path.abspath(d) for d in args.watch_dirs]

        with open(config_file, "w", encoding="utf-8") as f:
            json.dump({"watch_dirs": watch_dirs}, f, ensure_ascii=False, indent=4)

        print("[*] 已使用命令行指定的保护路径，并保存到 config.json：")
        for d in watch_dirs:
            print(f"    - {d}")

    # 2. 没有命令行路径：读取上次保存的 config.json
    elif os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                watch_dirs = [
                    os.path.abspath(d)
                    for d in json.load(f).get("watch_dirs", [])
                    if d.strip()
                ]

            if not watch_dirs:
                watch_dirs = [os.path.abspath("./test_data")]

            print("[*] 已读取上次保存的保护路径：")
            for d in watch_dirs:
                print(f"    - {d}")

        except Exception:
            watch_dirs = [os.path.abspath("./test_data")]

    # 3. 没有配置文件：使用默认 test_data，并保存
    else:
        watch_dirs = [os.path.abspath("./test_data")]

        with open(config_file, "w", encoding="utf-8") as f:
            json.dump({"watch_dirs": watch_dirs}, f, ensure_ascii=False, indent=4)

        print("[*] 未发现配置文件，已使用默认保护路径：")
        for d in watch_dirs:
            print(f"    - {d}")

    system = IntegratedSystem(watch_dirs=watch_dirs)

    try:
        system.run()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] 系统安全退出。")
