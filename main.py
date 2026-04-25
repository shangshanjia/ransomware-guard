# -*- coding: utf-8 -*-
import os
import sys
import time
import csv
import psutil
import json
import threading
import argparse
from datetime import datetime
from collections import defaultdict

# 确保项目根目录在路径中
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.monitor.real_etw_listener import RealWindowsListener
from src.protection.detector_engine import RansomwareEngine
from src.protection.honeyfile_manager import HoneyfileManager
from src.features.real_entropy_calc import calculate_real_entropy

class IntegratedSystem(RealWindowsListener):
    def __init__(self, watch_dirs):
        super().__init__(watch_dirs=watch_dirs)
        print("\n" + "="*50)
        print("🛡️  勒索病毒实时阻断系统 (完全体：策略热加载版) 已启动")
        print(f"[*] 初始保护目录: {self.watch_dirs}")
        print("="*50 + "\n")
        
        # 【新增】：部署静默期时间戳，防止系统“自己监控自己”
        self._deploy_time = time.time()
        
        self.honey_mgr = HoneyfileManager(target_dirs=self.watch_dirs)
        self.honey_mgr.deploy()
        
        self.engine = RansomwareEngine(model_path="models/rf_ransomware_model.joblib")
        self.agg_id = "global_monitor"
        self.process_entropies = defaultdict(float)
        
        os.makedirs("logs", exist_ok=True)
        self.log_file = "logs/alerts.csv"

        self.config_file = "config.json"
        self.last_config_mtime = 0
        self.config_lock = threading.Lock()
        threading.Thread(target=self._watch_config_change, daemon=True).start()

    def _watch_config_change(self):
        """后台线程：实时监听 config.json，实现无感热加载与策略撤销"""
        while True:
            if os.path.exists(self.config_file):
                try:
                    current_mtime = os.path.getmtime(self.config_file)
                    if current_mtime > self.last_config_mtime:
                        self.last_config_mtime = current_mtime
                        with open(self.config_file, "r", encoding="utf-8") as f:
                            config = json.load(f)
                            new_dirs = [os.path.abspath(d) for d in config.get("watch_dirs", [])]
                            
                            with self.config_lock:
                                # 1. 处理被删除的路径（策略撤销/逻辑解绑）
                                removed_dirs = [d for d in self.watch_dirs if d not in new_dirs]
                                for rd in removed_dirs:
                                    print(f"\n[🛑 策略撤销] 接收到前端指令，已解除对该路径的保护: {rd}")
                                    self.watch_dirs.remove(rd)

                                # 2. 处理新增的路径（策略下发）
                                for d in new_dirs:
                                    if d not in self.watch_dirs:
                                        print(f"\n[🔄 策略下发] 接收到前端新指令，正在为新路径注入探针: {d}")
                                        self.watch_dirs.append(d)
                                        
                                        # 重置部署时间戳，开启2秒静默期
                                        self._deploy_time = time.time() 
                                        self.honey_mgr.target_dirs = [d]
                                        self.honey_mgr.deploy()
                                        
                                        # 启动新的监听线程
                                        threading.Thread(target=self.monitor_directory, args=(d,), daemon=True).start()
                except Exception as e:
                    print(f"[-] 配置文件同步失败: {e}")
            time.sleep(2)

    def log_alert(self, process_name, pid, trigger, target):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([current_time, process_name, pid, trigger, target, "已阻断 🛑"])

    def lazy_traceback(self, target_file):
        print(f"  [⚡ 延迟溯源] 正在逆向追踪操作 {os.path.basename(target_file)} 的真实进程...")
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for item in proc.open_files():
                        if target_file in item.path:
                            return proc.info['pid'], proc.info['name']
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        return 9999, "Unknown_Process"

    def on_real_event_captured(self, operation, file_path):
        """核心回调：捕获行为并决策"""
        with self.config_lock:
            # 逻辑解绑
            is_monitored = any(file_path.startswith(d) for d in self.watch_dirs)
            if not is_monitored:
                return

        # ==========================================
        # 【新增：工业级安全软件的“目录白名单”机制】
        # 浏览器(Edge/Chrome)和系统底层会在 AppData 疯狂写入高熵数据库(如 shared_proto_db)
        # 必须过滤掉这些合法的高频噪点，否则 AI 会将其误判为勒索病毒并击杀！
        # ==========================================
        lower_path = file_path.lower()
        if "appdata" in lower_path or "windows" in lower_path:
            return

        # 【防线一】：诱饵文件防线增加“部署静默期”
        if operation in ['FileWrite', 'FileRename_New', 'FileDelete', 'FileRename_Old']:
            if self.honey_mgr.is_tampered(file_path):
                # 部署后的前 2 秒内发生的诱饵文件修改，认定为系统自身的部署行为，忽略！
                if time.time() - self._deploy_time < 2.0:
                    return 
                    
                print(f"\n[!!!] 🚨 触发第一防线：诱饵陷阱受损！目标: {file_path}")
                real_pid, process_name = self.lazy_traceback(file_path)
                self.log_alert(process_name, real_pid, "诱饵陷阱 (Honeyfile)", os.path.basename(file_path))
                self.engine.kill_process(real_pid, process_name)
                return  

        if operation in ['FileWrite', 'FileRename_New']:
            current_entropy = calculate_real_entropy(file_path)
            if current_entropy > self.process_entropies[self.agg_id]:
                self.process_entropies[self.agg_id] = current_entropy

        rf_operation = 'FileWrite' if operation in ['FileCreate', 'FileWrite'] else ('FileRename' if operation == 'FileRename_New' else operation)

        self.file_behaviors[self.agg_id].append(rf_operation)
        if len(self.file_behaviors[self.agg_id]) > 200:
            self.file_behaviors[self.agg_id].pop(0)

        current_seq = self.file_behaviors[self.agg_id]
        write_count = current_seq.count('FileWrite')
        max_entropy = self.process_entropies[self.agg_id]
        
        is_low_freq_evasion = (max_entropy > 7.8) and (rf_operation == 'FileRename')
        is_high_freq = len(current_seq) >= 20 and (rf_operation == 'FileRename' or write_count >= 15)

        if is_low_freq_evasion:
            real_pid, process_name = self.lazy_traceback(file_path)
            print(f"\n[🐺 嗅探器触发] 捕获到低频逃逸变种 (Watchdog)！")
            self.log_alert(process_name, real_pid, "异常高熵重命名 (规则兜底)", os.path.basename(file_path))
            self.engine.kill_process(real_pid, process_name)
            self._reset_state()

        elif is_high_freq:
            is_malicious = self.engine.analyze_and_block(9999, "Pending", current_seq, real_entropy=max_entropy)
            if is_malicious:
                real_pid, process_name = self.lazy_traceback(file_path)
                print(f"\n[🤖 AI 研判成功] 随机森林模型判定威胁成立！")
                self.log_alert(process_name, real_pid, "AI 语义与内容熵融合研判", os.path.basename(file_path))
                self.engine.kill_process(real_pid, process_name)
                self._reset_state()
            else:
                self.process_entropies[self.agg_id] = 0.0

    def _reset_state(self):
        self.file_behaviors[self.agg_id] = []
        self.process_entropies[self.agg_id] = 0.0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ransomware Guard CLI")
    default_path = os.path.abspath("./test_data")
    parser.add_argument('--watch-dirs', nargs='+', default=[default_path])
    args = parser.parse_args()

    system = IntegratedSystem(watch_dirs=args.watch_dirs)
    try:
        system.start_monitoring()
    except KeyboardInterrupt:
        system.stop_monitoring()
