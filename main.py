import os
import sys
import time
import csv
import psutil
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.monitor.real_etw_listener import RealWindowsListener
from src.protection.detector_engine import RansomwareEngine
from src.protection.honeyfile_manager import HoneyfileManager
from src.features.real_entropy_calc import calculate_real_entropy

class IntegratedSystem(RealWindowsListener):
    def __init__(self, watch_dirs):
        super().__init__(watch_dirs=watch_dirs)
        print("[*] ==============================================")
        print("[*] 🛡️ 勒索病毒实时阻断系统 (完全体：延迟溯源版) 已启动")
        print("[*] ==============================================\n")
        
        self.honey_mgr = HoneyfileManager(target_dirs=self.watch_dirs)
        self.honey_mgr.deploy()
        self.engine = RansomwareEngine(model_path="models/rf_ransomware_model.joblib")
        
        # 使用全局聚合ID，替代缓慢的逐一 PID 跟踪
        self.agg_id = "global_monitor"
        self.process_entropies = defaultdict(float)
        
        os.makedirs("logs", exist_ok=True)
        self.log_file = "logs/alerts.csv"

    def log_alert(self, process_name, pid, trigger, target):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([current_time, process_name, pid, trigger, target, "已阻断 🛑"])

    def lazy_traceback(self, target_file):
        """【终极杀招：延迟溯源机制】只在确认被攻击时，才全盘锁定凶手"""
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
        # 【防线一】：诱饵文件极速双重验证
        if operation in ['FileWrite', 'FileRename_New', 'FileDelete', 'FileRename_Old']:
            if self.honey_mgr.is_tampered(file_path):
                print(f"\n[!!!] 🚨 触发第一防线：诱饵陷阱 🚨 [!!!]")
                real_pid, process_name = self.lazy_traceback(file_path)
                self.log_alert(process_name, real_pid, "诱饵陷阱 (Honeyfile)", os.path.basename(file_path))
                self.engine.kill_process(real_pid, process_name)
                return  

        # 【全局特征聚合】计算信息熵与序列
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
        
        # ==========================================
        # 🛡️ 终极混合决策引擎 (Hybrid Decision Engine)
        # ==========================================
        
        # 规则 1：常规高频启发式触发 (交给 AI 随机森林研判)
        is_high_freq = len(current_seq) >= 20 and (rf_operation == 'FileRename' or write_count >= 15)
        
        # 规则 2：低频高危嗅探器 (Watchdog 兜底拦截)
        # 释义：哪怕动作极少(低频)，但只要写入了极高混乱度的数据(>7.8)并试图重命名，绝对是恶意加密！
        is_low_freq_evasion = (max_entropy > 7.8) and (rf_operation == 'FileRename')

        if is_low_freq_evasion:
            # 【直接击杀，不问 AI】对付极度狡猾的低频变种，采用规则兜底秒杀！
            real_pid, process_name = self.lazy_traceback(file_path)
            print(f"\n[!!!] 🐺 触发低频高危嗅探器 (Watchdog): 捕获到低频逃逸变种！")
            self.log_alert(process_name, real_pid, "异常高熵重命名 (低频嗅探兜底)", os.path.basename(file_path))
            self.engine.kill_process(real_pid, process_name)
            
            self.file_behaviors[self.agg_id] = []
            self.process_entropies[self.agg_id] = 0.0

        elif is_high_freq:
            # 【交给 AI 大脑】常规高频操作，交给随机森林区分是“正常压缩”还是“勒索病毒”
            is_malicious = self.engine.analyze_and_block(9999, "Pending", current_seq, real_entropy=max_entropy)
            
            if is_malicious:
                real_pid, process_name = self.lazy_traceback(file_path)
                self.log_alert(process_name, real_pid, "行为语义与内容熵融合分析", os.path.basename(file_path))
                self.engine.kill_process(real_pid, process_name)
                
                self.file_behaviors[self.agg_id] = []
                self.process_entropies[self.agg_id] = 0.0
            else:
                # 正常的高频操作，放行并重置熵值
                self.process_entropies[self.agg_id] = 0.0

if __name__ == "__main__":
    target_dir = os.path.abspath("./test_data")
    print(f"[*] 全局保护目录已设定为: {target_dir}")
    
    system = IntegratedSystem(watch_dirs=[target_dir])
    try:
        system.start_monitoring()
    except KeyboardInterrupt:
        system.stop_monitoring()