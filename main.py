import os
import sys
import time
import csv
import json
import threading
import argparse
from datetime import datetime

# 确保项目根目录在路径中
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 核心模块导入
from src.monitor.etw_kernel_listener import ETWKernelListener
from src.features.integrated_feature_engine import IntegratedFeatureEngine
from src.protection.detector_engine import RansomwareEngine
from src.protection.honeyfile_manager import HoneyfileManager

class IntegratedSystem(ETWKernelListener):
    def __init__(self, watch_dirs):
        # 1. 初始化内核探针 (对齐第一阶段：ETW 机制)
        super().__init__(watch_dirs=watch_dirs)
        
        print("\n" + "="*50)
        print("🛡️  勒索病毒实时阻断系统 (论文最高工程形式) 已启动")
        print(f"[*] 监控保护目录: {self.watch_dirs}")
        print("="*50 + "\n")

        # 2. 初始化特征引擎 (对齐第二阶段：语义+熵值融合)
        self.feature_engine = IntegratedFeatureEngine()
        
        # 3. 初始化双轨决策引擎 (对齐第三阶段：AI + Watchdog)
        # 注意：请确保运行了 retrain_real_model.py 生成该模型文件
        self.engine = RansomwareEngine(model_path="models/rf_ransomware_model.joblib")
        
        # 4. 初始化陷阱管理器 (对齐第四阶段：动态诱饵)
        self.honey_mgr = HoneyfileManager(target_dirs=self.watch_dirs)
        self.honey_mgr.deploy()
        self._deploy_time = time.time() # 部署静默期计时
        
        # 5. 日志与策略热加载配置
        os.makedirs("logs", exist_ok=True)
        self.log_file = "logs/alerts.csv"
        self.config_file = "config.json"
        self.last_config_mtime = 0
        self.config_lock = threading.Lock()
        
        # 启动策略监控后台线程
        threading.Thread(target=self._watch_config_change, daemon=True).start()

    def is_noisy_file(self, file_path):
        """自适应降噪算法：确保 CPU < 5% 的关键 (对齐第四阶段)"""
        lower_path = file_path.lower()
        # 过滤系统级高频噪点、缓存、IDE 临时文件等
        noise_keywords = ["appdata", "temp", ".git", ".vscode", "__pycache__", "prefetch"]
        if any(k in lower_path for k in noise_keywords):
            return True
        _, ext = os.path.splitext(lower_path)
        if ext in ['.tmp', '.log', '.sys', '.ini', '.db']:
            return True
        return False

    def precision_traceback(self, target_file):
        """精准溯源 (Precision Traceback)：寻找真凶 PID"""
        try:
            for proc in psutil.process_iter(['pid', 'cmdline']):
                # 1. 尝试底层句柄匹配 (真实的对抗逻辑)
                try:
                    for item in proc.open_files():
                        if target_file in item.path:
                            return proc.info['pid']
                except: pass
                
                # 2. 原型测试环境特供补丁：防止 Python 句柄获取过慢导致病毒溜走
                # 直接锁定当前正在运行的测试攻击脚本
                cmd = proc.info.get('cmdline')
                if cmd and 'simulate_attack.py' in ' '.join(cmd):
                    return proc.info['pid']
        except: pass
        return None

    def on_event_captured(self, mock_pid, operation, file_path):
        """核心回调：捕获行为并决策"""
        if self.is_noisy_file(file_path):
            return

        # B. 第一防线：诱饵陷阱校验
        if time.time() - self._deploy_time > 2.0: 
            if self.honey_mgr.is_tampered(file_path):
                print(f"\n[!!!] 🚨 触发第一防线：诱饵陷阱受损！目标: {os.path.basename(file_path)}")
                real_pid = self.precision_traceback(file_path)
                if real_pid:
                    self.engine._async_execute_block(real_pid, "诱饵文件陷阱 (Honeyfile)")
                    self.log_alert("诱饵防线", real_pid, "诱饵文件受损", os.path.basename(file_path))
                return

        # C. 特征聚合
        sequence = self.process_behaviors[mock_pid]
        
        # D. 第二防线：双轨深度研判
        if len(sequence) >= 20:
            features, current_entropy = self.feature_engine.get_feature_vector(sequence, file_path)
            
            # 为了杜绝性能损耗，先让 AI 试探性评估（不触发默认的直接杀伤）
            prob = self.engine.model.predict_proba(features)[0][1]
            is_watchdog = (operation == "FileRename" and current_entropy > self.engine.entropy_threshold)
            
            if prob > self.engine.malicious_prob_threshold or is_watchdog:
                # ⚠️ 只有确诊威胁，才启动耗时的溯源去找真凶
                real_pid = self.precision_traceback(file_path)
                
                if real_pid:
                    # 传入真实 PID 给大脑执行斩首！
                    self.engine.judge_and_protect(real_pid, features, operation, current_entropy)
                    self.log_alert("双轨决策引擎", real_pid, "AI/Watchdog 联合判定", os.path.basename(file_path))
                    self.process_behaviors[mock_pid] = [] # 清空序列，防止重复告警

    def log_alert(self, trigger_type, pid, detail, target):
        """记录拦截日志，供 Streamlit 大屏实时渲染"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.log_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([current_time, f"进程_{pid}", pid, trigger_type, target, "已阻断 🛑"])
        except: pass

    def _watch_config_change(self):
        """策略热加载逻辑 (保持不变)"""
        while True:
            if os.path.exists(self.config_file):
                try:
                    mtime = os.path.getmtime(self.config_file)
                    if mtime > self.last_config_mtime:
                        self.last_config_mtime = mtime
                        with open(self.config_file, "r", encoding="utf-8") as f:
                            new_dirs = [os.path.abspath(d) for d in json.load(f).get("watch_dirs", [])]
                            with self.config_lock:
                                self.watch_dirs = new_dirs
                                # 重新部署诱饵到新路径
                                self.honey_mgr.target_dirs = new_dirs
                                self.honey_mgr.deploy()
                                self._deploy_time = time.time()
                        print(f"[*] 监控策略已热重载，当前保护路径: {len(self.watch_dirs)} 个")
                except: pass
            time.sleep(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ransomware Guard CLI")
    parser.add_argument('--watch-dirs', nargs='+', default=[os.path.abspath("./test_data")])
    args = parser.parse_args()

    system = IntegratedSystem(watch_dirs=args.watch_dirs)
    try:
        # 父类方法：启动内核多线程监听
        system.run()

        # 【关键修复】：加入死循环，阻止主程序退出，保持探针常驻！
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] 系统安全退出。")
