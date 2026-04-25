import joblib
import numpy as np
import time
import os
import psutil
import warnings  # 新增：导入警告控制模块

warnings.filterwarnings("ignore", category=UserWarning)

class RansomwareEngine:
    def __init__(self, model_path="../../models/rf_ransomware_model.joblib"):
        """
        初始化核心检测引擎
        """
        print("[*] 正在初始化主动防御引擎...")
        
        # 1. 加载随机森林模型
        # 注意：请确保相对路径正确，或者改为你的绝对路径
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            print("[+] 随机森林大脑加载成功！低延迟推理已就绪。")
        else:
            print("[-] 警告: 未找到模型文件！请确保已运行 train_model.py")
            self.model = None

        # 论文中定义的关键特征维度
        self.critical_apis = ['FileWrite', 'FileRename', 'FileDelete', 'SetInfo']

    def extract_features(self, api_sequence, max_entropy):
        """
        实时特征提取：将 N-gram 序列和信息熵转化为模型可读的向量
        """
        api_counts = [api_sequence.count(api) for api in self.critical_apis]
        entropy_risk = 1 if max_entropy > 7.0 else 0
        
        # 组装特征并转换为 2D 数组供 sklearn 预测
        feature_vector = api_counts + [max_entropy, entropy_risk]
        return np.array([feature_vector])

    def analyze_and_block(self, pid, process_name, api_sequence, real_entropy=0.0):
        """
        核心流式处理管道：评估进程行为并在必要时阻断 (真实数据版)
        """
        if not self.model: 
            return False

        start_time = time.time()

        # 1. 直接使用传入的真实信息熵！不再做模拟判断！
        current_entropy = real_entropy

        # 2. 提取特征向量
        features = self.extract_features(api_sequence, current_entropy)

        # 3. 随机森林毫秒级推理
        prediction = self.model.predict(features)[0]
        
        process_time_ms = (time.time() - start_time) * 1000 

        # 4. 判决与阻断逻辑
        if prediction == 1:
            print(f"\n[!!!] 🚨 严重威胁告警 (算法层) 🚨 [!!!]")
            print(f"发现异常进程: {process_name} (PID: {pid})")
            print(f"威胁特征: 高频 I/O 操作, 文件信息熵飙升至 {current_entropy:.4f}")
            print(f"算法推理耗时: {process_time_ms:.2f} ms")
            self.kill_process(pid, process_name)
            return True
        else:
            return False

    def kill_process(self, pid, process_name):
        """
        真实的进程猎杀机制 (对齐论文 4.2 节：调用 TerminateProcess)
        """
        import win32api
        import win32con
        print(f"[🛡️ 主动防御] 正在切断 {process_name} 的 I/O 句柄并尝试终止进程...")
        if pid == 9999:
            print("[-] 警告: 未能反查到真实 PID，进程可能已退出或隐藏。")
            return
            
        try:
            # 使用 Windows 底层 API 提权并获取进程句柄 (对应论文中的 0x000F0000 也就是 PROCESS_TERMINATE)
            handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
            # 强制猎杀进程
            win32api.TerminateProcess(handle, 0)
            print(f"[+] 猎杀成功！恶意进程 {process_name} (PID: {pid}) 已被 TerminateProcess 彻底切断。\n")
        except Exception as e:
            # 如果底层 API 失败，作为兜底依然尝试使用 psutil
            try:
                import psutil
                psutil.Process(pid).kill()
                print(f"[+] 猎杀成功！恶意进程 {process_name} (PID: {pid}) 已被 psutil 清除。\n")
            except Exception as backup_e:
                print(f"[-] 猎杀发生未知错误: {e} | {backup_e}")

# --- 模拟引擎测试 ---
if __name__ == "__main__":
    # 为了测试方便，假设我们在当前目录下寻找模型
    engine = RansomwareEngine(model_path="../../models/rf_ransomware_model.joblib")
    
    # 场景 1：输入一段正常的 Word 文档操作序列
    normal_seq = ['FileOpen', 'FileRead', 'FileWrite', 'FileClose']
    engine.analyze_and_block(pid=2048, process_name="winword.exe", api_sequence=normal_seq)
    
    # 场景 2：输入一段勒索病毒典型的 加密->重命名 序列
    ransom_seq = ['FileOpen', 'FileRead', 'FileWrite', 'FileWrite', 'FileWrite', 'FileRename']
    engine.analyze_and_block(pid=8848, process_name="unknown_cryptor.exe", api_sequence=ransom_seq)
