import joblib
import psutil
from concurrent.futures import ThreadPoolExecutor

class RansomwareEngine:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)
        self.entropy_threshold = 7.9  
        self.malicious_prob_threshold = 0.85
        
        # 【核心优化】：初始化专用查杀线程池 (对齐论文 2.3 节性能需求)
        # 保证主监听线程的 CPU 占用与响应时延极低
        self.kill_executor = ThreadPoolExecutor(max_workers=3)

    def judge_and_protect(self, pid, features, current_op, current_entropy):
        prob = self.model.predict_proba(features)[0][1] 
        is_watchdog_triggered = (current_op == "FileRename" and current_entropy > self.entropy_threshold)

        if prob > self.malicious_prob_threshold or is_watchdog_triggered:
            reason = "Watchdog兜底" if is_watchdog_triggered else f"AI置信度 {prob:.2f}"
            # 【核心优化】：将阻塞的猎杀动作推入异步线程池，立即返回 True 释放主线程
            self.kill_executor.submit(self._async_execute_block, pid, reason)
            return True
        return False

    def _async_execute_block(self, pid, reason):
        """后台异步执行挂起与查杀，不卡顿主监控循环"""
        try:
            p = psutil.Process(pid)
            # 针对勒索病毒的高危特性，先挂起剥夺 I/O 权限，再从容击杀
            p.suspend() 
            p.kill()    
            print(f"[🔥 异步阻断成功] PID: {pid} 已被彻底清除。触发机制: {reason}")
        except Exception as e:
            # 进程可能已瞬间退出，属于正常对抗现象
            pass
