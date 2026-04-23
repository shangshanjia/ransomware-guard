import time
from collections import defaultdict

class ETWMonitor:
    def __init__(self):
        """
        初始化 ETW 轻量化行为监听器
        """
        # 1. 自适应噪声过滤算法：定义系统白名单进程
        # 过滤掉这些高频正常进程，是保证 CPU 占用率 < 5% 的关键
        self.whitelist_processes = ['explorer.exe', 'svchost.exe', 'MsMpEng.exe', 'System']
        
        # 2. 行为序列表：按进程 ID (PID) 隔离维护操作序列
        # 结构示例: { 2048: ['FileOpen', 'FileRead', 'FileWrite'] }
        self.process_behaviors = defaultdict(list)
        
        # 3. 序列滑动窗口大小
        # 仅保留每个进程最近的 50 次操作，防止内存溢出，保持轻量化
        self.max_sequence_length = 50
        
        self.is_running = False

    def is_noisy_process(self, process_name):
        """自适应噪声过滤机制：检查是否为冗余进程"""
        return process_name in self.whitelist_processes

    def on_event_callback(self, event):
        """
        ETW 事件的回调处理函数（当捕获到文件创建、写入、重命名等操作时触发）
        """
        pid = event.get('pid')
        process_name = event.get('process_name')
        operation = event.get('operation')
        file_path = event.get('file_path')
        
        # 步骤 1: 噪声过滤 (剔除白名单进程)
        if self.is_noisy_process(process_name):
            return
            
        # 步骤 2: 提取并追加行为到对应 PID 的序列中
        self.process_behaviors[pid].append(operation)
        
        # 步骤 3: 维护滑动窗口 (遵循先入先出原则)
        if len(self.process_behaviors[pid]) > self.max_sequence_length:
            self.process_behaviors[pid].pop(0)
            
        # 打印实时捕获日志 (用于调试展示)
        print(f"[ETW 捕获] PID: {pid} ({process_name}) 执行了 {operation} -> {file_path}")

    def start_monitoring(self):
        """启动无代理行为监听"""
        self.is_running = True
        print("[*] 正在启动 ETW 用户态轻量化行为捕获引擎...")
        print("[*] 自适应噪声过滤已激活，目标稳态 CPU 占用率控制在 < 5%...")
        print("[+] ETW 监听已就绪，等待底层文件系统事件...\n")
        
        # 模拟产生真实的系统流事件供测试
        self._simulate_etw_stream()

    def stop_monitoring(self):
        """安全停止监听"""
        self.is_running = False
        print("\n[*] ETW 监听已安全停止。")

    def _simulate_etw_stream(self):
        """
        模拟 ETW 底层抛出的事件流（方便在无底层驱动环境下进行联调）
        """
        time.sleep(1)
        # 模拟 1: 普通办公软件操作 (应被记录，用于后续模型判定为正常)
        self.on_event_callback({'pid': 2048, 'process_name': 'winword.exe', 'operation': 'FileOpen', 'file_path': 'C:\\Docs\\thesis.docx'})
        self.on_event_callback({'pid': 2048, 'process_name': 'winword.exe', 'operation': 'FileRead', 'file_path': 'C:\\Docs\\thesis.docx'})
        
        # 模拟 2: 系统底层高频操作 (应被噪声过滤算法拦截，不输出日志)
        self.on_event_callback({'pid': 4, 'process_name': 'System', 'operation': 'FileWrite', 'file_path': 'C:\\Windows\\Temp\\sys.log'})
        
        time.sleep(1.5)
        # 模拟 3: 未知的疑似勒索软件高频修改行为
        print("\n[!] 警告：系统检测到未知进程的大量连续文件操作！")
        malware_pid = 8848
        for i in range(1, 4):
            # 连续进行 写入 -> 重命名(追加加密后缀) 的典型勒索行为
            self.on_event_callback({'pid': malware_pid, 'process_name': 'unknown_cryptor.exe', 'operation': 'FileWrite', 'file_path': f'C:\\Data\\file_{i}.txt'})
            self.on_event_callback({'pid': malware_pid, 'process_name': 'unknown_cryptor.exe', 'operation': 'FileRename', 'file_path': f'C:\\Data\\file_{i}.txt.locked'})

# 运行入口
if __name__ == "__main__":
    monitor = ETWMonitor()
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.stop_monitoring()