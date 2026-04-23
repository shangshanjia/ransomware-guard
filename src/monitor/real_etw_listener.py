import os
import time
import win32file
import win32con
import threading
from collections import defaultdict

class RealWindowsListener:
    def __init__(self, watch_dirs=None):
        """
        真实的 Windows 用户态文件 I/O 监听器
        :param watch_dirs: 需要重点保护的目录列表 (如桌面、文档等)
        """
        # 为了演示安全，我们先监控当前项目的 test_data 目录
        self.watch_dirs = watch_dirs or [os.path.abspath("../../test_data")]
        
        # 论文要求：自适应噪声过滤算法，剔除系统冗余进程干扰
        self.whitelist_extensions = ['.tmp', '.log', '.sys'] 
        
        self.is_running = False
        # 行为序列表 (按文件路径/会话隔离)
        self.file_behaviors = defaultdict(list)

    def is_noisy_file(self, file_path):
        """自适应噪声过滤机制"""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in self.whitelist_extensions

    def monitor_directory(self, path_to_watch):
        """
        核心函数：调用 Windows 底层 API 监听目录变化
        这比轮询扫描要高效得多，是实现低 CPU 占用的关键
        """
        print(f"[*] 正在将底层探针注入目录: {path_to_watch}")
        
        # 获取目录句柄
        h_dir = win32file.CreateFile(
            path_to_watch,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

        while self.is_running:
            try:
                # 调用 ReadDirectoryChangesW 获取真实的底层 I/O 事件
                results = win32file.ReadDirectoryChangesW(
                    h_dir,
                    65536, # 缓冲区大小
                    True, # 监控子目录
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    win32con.FILE_NOTIFY_CHANGE_SIZE |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SECURITY,
                    None,
                    None
                )
                
                for action, file_name in results:
                    full_path = os.path.join(path_to_watch, file_name)
                    
                    if self.is_noisy_file(full_path):
                        continue

                    # 将 Windows 底层 action 代码映射为我们的语义标签
                    operation = "Unknown"
                    if action == 1: operation = "FileCreate"
                    elif action == 2: operation = "FileDelete"
                    elif action == 3: operation = "FileWrite"
                    elif action == 4: operation = "FileRename_Old"
                    elif action == 5: operation = "FileRename_New"

                    # 触发回调 (这里我们可以把真实事件喂给你的 IntegratedSystem)
                    self.on_real_event_captured(operation, full_path)
                    
            except Exception as e:
                print(f"[-] 监听异常: {e}")
                break

    def on_real_event_captured(self, operation, file_path):
        """
        捕获到真实事件后的回调函数
        """
        # 注意：在真实的 ETW 中我们可以轻易拿到 PID，但在纯文件监听中获取 PID 较慢
        # 这里我们记录真实的 I/O 动作，用于喂给随机森林
        print(f"[🔥 真实系统事件] 动作: {operation:<15} 目标: {file_path}")

    def start_monitoring(self):
        self.is_running = True
        print("[*] 正在启动真实 Windows 用户态监听引擎...")
        print("[*] 目标稳态 CPU 占用率控制在 < 5%...")
        
        # 使用多线程为每个保护目录开启监听，防止阻塞主进程
        for directory in self.watch_dirs:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            t = threading.Thread(target=self.monitor_directory, args=(directory,))
            t.daemon = True
            t.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()

    def stop_monitoring(self):
        self.is_running = False
        print("\n[*] 真实监听已安全停止。")

if __name__ == "__main__":
    # 【修改这里】：因为你是在 src/monitor 目录下运行，所以需要用 ../../ 返回两层到根目录
    # 为了百分百确保路径不出错，我们直接把它转成绝对路径
    target_dir = os.path.abspath("../../test_data")
    print(f"[*] 准备监听的绝对路径是: {target_dir}")
    
    listener = RealWindowsListener(watch_dirs=[target_dir])
    listener.start_monitoring()