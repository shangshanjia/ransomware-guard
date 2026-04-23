import os
import ctypes

class HoneyfileManager:
    def __init__(self, target_dirs=None):
        """
        初始化诱饵文件管理器
        :param target_dirs: 部署诱饵文件的目标目录列表。为防止污染你的真实环境，默认设为当前工程的 test_data 目录
        """
        self.target_dirs = target_dirs or ["./test_data"]
        self.deployed_honeyfiles = set()
        
        # 诱饵文件名设计技巧：下划线开头可以在勒索软件按字母顺序遍历时，被优先读取和加密，实现“早期阻断”
        self.file_names = [
            "_confidential_passwords.txt", 
            "_financial_report_2025.xlsx", 
            "_system_config_backup.docx"
        ]

    def deploy(self):
        """
        在目标目录下生成诱饵文件，并将其属性设置为“隐藏”
        """
        print("[*] 正在部署静默诱饵文件 (Honeyfiles)...")
        for directory in self.target_dirs:
            os.makedirs(directory, exist_ok=True)
            for name in self.file_names:
                file_path = os.path.join(directory, name)
                
                # 【新增修复】：如果文件已存在（上次运行残留的隐藏文件），先恢复正常属性
                if os.path.exists(file_path):
                    try:
                        # 0x80 代表 FILE_ATTRIBUTE_NORMAL (正常文件)
                        ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x80)
                    except Exception as e:
                        pass
                
                # 1. 写入伪造的诱饵数据
                with open(file_path, "w") as f:
                    f.write("CONFIDENTIAL DATA. DO NOT MODIFY OR DELETE.\n" * 10)
                
                # 2. 调用 Windows API 将文件设置为“隐藏” (FILE_ATTRIBUTE_HIDDEN = 0x02)
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x02)
                except Exception as e:
                    print(f"[-] 隐藏文件设置失败: {e}")
                    
                # 3. 记录绝对路径，用于后续的极速匹配
                abs_path = os.path.abspath(file_path)
                self.deployed_honeyfiles.add(abs_path)
                print(f"  [+] 部署成功: {abs_path}")

    def is_tampered(self, event_file_path):
        """
        双重验证核心逻辑：检查发生 I/O 操作的文件是否为我们的诱饵文件
        如果是，则直接绕过随机森林模型，实施一票否决式阻断！
        """
        abs_path = os.path.abspath(event_file_path)
        if abs_path in self.deployed_honeyfiles:
            return True
        return False

# --- 模块独立测试 ---
if __name__ == "__main__":
    manager = HoneyfileManager()
    manager.deploy()
    
    print("\n[*] 模拟 ETW 捕获到文件写入事件...")
    
    # 测试用例 1: 正常用户修改了普通文档
    normal_file = os.path.abspath("./test_data/my_thesis.docx")
    print(f"事件 1 -> 修改文件: {normal_file}")
    if manager.is_tampered(normal_file):
        print("[!!!] 🚨 触发诱饵陷阱！实施拦截！")
    else:
        print("[-] 安全：非诱饵文件，放行至随机森林模型进行行为研判。")
        
    print("-" * 40)
    
    # 测试用例 2: 勒索病毒不长眼，修改了我们布置的诱饵文件
    ransom_target = os.path.abspath("./test_data/_confidential_passwords.txt")
    print(f"事件 2 -> 修改文件: {ransom_target}")
    if manager.is_tampered(ransom_target):
        print("[!!!] 🚨 触发诱饵陷阱！检测到绝对恶意行为，直接绕过算法，执行零延迟阻断！")
    else:
        print("[-] 安全：非诱饵文件。")