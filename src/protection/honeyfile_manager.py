import os
import ctypes
import random
import string
from datetime import datetime

class HoneyfileManager:
    def __init__(self, target_dirs):
        self.target_dirs = target_dirs
        self.deployed_traps = set()
        # 常见的高价值扩展名，吸引勒索病毒优先加密
        self.lure_extensions = ['.xlsx', '.docx', '.pptx', '.pdf']

    def _generate_dynamic_name(self):
        """生成随机化的高价值诱饵文件名 (防范静态规则绕过)"""
        # 前缀通常加特殊符号（如 _ 或 ~）可确保在系统默认排序中排在最前面，被优先遍历
        date_str = datetime.now().strftime("%Y%m")
        random_str = ''.join(random.choices(string.ascii_lowercase, k=4))
        ext = random.choice(self.lure_extensions)
        return f"_财务备份_{date_str}_{random_str}{ext}"

    def deploy(self):
        print("[*] 正在部署动态隐蔽诱饵阵列 (Dynamic Honeyfiles)...")
        for directory in self.target_dirs:
            os.makedirs(directory, exist_ok=True)
            
            # 动态生成 2-3 个诱饵
            for _ in range(random.randint(2, 3)):
                honey_name = self._generate_dynamic_name()
                honey_path = os.path.join(directory, honey_name)
                
                # 写入极具迷惑性的乱码/加密文本（提高诱惑力）
                with open(honey_path, "wb") as f:
                    f.write(os.urandom(2048)) 
                
                # 【底层调用】：赋予系统级强制隐藏属性 (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(honey_path, 0x02 | 0x04)
                except:
                    pass
                
                self.deployed_traps.add(os.path.abspath(honey_path))
        print(f"[+] 部署完毕，共埋设 {len(self.deployed_traps)} 个高隐蔽陷阱。")

    def is_tampered(self, event_file_path):
        """O(1) 极速匹配"""
        return os.path.abspath(event_file_path) in self.deployed_traps
