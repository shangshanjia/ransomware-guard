# -*- coding: utf-8 -*-

import os
import ctypes
import random
import string
from datetime import datetime


class HoneyfileManager:
    def __init__(self, target_dirs):
        self.target_dirs = target_dirs
        self.deployed_traps = set()
        self.lure_extensions = [".xlsx", ".docx", ".pptx", ".pdf"]

    def _generate_dynamic_name(self):
        """
        生成随机化高价值诱饵文件名。
        """
        date_str = datetime.now().strftime("%Y%m")
        random_str = "".join(random.choices(string.ascii_lowercase, k=4))
        ext = random.choice(self.lure_extensions)
        return f"_财务备份_{date_str}_{random_str}{ext}"

    def deploy(self):
        """
        部署动态诱饵文件。

        修复点：
        1. 每次重新部署前清空 deployed_traps，避免旧诱饵路径长期残留。
        2. 如果目录中已有诱饵文件，先纳入保护集合，不重复创建过多文件。
        3. 每个目录最多保持 2-3 个诱饵文件，避免热加载后诱饵数量不断增加。
        """
        print("[*] 正在部署动态隐蔽诱饵阵列 (Dynamic Honeyfiles)...")

        self.deployed_traps.clear()

        total_count = 0

        for directory in self.target_dirs:
            os.makedirs(directory, exist_ok=True)

            existing_honeyfiles = []

            try:
                for name in os.listdir(directory):
                    if name.startswith("_财务备份_"):
                        full_path = os.path.abspath(os.path.join(directory, name))
                        if os.path.isfile(full_path):
                            existing_honeyfiles.append(full_path)
            except Exception:
                existing_honeyfiles = []

            # 如果已经有 2 个以上诱饵文件，则直接复用，不再疯狂新增
            if len(existing_honeyfiles) >= 2:
                for path in existing_honeyfiles:
                    self.deployed_traps.add(os.path.abspath(path))
                    total_count += 1
                continue

            # 不足 2 个时补齐到 2-3 个
            target_count = random.randint(2, 3)
            need_create = max(0, target_count - len(existing_honeyfiles))

            for path in existing_honeyfiles:
                self.deployed_traps.add(os.path.abspath(path))
                total_count += 1

            for _ in range(need_create):
                honey_name = self._generate_dynamic_name()
                honey_path = os.path.abspath(os.path.join(directory, honey_name))

                try:
                    with open(honey_path, "wb") as f:
                        f.write(os.urandom(2048))

                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(
                            honey_path,
                            0x02 | 0x04
                        )
                    except Exception:
                        pass

                    self.deployed_traps.add(honey_path)
                    total_count += 1

                except Exception as e:
                    print(f"[-] 诱饵文件部署失败: {honey_path}, 原因: {e}")

        print(f"[+] 部署完毕，共埋设 {total_count} 个高隐蔽陷阱。")

    def is_tampered(self, event_file_path):
        """
        判断事件路径是否命中诱饵文件。
        """
        return os.path.abspath(event_file_path) in self.deployed_traps
