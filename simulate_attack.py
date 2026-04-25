# -*- coding: utf-8 -*-
import os
import time
import sys

# 设定目标目录（必须是你的系统正在保护的目录）
target_dir = r"C:\Users\root\Desktop\Ransomware_Guard\test_data"

def simulate_ransomware():
    print("="*60)
    print(f"[☠️ 恶意进程] 模拟勒索变种 (Ransomware Simulator) 已启动！")
    print(f"[☠️ 恶意进程] 当前进程真实 PID: {os.getpid()}")
    print("="*60)
    print("[*] 正在寻找目标文件进行高频遍历与加密...")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    try:
        # 连续发起多次高熵写入与重命名，必将触发 AI 或 Watchdog！
        for i in range(1, 10):
            file_path = os.path.join(target_dir, f"company_finance_report_{i}.xlsx")
            
            # 1. 模拟打开并写入被加密的乱码数据 (高熵值)
            print(f"  [-] 正在加密锁定目标: {os.path.basename(file_path)} ...")
            with open(file_path, "wb") as f:
                # 写入 4KB 完全随机的字节流，模拟高级加密标准(AES)的密文，信息熵极高
                f.write(os.urandom(4096))
                
            # 2. 模拟勒索病毒修改后缀名
            locked_path = file_path + ".WannaCry"
            os.rename(file_path, locked_path)
            
            # 短暂休眠，给底层探针抓取和 AI 推理留出极短的窗口期
            time.sleep(0.2)
            
        print("[*] 所有文件加密完成，准备弹出勒索信...")
        # 如果程序能走到这里，说明你的防御系统没起作用
        time.sleep(10) 

    except PermissionError:
        print("\n[!] 权限拒绝：文件已被安全引擎强行锁定！")
    except ProcessLookupError:
         pass
    except Exception as e:
        print(f"\n[!] 恶意进程遭遇异常终止 (被系统截杀): {e}")

if __name__ == "__main__":
    simulate_ransomware()
