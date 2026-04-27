import os
import time

# 设定目标目录（必须是你的系统正在保护的目录）
target_dir = r"C:\Users\root\Desktop\Ransomware_Guard\test_data"

def simulate_apt_ransomware():
    print("="*60)
    print(f"[☠️ 恶意进程] 高级持续性威胁 (APT) 慢速逃逸模式 已启动！")
    print(f"[☠️ 恶意进程] 当前进程真实 PID: {os.getpid()}")
    print("="*60)

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    try:
        # 【核心修改】：分为 20 波攻击，每波加密 5 个文件，中间穿插休息
        # 即使防守方找 PID 需要 2-3 秒，病毒也绝对撑不到最后一波！
        for batch in range(1, 21):
            print(f"\n[*] >>> 发起第 {batch} 波加密攻击 <<<")
            
            for i in range(1, 6):
                file_index = (batch - 1) * 5 + i
                file_path = os.path.join(target_dir, f"company_finance_report_{file_index}.xlsx")
                
                # 1. 高熵写入
                print(f"  [-] 正在加密目标: {os.path.basename(file_path)}")
                with open(file_path, "wb") as f:
                    f.write(os.urandom(4096))
                    
                # 2. 更改后缀
                locked_path = file_path + ".WannaCry"
                os.rename(file_path, locked_path)
                
                # 动作极快
                time.sleep(0.1)
                
            # 💡 核心测试点：打完一波，休眠 2 秒（给防守方主程序溯源找 PID 的时间）
            print("[zZz] 狡猾的模拟病毒开始休眠 (企图切断行为序列特征)...")
            time.sleep(2) 

        print("\n[*] 所有波次攻击均已完成，准备弹出勒索信...")
        time.sleep(10) 

    except PermissionError:
        print("\n[!] 权限拒绝：文件已被安全引擎强行锁定！")
    except ProcessLookupError:
        pass
    except Exception as e:
        print(f"\n[!] 恶意进程遭遇异常终止 (被系统成功截杀): {e}")

if __name__ == "__main__":
    simulate_apt_ransomware()
