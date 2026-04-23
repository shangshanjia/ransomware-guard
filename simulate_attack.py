import os
import time
import shutil

def simulate_ransomware_attack(target_dir="./test_data"):
    print("[💀 攻击模拟器] 正在启动高频加密脚本...")
    
    source_zip = os.path.join(target_dir, "test.zip")
    if not os.path.exists(source_zip):
        print("[-] 错误：请先在 test_data 文件夹里放一个名为 test.zip 的压缩包！")
        return

    print("[💀 攻击模拟器] 开始执行: 写入高熵数据 -> 重命名为.locked")
    
    start_time = time.time()
    
    # 连续生成 150 个高熵文件
    for i in range(1, 151):
        fake_file = os.path.join(target_dir, f"document_{i}.docx")
        locked_file = os.path.join(target_dir, f"document_{i}.docx.locked")
        
        # 动作 1：写入高熵数据
        shutil.copy2(source_zip, fake_file)
        
        # 动作 2：狡猾的重命名机制
        retry_count = 0
        while retry_count < 5:
            try:
                os.rename(fake_file, locked_file)
                break  
            except PermissionError:
                retry_count += 1
                time.sleep(0.05)
                
        # 【新增】：模拟勒索病毒底层计算 AES 加密时的 CPU 耗时 (10毫秒)
        time.sleep(0.01) 
                
    end_time = time.time()
    print(f"[💀 攻击模拟器] 攻击完成！生成 150 个文件耗时: {end_time - start_time:.4f} 秒")

if __name__ == "__main__":
    simulate_ransomware_attack()