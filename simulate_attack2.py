import os
import time
import threading

# 设定目标目录
target_dir = r"C:\Users\root\Desktop\Ransomware_Guard\test_data"

def malicious_worker(file_path):
    """单线程执行高熵写入与重命名"""
    try:
        # 写入高熵密文
        with open(file_path, "wb") as f:
            f.write(os.urandom(4096))
        # 极速重命名
        locked_path = file_path + ".LockBit"
        os.rename(file_path, locked_path)
        # ⚠️ 为了让 Python 探针来得及抓人，给每个线程强行加 50 毫秒延迟
        time.sleep(0.05)
    except Exception:
        # 进程被系统击杀或文件被锁定时的静默处理
        pass

def simulate_high_concurrency_attack():
    print("="*60)
    print(f"[☠️ 恶意进程] LockBit 极速并发模式已启动！")
    print(f"[☠️ 恶意进程] 当前进程真实 PID: {os.getpid()}")
    print("="*60)

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # 1. 战前准备：瞬间生成 50 个待宰的测试文件
    print("[*] 正在瞬间生成 50 个测试文件...")
    target_files = []
    for i in range(1, 51):
        file_path = os.path.join(target_dir, f"concurrent_target_{i}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("正常办公数据" * 50)
        target_files.append(file_path)

    time.sleep(2) # 给 ETW 底层探针一点喘息和降噪的时间

    print("[*] 准备就绪！3, 2, 1... 发起多线程并发 I/O 风暴！")
    
    # 2. 核心对抗：瞬间开启 50 个线程同时去加密，测试 ETW 是否会丢包漏报！
    threads = []
    start_time = time.time()
    
    for file_path in target_files:
        t = threading.Thread(target=malicious_worker, args=(file_path,))
        threads.append(t)
        t.start()

    # 等待所有恶意线程执行完毕
    for t in threads:
        t.join()

    end_time = time.time()
    print(f"\n[*] 并发攻击结束，总耗时: {end_time - start_time:.4f} 秒。")
    print("[*] 如果你能看到这条消息，且 50 个文件全被加密，说明你的防线被高并发击穿了！")

if __name__ == "__main__":
    simulate_high_concurrency_attack()
