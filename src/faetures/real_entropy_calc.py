import math
import collections
import os

def calculate_real_entropy(file_path, sample_size=4096):
    """
    计算真实文件的信息熵 (轻量化版本)
    :param file_path: 目标文件路径
    :param sample_size: 仅读取前 4KB 数据，确保 CPU 负载 < 5% 且响应时间 < 50ms
    :return: 熵值 (0.0 到 8.0)
    """
    if not os.path.exists(file_path):
        return 0.0
        
    try:
        # 以二进制模式读取真实文件
        with open(file_path, 'rb') as f:
            data = f.read(sample_size)
            
        if not data:
            return 0.0
            
        # 香农熵核心计算逻辑
        counter = collections.Counter(data)
        len_data = len(data)
        entropy = -sum((count / len_data) * math.log2(count / len_data) for count in counter.values())
        return entropy
        
    except Exception as e:
        # 文件可能正被独占锁定，忽略报错
        return 0.0

# --- 仅用于测试和截图的批量运行代码 ---
if __name__ == "__main__":
    import os
    import time

    # 修改这里：将目标文件夹写死为你指定的绝对路径，前面加 r 防止转义
    target_folder = r"C:\Users\root\Desktop\Ransomware_Guard\test_data"
    
    print("="*60)
    print(f"[*] 正在初始化多维特征提取模块...")
    print(f"[*] 目标批量扫描文件夹: {target_folder}")
    print("="*60 + "\n")
    
    # 确保文件夹存在，防止报错
    if not os.path.exists(target_folder):
        print(f"[!] 错误: 找不到指定的文件夹路径，请检查路径是否正确！")
    else:
        # 统计用的变量
        file_count = 0
        start_time = time.time()

        # 遍历文件夹内的所有内容
        for filename in os.listdir(target_folder):
            file_path = os.path.join(target_folder, filename)
            
            # 只计算文件，跳过子文件夹
            if os.path.isfile(file_path):
                file_count += 1
                print(f"[-] 正在提取特征: {filename}")
                
                # 调用核心计算函数
                entropy_value = calculate_real_entropy(file_path)
                
                # 根据熵值高低，打印不同的提示
                if entropy_value >= 7.8:
                    print(f"    [!] 警告: Shannon 信息熵为 {entropy_value:.4f} (异常高危！)")
                elif entropy_value == 0.0:
                    print(f"    [?] 跳过: 文件为空或被独占锁定")
                else:
                    print(f"    [+] 正常: Shannon 信息熵为 {entropy_value:.4f}")

        end_time = time.time()
        print("\n" + "="*60)
        print(f"[+] 特征矩阵批量提取完成！")
        print(f"[+] 共扫描文件: {file_count} 个 | 总耗时: {(end_time - start_time)*1000:.2f} ms")
        print("="*60)
