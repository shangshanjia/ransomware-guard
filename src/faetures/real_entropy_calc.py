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

if __name__ == "__main__":
    # 临时测试一下
    # 你可以在 test_data 里放一个普通的 txt 和一个压缩包 (zip/rar) 当作加密文件测试
    test_file = "../../test_data/1.txt"  # 随便建个文本
    print(f"文件 {test_file} 的真实熵值为: {calculate_real_entropy(test_file):.4f}")