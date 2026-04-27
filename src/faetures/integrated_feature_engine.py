import numpy as np
from collections import Counter
import math
import os

class IntegratedFeatureEngine:
    def __init__(self):
        # 论文定义的关键行为语义标签 (对齐 3.4 节)
        self.semantic_map = {
            'FileWrite': 1,
            'FileRename': 2,
            'FileDelete': 3,
            'SetInfo': 4
        }
        self.window_size = 20 # 论文中提到的滑动窗口大小

    def calculate_shannon_entropy(self, file_path):
        """对齐论文 3.4 节：计算待写入数据块的混乱度"""
        try:
            if not os.path.exists(file_path): return 0.0
            with open(file_path, 'rb') as f:
                # 仅读取头部 4KB，确保阻断延迟 < 35ms (对齐 5.2 节指标)
                data = f.read(4096)
            if not data: return 0.0
            
            counter = Counter(data)
            len_data = len(data)
            # 应用 Shannon 公式
            entropy = -sum((count/len_data) * math.log2(count/len_data) for count in counter.values())
            return entropy
        except:
            return 0.0

    def get_feature_vector(self, api_sequence, last_file_path):
        """
        核心：将时序操作频率与文件信息熵相结合 (对齐 1.2 节)
        """
        # 1. 统计频率特征
        api_counts = [api_sequence.count(op) for op in ['FileWrite', 'FileRename', 'FileDelete', 'SetInfo']]
        
        # 2. 提取内容特征
        current_entropy = self.calculate_shannon_entropy(last_file_path)
        
        # 3. 构造融合特征向量: [频率1, 频率2, 频率3, 频率4, 信息熵, 风险标志]
        # 风险标志：当熵值 > 7.5 时标记为高随机性数据 (密文)
        entropy_risk = 1 if current_entropy > 7.5 else 0
        
        combined_vector = api_counts + [current_entropy, entropy_risk]
        
        # 转换为 AI 模型所需的矩阵格式
        return np.array([combined_vector]), current_entropy
