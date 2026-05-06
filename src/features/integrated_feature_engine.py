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
            'SetInfo': 4  # 原始事件名
        }
        self.window_size = 20 # 滑动窗口大小

    def calculate_shannon_entropy(self, file_path):
        """计算文件头部 4KB 的 Shannon 熵"""
        try:
            if not os.path.exists(file_path):
                return 0.0
            with open(file_path, 'rb') as f:
                data = f.read(4096)
            if not data:
                return 0.0

            counter = Counter(data)
            len_data = len(data)
            entropy = -sum((count / len_data) * math.log2(count / len_data) for count in counter.values())
            return entropy
        except:
            return 0.0

    def get_feature_vector(self, api_sequence, last_file_path):
        """
        核心：将时序操作频率与文件信息熵相结合
        输出特征向量列名与训练脚本一致
        """
        # 1. 统计频率特征
        write_count = api_sequence.count('FileWrite')
        rename_count = api_sequence.count('FileRename')
        delete_count = api_sequence.count('FileDelete')
        setinfo_count = api_sequence.count('SetInfo')  # 统一列名

        # 2. 提取内容特征
        current_entropy = self.calculate_shannon_entropy(last_file_path)
        entropy_risk = 1 if current_entropy > 7.5 else 0

        # 3. 构造融合特征向量: [write_count, rename_count, delete_count, setinfo_count, entropy, entropy_risk]
        combined_vector = [write_count, rename_count, delete_count, setinfo_count, current_entropy, entropy_risk]

        # 转换为 AI 模型所需的矩阵格式
        return np.array([combined_vector]), current_entropy
