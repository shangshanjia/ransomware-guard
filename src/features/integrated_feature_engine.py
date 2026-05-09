# -*- coding: utf-8 -*-

import os
import math
import numpy as np
from collections import Counter


class IntegratedFeatureEngine:
    """
    融合特征工程模块。

    特征维度：
    1. Write 次数
    2. Rename 次数
    3. Delete 次数
    4. SetInfo 次数
    5. 文件信息熵
    6. 熵风险点
    """

    FEATURE_COLUMNS = [
        "write_count",
        "rename_count",
        "delete_count",
        "setinfo_count",
        "entropy",
        "entropy_risk"
    ]

    def __init__(self):
        self.semantic_map = {
            "FileWrite": 1,
            "FileRename": 2,
            "FileDelete": 3,
            "SetInfo": 4
        }

        self.window_size = 20

    def calculate_shannon_entropy(self, file_path):
        """
        计算文件前 4KB 的 Shannon 熵。
        """
        try:
            if not os.path.exists(file_path):
                return 0.0

            with open(file_path, "rb") as f:
                data = f.read(4096)

            if not data:
                return 0.0

            counter = Counter(data)
            data_len = len(data)

            entropy = -sum(
                (count / data_len) * math.log2(count / data_len)
                for count in counter.values()
            )

            return entropy

        except Exception:
            return 0.0

    def get_feature_vector(self, api_sequence, last_file_path):
        """
        将行为序列和文件熵转换为模型输入特征。

        返回：
        features: numpy.ndarray，形状为 (1, 6)
        current_entropy: 当前文件熵值
        """
        write_count = api_sequence.count("FileWrite")
        rename_count = api_sequence.count("FileRename")
        delete_count = api_sequence.count("FileDelete")
        setinfo_count = api_sequence.count("SetInfo")

        current_entropy = self.calculate_shannon_entropy(last_file_path)
        entropy_risk = 1 if current_entropy > 7.5 else 0

        combined_vector = [
            write_count,
            rename_count,
            delete_count,
            setinfo_count,
            current_entropy,
            entropy_risk
        ]

        return np.array([combined_vector]), current_entropy

    def get_feature_columns(self):
        """
        返回特征列名，供模型输入对齐或调试使用。
        """
        return list(self.FEATURE_COLUMNS)
