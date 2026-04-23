import numpy as np


class RansomwareFeatureExtractor:
    def __init__(self):
        # 记录关键API的权重，后续用于随机森林输入
        self.critical_apis = ['FileWrite', 'FileRename', 'FileDelete', 'SetInfo']

    def create_feature_vector(self, api_sequence, max_entropy):
        """
        构造单条行为记录的特征向量
        :param api_sequence: 行为序列 (例如: ['Read', 'Write', 'Write'])
        :param max_entropy: 该进程产生的最大文件熵值
        """
        # 1. 统计关键API出现的频率 (简化的语义向量)
        api_counts = [api_sequence.count(api) for api in self.critical_apis]

        # 2. 加入熵值维度 (论文中的关键判定指标)
        # 我们假设熵值超过 7.0 是极度可疑的
        entropy_risk = 1 if max_entropy > 7.0 else 0

        # 3. 组合特征: [API频率..., 最大熵值, 熵值风险点]
        feature_vector = api_counts + [max_entropy, entropy_risk]
        return np.array(feature_vector)


# 模拟一个典型的勒索行为特征提取
behavior_seq = ['FileOpen', 'FileRead', 'FileWrite', 'FileWrite', 'FileRename']
peak_entropy = 7.92  # 模拟高熵值
extractor = RansomwareFeatureExtractor()
vector = extractor.create_feature_vector(behavior_seq, peak_entropy)

print(f"生成的复合特征向量: {vector}")
# 输出示例: [2, 1, 0, 0, 7.92, 1]
# 含义: [写2次, 改名1次, 删0次, SetInfo0次, 熵值7.92, 风险触发1]