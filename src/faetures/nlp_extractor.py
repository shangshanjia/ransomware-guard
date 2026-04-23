import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer


class BehaviorProcessor:
    def __init__(self, n_gram_range=(2, 3)):
        """
        初始化语义处理器
        :param n_gram_range: N-gram的范围，捕获连续行为的关联
        """
        self.vectorizer = CountVectorizer(ngram_range=n_gram_range, analyzer='word')

    def raw_events_to_sequence(self, events_list):
        """
        将原始ETW事件流转换为行为句子
        例如: ['Open', 'Read', 'Write'] -> "Open Read Write"
        """
        return " ".join(events_list)

    def extract_features(self, corpus):
        """
        利用TF-IDF或N-gram提取特征矩阵
        """
        X = self.vectorizer.fit_transform(corpus)
        return X, self.vectorizer.get_feature_names_out()


# --- 模拟中等强度的行为数据 ---
# 正常行为：打开-读取-关闭
normal_behavior = ["FileOpen", "FileRead", "FileClose", "FileOpen", "FileRead"]
# 勒索行为：打开-读取-写入(加密)-重命名-删除
ransom_behavior = ["FileOpen", "FileRead", "FileWrite", "FileRename", "FileDelete"]

processor = BehaviorProcessor()
corpus = [
    processor.raw_events_to_sequence(normal_behavior),
    processor.raw_events_to_sequence(ransom_behavior)
]

X, features = processor.extract_features(corpus)
print(f"生成的特征维度: {features}")