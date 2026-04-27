import math
import collections

def calculate_entropy(data):
    """
    计算数据块的香农熵
    :param data: bytes类型的数据
    :return: 熵值 (0.0 - 8.0)
    """
    if not data:
        return 0
    # 统计每个字节出现的频率
    counter = collections.Counter(data)
    len_data = len(data)
    # 应用香农熵公式: H = -Σ P(x) * log2(P(x))
    entropy = -sum((count / len_data) * math.log2(count / len_data) for count in counter.values())
    return entropy

# 测试示例
normal_text = b"This is a normal document with repetitive patterns."
encrypted_sample = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\xed\x9d\x07..." # 模拟加密流

print(f"正常文本熵值: {calculate_entropy(normal_text):.4f}")
print(f"疑似加密流熵值: {calculate_entropy(encrypted_sample):.4f}")