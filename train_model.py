import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
import time


def generate_mock_data(num_samples=1000):
    """
    生成模拟的训练数据 (实际应用中，这里应读取你从 ETW 采集并经过 feature_fusion 处理后的 CSV 数据)
    特征维度定义: [Write次数, Rename次数, Delete次数, SetInfo次数, 最大熵值, 熵值风险点(0或1)]
    标签定义: 0 为正常软件, 1 为勒索软件
    """
    X = []
    y = []

    for _ in range(num_samples):
        # 模拟 50% 的正常软件行为 (低文件操作，低熵值)
        is_ransomware = np.random.choice([0, 1])
        if is_ransomware == 0:
            writes = np.random.randint(0, 50)
            renames = np.random.randint(0, 5)
            deletes = np.random.randint(0, 2)
            setinfo = np.random.randint(0, 10)
            entropy = np.random.uniform(2.0, 5.5)  # 正常文件熵值较低
            risk = 0
            X.append([writes, renames, deletes, setinfo, entropy, risk])
            y.append(0)
        # 模拟 50% 的勒索软件行为 (高文件写入/重命名，极高熵值)
        else:
            writes = np.random.randint(100, 5000)
            renames = np.random.randint(50, 2000)
            deletes = np.random.randint(10, 500)
            setinfo = np.random.randint(20, 100)
            entropy = np.random.uniform(7.2, 8.0)  # 加密文件熵值极高
            risk = 1
            X.append([writes, renames, deletes, setinfo, entropy, risk])
            y.append(1)

    return np.array(X), np.array(y)


def train_ransomware_model():
    print("[*] 正在加载和准备特征数据...")
    X, y = generate_mock_data(num_samples=2000)

    # 划分训练集和测试集 (80% 训练, 20% 测试)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[*] 开始训练轻量级随机森林模型...")
    # 这里的参数经过轻量化设计：
    # n_estimators=50: 树的数量，50棵树在精度和速度上能取得很好的平衡，满足 <50ms 的推理要求
    # max_depth=10: 限制树的深度，防止模型过大和过拟合
    clf = RandomForestClassifier(n_estimators=50, max_depth=10, n_jobs=-1, random_state=42)

    start_time = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - start_time
    print(f"[+] 训练完成! 耗时: {train_time:.4f} 秒")

    # --- 模型评估 ---
    print("\n[*] 正在进行模型评估...")
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"[-] 整体准确率 (Accuracy): {acc * 100:.2f}%")
    print(f"[-] 误报率 (False Positive Rate): {false_positive_rate * 100:.2f}% (目标是 <6%)")
    print("\n详细分类报告:\n", classification_report(y_test, y_pred))

    # 保存模型到文件，供监听器调用
    model_path = "models/rf_ransomware_model.joblib"
    # 注意：运行前请确保项目根目录下存在 models 文件夹
    import os
    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, model_path)
    print(f"[+] 模型已保存至: {model_path}")


if __name__ == "__main__":
    train_ransomware_model()