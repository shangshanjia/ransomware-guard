import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

def retrain_with_real_data(csv_path="data/real_training_data.csv"):
    print("[*] 正在启动真实数据清洗与模型重训引擎...")
    
    if not os.path.exists(csv_path):
        print(f"[-] 找不到数据集 {csv_path}。请先运行 main.py 收集数据！")
        return

    # 1. 数据加载与清洗
    df = pd.read_csv(csv_path)
    print(f"[+] 成功加载真实数据集，共计 {len(df)} 条行为特征记录。")
    
    # 检查是否有恶意样本 (Label == 1)
    if 1 not in df['Label'].values:
        print("[-] 警告：你的数据集中只有正常行为(Label=0)，缺少勒索病毒样本(Label=1)。")
        print("[-] 请先运行 simulate_attack.py，并将 CSV 中对应的行标签手动改为 1！")
        return

    # 提取特征 (X) 和 标签 (y)
    # 注意：我们这里加入了 SetInfo 等缺失维度补齐，保持与原模型兼容
    X = df[['Writes', 'Renames', 'Deletes', 'Max_Entropy']].copy()
    X['SetInfo'] = 0 # 为了兼容之前特征矩阵维度的占位符
    X['Risk_Flag'] = X['Max_Entropy'].apply(lambda e: 1 if e > 7.0 else 0)
    
    # 重排列特征顺序以严格匹配旧模型输入
    X = X[['Writes', 'Renames', 'Deletes', 'SetInfo', 'Max_Entropy', 'Risk_Flag']]
    y = df['Label']

    # 2. 划分训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 3. 训练最新版随机森林模型
    print("[*] 正在基于真实行为特征拟合 Random Forest 决策树...")
    clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)
    
    # 4. 模型评估 (把这段输出截图，就是论文第五章最好的素材！)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print("\n" + "="*40)
    print(f"[+] 真实环境重新训练完成！")
    print(f"[+] 模型准确率 (Accuracy): {acc * 100:.2f}%")
    print("详细分类报告:\n", classification_report(y_test, y_pred))
    print("="*40 + "\n")
    
    # 5. 保存并覆盖旧的假模型
    model_path = "models/rf_ransomware_model.joblib"
    joblib.dump(clf, model_path)
    print(f"[+] 全新实战级模型已保存并覆盖至: {model_path}")
    print("[+] 你的系统现在已经拥有了真正的实战大脑！")

if __name__ == "__main__":
    retrain_with_real_data()
