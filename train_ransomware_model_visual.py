# train_ransomware_model_visual.py
# 一条龙训练流程：合并数据、训练随机森林、评估并可视化混淆矩阵

import os
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ========================
# 基于脚本位置动态获取路径
# ========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NORMAL_PATH = os.path.join(BASE_DIR, 'data', 'normal_samples_final.csv')
RANSOM_PATH = os.path.join(BASE_DIR, 'data', 'ransomware_samples_final.csv')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'rf_ransomware_model.joblib')
os.makedirs(MODEL_DIR, exist_ok=True)

# ========================
# 读取数据
# ========================
normal = pd.read_csv(NORMAL_PATH)
ransom = pd.read_csv(RANSOM_PATH)

normal['label'] = 0
ransom['label'] = 1

data = pd.concat([normal, ransom], ignore_index=True)

# ========================
# 特征与标签
# ========================
features = ['write_count','rename_count','delete_count','setinfo_count','entropy','entropy_risk']
X = data[features]
y = data['label']

# ========================
# 划分训练/测试集
# ========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, stratify=y, random_state=42
)

# ========================
# 训练随机森林
# ========================
rf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
rf.fit(X_train, y_train)

# ========================
# 预测与评估
# ========================
y_pred = rf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# ========================
# 可视化混淆矩阵
# ========================
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal','Ransom'], yticklabels=['Normal','Ransom'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()

# ========================
# 保存模型
# ========================
joblib.dump(rf, MODEL_PATH)
print(f"Model saved at {MODEL_PATH}")
