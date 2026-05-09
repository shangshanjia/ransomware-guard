# augment_human_samples.py
# 功能：
# 基于已经采集到的 human_normal_samples.csv，
# 对真实手动样本进行轻微扰动扩展，生成更多正常样本。
#
# 输入：data/human_normal_samples.csv
# 输出：data/human_normal_samples_augmented.csv

import os
import random
import pandas as pd


BASE_DIR = r"C:\Users\root\Desktop\Ransomware_Guard"

INPUT_PATH = os.path.join(BASE_DIR, "data", "human_normal_samples.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "human_normal_samples_augmented.csv")

FEATURE_COLUMNS = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
    "entropy",
    "entropy_risk",
    "label"
]


TARGET_TOTAL = 200


def clamp(value, low, high):
    return max(low, min(high, value))


def perturb_count(value, max_value):
    """
    对操作次数做小幅扰动。
    正常手动行为不应该突然变成特别高频。
    """
    value = int(value)

    delta = random.choice([-1, 0, 0, 1])

    # 少量情况下允许稍大一点的变化
    if random.random() < 0.15:
        delta += random.choice([-2, 2])

    return clamp(value + delta, 0, max_value)


def perturb_entropy(entropy):
    """
    对熵值做小幅扰动。
    保留原始分布：
    0.0 附近仍然保持 0；
    1~2、4~5、6.4、7.9 这些区间做轻微浮动。
    """
    entropy = float(entropy)

    # 0 熵通常代表删除、空文件、文件不存在或读取失败，不强行改成非 0
    if entropy == 0.0:
        if random.random() < 0.85:
            return 0.0
        return round(random.uniform(1.0, 2.2), 4)

    # 高熵正常文件，例如图片、zip、pdf
    if entropy >= 7.5:
        return round(clamp(entropy + random.uniform(-0.08, 0.05), 7.55, 7.9999), 4)

    # 中等熵办公文件
    if 6.0 <= entropy < 7.5:
        return round(clamp(entropy + random.uniform(-0.12, 0.12), 5.8, 7.2), 4)

    # 普通文本、CSV、日志
    if 3.0 <= entropy < 6.0:
        return round(clamp(entropy + random.uniform(-0.35, 0.35), 2.8, 6.2), 4)

    # 低熵重复内容
    return round(clamp(entropy + random.uniform(-0.2, 0.3), 0.5, 3.0), 4)


def generate_augmented_row(seed_row):
    """
    基于一条真实手动样本生成一条扰动样本。
    """
    write_count = perturb_count(seed_row["write_count"], max_value=60)
    rename_count = perturb_count(seed_row["rename_count"], max_value=5)
    delete_count = perturb_count(seed_row["delete_count"], max_value=15)
    setinfo_count = 0

    entropy = perturb_entropy(seed_row["entropy"])
    entropy_risk = 1 if entropy > 7.5 else 0

    return {
        "write_count": write_count,
        "rename_count": rename_count,
        "delete_count": delete_count,
        "setinfo_count": setinfo_count,
        "entropy": entropy,
        "entropy_risk": entropy_risk,
        "label": 0
    }


def clean_df(df):
    df = df[FEATURE_COLUMNS].copy()

    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna()
    df["write_count"] = df["write_count"].astype(int)
    df["rename_count"] = df["rename_count"].astype(int)
    df["delete_count"] = df["delete_count"].astype(int)
    df["setinfo_count"] = df["setinfo_count"].astype(int)
    df["entropy_risk"] = df["entropy_risk"].astype(int)
    df["label"] = 0

    return df


def main():
    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError(f"未找到输入文件：{INPUT_PATH}")

    df = pd.read_csv(INPUT_PATH)
    df = clean_df(df)

    current_count = len(df)

    if current_count == 0:
        raise ValueError("human_normal_samples.csv 为空，无法扩展。")

    print(f"[+] 已读取真实手动样本：{current_count} 条")

    if current_count >= TARGET_TOTAL:
        final_df = df.sample(n=TARGET_TOTAL, random_state=42).reset_index(drop=True)
    else:
        need_count = TARGET_TOTAL - current_count
        print(f"[+] 需要扩展样本：{need_count} 条")

        augmented_rows = []

        for _ in range(need_count):
            seed_row = df.sample(n=1).iloc[0]
            new_row = generate_augmented_row(seed_row)
            augmented_rows.append(new_row)

        aug_df = pd.DataFrame(augmented_rows, columns=FEATURE_COLUMNS)

        final_df = pd.concat([df, aug_df], ignore_index=True)
        final_df = final_df.sample(frac=1, random_state=2026).reset_index(drop=True)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    final_df.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")

    print(f"[+] 扩展后人工正常样本数量：{len(final_df)}")
    print(f"[+] 保存位置：{OUTPUT_PATH}")

    print("\n[+] 熵值分布预览：")
    print(final_df["entropy"].describe())

    print("\n[+] entropy_risk 分布：")
    print(final_df["entropy_risk"].value_counts())

    print("\n[+] 操作计数预览：")
    print(final_df[["write_count", "rename_count", "delete_count"]].describe())


if __name__ == "__main__":
    main()
