# merge_normal_datasets.py
# 功能：
# 合并三份正常样本数据：
# 1. data/normal_samples.csv                  自动脚本采集样本
# 2. data/human_normal_samples.csv            真实人工操作样本
# 3. data/human_normal_samples_augmented.csv  基于人工样本扰动扩展的数据
#
# 输出：
# 1. data/normal_samples_final.csv            最终用于训练的正常样本，默认1000条
# 2. data/normal_samples_final_with_source.csv 带来源字段的审计版本
# 3. data/normal_merge_report.txt             合并报告

import os
import pandas as pd


BASE_DIR = r"C:\Users\root\Desktop\Ransomware_Guard"

AUTO_PATH = os.path.join(BASE_DIR, "data", "normal_samples.csv")
HUMAN_PATH = os.path.join(BASE_DIR, "data", "human_normal_samples.csv")
AUG_PATH = os.path.join(BASE_DIR, "data", "human_normal_samples_augmented.csv")

OUTPUT_PATH = os.path.join(BASE_DIR, "data", "normal_samples_final.csv")
OUTPUT_WITH_SOURCE_PATH = os.path.join(BASE_DIR, "data", "normal_samples_final_with_source.csv")
REPORT_PATH = os.path.join(BASE_DIR, "data", "normal_merge_report.txt")

FEATURE_COLUMNS = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
    "entropy",
    "entropy_risk",
    "label"
]

# 最终正常样本总量
TARGET_TOTAL = 1000

# 自动模拟样本建议保留数量
AUTO_KEEP = 800

# 人工侧样本总量，即 真实人工 + 人工扩展
HUMAN_SIDE_TOTAL = TARGET_TOTAL - AUTO_KEEP


def load_and_clean(path, source_name):
    """
    读取并清洗样本数据。
    """
    if not os.path.exists(path):
        print(f"[!] 文件不存在，跳过：{path}")
        return pd.DataFrame(columns=FEATURE_COLUMNS + ["source"])

    df = pd.read_csv(path)

    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"{path} 缺少字段：{missing}")

    df = df[FEATURE_COLUMNS].copy()

    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna()

    # 类型修正
    df["write_count"] = df["write_count"].astype(int)
    df["rename_count"] = df["rename_count"].astype(int)
    df["delete_count"] = df["delete_count"].astype(int)
    df["setinfo_count"] = df["setinfo_count"].astype(int)
    df["entropy"] = df["entropy"].astype(float)

    # 删除明显非法值
    df = df[df["write_count"] >= 0]
    df = df[df["rename_count"] >= 0]
    df = df[df["delete_count"] >= 0]
    df = df[df["setinfo_count"] >= 0]
    df = df[(df["entropy"] >= 0.0) & (df["entropy"] <= 8.0)]

    # 统一修正 entropy_risk 和 label
    df["entropy_risk"] = (df["entropy"] > 7.5).astype(int)
    df["label"] = 0

    df["source"] = source_name

    return df.reset_index(drop=True)


def add_entropy_band(df):
    """
    按熵值分段，方便从自动样本中保持熵值分布。
    """
    df = df.copy()

    def band(x):
        if x == 0:
            return "entropy_0"
        elif x < 3:
            return "entropy_low"
        elif x < 6:
            return "entropy_mid"
        elif x <= 7.5:
            return "entropy_mid_high"
        else:
            return "entropy_high"

    df["entropy_band"] = df["entropy"].apply(band)
    return df


def sample_by_entropy_band(df, n, random_state=42):
    """
    尽量按照原始熵值分布抽样。
    如果数据不足，则直接返回全部。
    """
    if len(df) <= n:
        return df.copy()

    df = add_entropy_band(df)

    sampled_parts = []

    band_counts = df["entropy_band"].value_counts(normalize=True)

    allocated = {}
    remaining = n

    bands = list(band_counts.index)

    for band in bands[:-1]:
        count = int(round(band_counts[band] * n))
        count = min(count, len(df[df["entropy_band"] == band]))
        allocated[band] = count
        remaining -= count

    if bands:
        last_band = bands[-1]
        allocated[last_band] = min(
            remaining,
            len(df[df["entropy_band"] == last_band])
        )

    for band, count in allocated.items():
        if count <= 0:
            continue

        part = df[df["entropy_band"] == band].sample(
            n=count,
            random_state=random_state
        )
        sampled_parts.append(part)

    sampled = pd.concat(sampled_parts, ignore_index=True)

    # 如果因为某些分段不足导致没抽够，则从剩余样本补齐
    if len(sampled) < n:
        need = n - len(sampled)
        used_index = set(sampled.index)

        remaining_df = df.drop(index=list(used_index), errors="ignore")

        if len(remaining_df) >= need:
            extra = remaining_df.sample(n=need, random_state=random_state + 1)
        else:
            extra = df.sample(n=need, replace=True, random_state=random_state + 1)

        sampled = pd.concat([sampled, extra], ignore_index=True)

    sampled = sampled.drop(columns=["entropy_band"], errors="ignore")
    sampled = sampled.sample(frac=1, random_state=random_state + 2).reset_index(drop=True)

    return sampled.head(n)


def remove_rows_already_in_human(aug_df, human_df):
    """
    human_normal_samples_augmented.csv 里通常包含原始人工样本。
    为避免重复，把与 human_normal_samples.csv 完全相同的行去掉。
    """
    if aug_df.empty or human_df.empty:
        return aug_df

    key_cols = FEATURE_COLUMNS

    human_keys = set(
        tuple(row) for row in human_df[key_cols].itertuples(index=False, name=None)
    )

    keep_rows = []

    for _, row in aug_df.iterrows():
        key = tuple(row[key_cols].tolist())
        if key not in human_keys:
            keep_rows.append(row)

    if not keep_rows:
        return pd.DataFrame(columns=aug_df.columns)

    return pd.DataFrame(keep_rows).reset_index(drop=True)


def main():
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

    auto_df = load_and_clean(AUTO_PATH, "auto_simulated")
    human_df = load_and_clean(HUMAN_PATH, "human_real")
    aug_df = load_and_clean(AUG_PATH, "human_augmented")

    print("[+] 原始数据读取完成")
    print(f"    自动模拟样本：{len(auto_df)}")
    print(f"    真实人工样本：{len(human_df)}")
    print(f"    人工扩展样本：{len(aug_df)}")

    # 去掉人工扩展数据中与真实人工数据完全重复的行
    aug_unique_df = remove_rows_already_in_human(aug_df, human_df)
    print(f"    去重后人工扩展样本：{len(aug_unique_df)}")

    # 1. 自动模拟样本：建议取 800 条
    auto_keep = min(AUTO_KEEP, len(auto_df))
    auto_part = sample_by_entropy_band(auto_df, auto_keep, random_state=42)

    # 2. 真实人工样本：尽量全部保留，但最多不超过人工侧总量
    human_real_keep = min(len(human_df), HUMAN_SIDE_TOTAL)
    human_real_part = human_df.sample(
        n=human_real_keep,
        random_state=43
    ) if human_real_keep > 0 else human_df

    # 3. 人工扩展样本：补足人工侧样本到 HUMAN_SIDE_TOTAL
    aug_need = HUMAN_SIDE_TOTAL - human_real_keep

    if aug_need > 0:
        if len(aug_unique_df) >= aug_need:
            aug_part = aug_unique_df.sample(n=aug_need, random_state=44)
        elif len(aug_unique_df) > 0:
            print("[!] 人工扩展样本不足，将使用有放回抽样补足。")
            aug_part = aug_unique_df.sample(n=aug_need, replace=True, random_state=44)
        else:
            print("[!] 人工扩展样本为空，将从真实人工样本中有放回抽样补足。")
            aug_part = human_df.sample(n=aug_need, replace=True, random_state=44)
            aug_part["source"] = "human_real_resampled"
    else:
        aug_part = pd.DataFrame(columns=FEATURE_COLUMNS + ["source"])

    # 4. 如果自动样本不足 800，则用人工扩展或自动有放回补齐到 1000
    final_with_source = pd.concat(
        [auto_part, human_real_part, aug_part],
        ignore_index=True
    )

    if len(final_with_source) < TARGET_TOTAL:
        need = TARGET_TOTAL - len(final_with_source)
        print(f"[!] 当前样本不足 {TARGET_TOTAL}，还需补充 {need} 条。")

        supplement_pool = pd.concat(
            [auto_df, human_df, aug_unique_df],
            ignore_index=True
        )

        if len(supplement_pool) == 0:
            raise ValueError("没有可用于补充的样本。")

        supplement = supplement_pool.sample(
            n=need,
            replace=len(supplement_pool) < need,
            random_state=45
        )
        supplement["source"] = "supplement_resampled"

        final_with_source = pd.concat(
            [final_with_source, supplement],
            ignore_index=True
        )

    # 5. 最终打乱
    final_with_source = final_with_source.sample(
        frac=1,
        random_state=2026
    ).reset_index(drop=True)

    final_with_source = final_with_source.head(TARGET_TOTAL)

    # 再次修正字段
    final_with_source["entropy_risk"] = (final_with_source["entropy"] > 7.5).astype(int)
    final_with_source["label"] = 0

    final_train = final_with_source[FEATURE_COLUMNS].copy()

    # 保存
    final_train.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")
    final_with_source.to_csv(OUTPUT_WITH_SOURCE_PATH, index=False, encoding="utf-8-sig")

    # 生成报告
    source_counts = final_with_source["source"].value_counts()
    entropy_risk_counts = final_with_source["entropy_risk"].value_counts()
    entropy_desc = final_with_source["entropy"].describe()
    op_desc = final_with_source[
        ["write_count", "rename_count", "delete_count", "setinfo_count"]
    ].describe()

    report_lines = []
    report_lines.append("正常样本合并报告")
    report_lines.append("=" * 40)
    report_lines.append(f"目标样本总数：{TARGET_TOTAL}")
    report_lines.append("")
    report_lines.append("输入数据：")
    report_lines.append(f"自动模拟样本 normal_samples.csv：{len(auto_df)}")
    report_lines.append(f"真实人工样本 human_normal_samples.csv：{len(human_df)}")
    report_lines.append(f"人工扩展样本 human_normal_samples_augmented.csv：{len(aug_df)}")
    report_lines.append(f"去重后人工扩展样本：{len(aug_unique_df)}")
    report_lines.append("")
    report_lines.append("最终来源分布：")
    report_lines.append(str(source_counts))
    report_lines.append("")
    report_lines.append("entropy_risk 分布：")
    report_lines.append(str(entropy_risk_counts))
    report_lines.append("")
    report_lines.append("entropy 描述统计：")
    report_lines.append(str(entropy_desc))
    report_lines.append("")
    report_lines.append("操作计数描述统计：")
    report_lines.append(str(op_desc))
    report_lines.append("")
    report_lines.append(f"训练用输出文件：{OUTPUT_PATH}")
    report_lines.append(f"带来源审计输出文件：{OUTPUT_WITH_SOURCE_PATH}")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print("\n[+] 合并完成")
    print(f"[+] 训练用正常样本：{OUTPUT_PATH}")
    print(f"[+] 带来源审计样本：{OUTPUT_WITH_SOURCE_PATH}")
    print(f"[+] 合并报告：{REPORT_PATH}")

    print("\n[+] 最终来源分布：")
    print(source_counts)

    print("\n[+] entropy_risk 分布：")
    print(entropy_risk_counts)

    print("\n[+] entropy 描述统计：")
    print(entropy_desc)


if __name__ == "__main__":
    main()
