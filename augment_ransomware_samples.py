import argparse
import shutil
from pathlib import Path

import numpy as np
import pandas as pd


BASE_DIR = Path(r"C:\Users\root\Desktop\Ransomware_Guard")

DEFAULT_INPUT = BASE_DIR / "data" / "ransomware_samples.csv"
DEFAULT_OUTPUT = BASE_DIR / "data" / "ransomware_samples_final.csv"
DEFAULT_REPORT = BASE_DIR / "data" / "ransomware_augment_report.txt"

FEATURE_COLUMNS = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
    "entropy",
    "entropy_risk",
    "label",
]

COUNT_COLUMNS = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
]


def load_and_clean(input_path: Path) -> pd.DataFrame:
    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在：{input_path}")

    df = pd.read_csv(input_path)

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"CSV 缺少必要列：{missing}")

    df = df[FEATURE_COLUMNS].copy()

    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna().copy()

    # 只保留勒索标签
    df = df[df["label"] == 1].copy()

    # 删除空窗口样本，例如：0,0,0,0,0.0,0,1
    empty_mask = (
        (df["write_count"] == 0)
        & (df["rename_count"] == 0)
        & (df["delete_count"] == 0)
        & (df["setinfo_count"] == 0)
        & (df["entropy"] == 0)
        & (df["entropy_risk"] == 0)
    )
    df = df[~empty_mask].copy()

    # 删除极端纯删除窗口：
    # 没有写入、没有重命名、没有熵风险，仅有大量删除。
    pure_delete_extreme = (
        (df["write_count"] == 0)
        & (df["rename_count"] == 0)
        & (df["setinfo_count"] == 0)
        & (df["entropy"] == 0)
        & (df["entropy_risk"] == 0)
        & (df["delete_count"] > 20)
    )
    df = df[~pure_delete_extreme].copy()

    # 删除明显异常值
    for col in COUNT_COLUMNS:
        df = df[df[col] >= 0]

    df = df[(df["entropy"] >= 0) & (df["entropy"] <= 8.0)].copy()

    for col in COUNT_COLUMNS:
        df[col] = df[col].round().astype(int)

    df["entropy"] = df["entropy"].round(4)
    df["entropy_risk"] = (df["entropy"] > 7.5).astype(int)
    df["label"] = 1

    df = df.reset_index(drop=True)

    if len(df) == 0:
        raise ValueError("清洗后没有有效勒索样本，不能扩增。")

    return df


def clip_by_quantile(value: float, series: pd.Series, low_q=0.03, high_q=0.97) -> float:
    low = float(series.quantile(low_q))
    high = float(series.quantile(high_q))

    if low == high:
        return max(0.0, value)

    return min(max(value, low), high)


def jitter_count(
    base_value: int,
    series: pd.Series,
    rng: np.random.Generator,
    strength: float,
) -> int:
    """
    对 write_count / rename_count / delete_count / setinfo_count 做小幅扰动。
    不是凭空随机，而是在真实采集分布附近生成。
    """
    if base_value <= 0:
        nonzero = series[series > 0]

        if len(nonzero) == 0:
            return 0

        # 少量概率把 0 扰动为真实分布里的低值
        if rng.random() < 0.12:
            sampled = int(rng.choice(nonzero.to_numpy()))
            return max(0, int(round(sampled * rng.uniform(0.5, 1.1))))

        return 0

    sigma = max(1.0, abs(base_value) * strength)
    value = rng.normal(loc=base_value, scale=sigma)
    value = clip_by_quantile(value, series)

    return max(0, int(round(value)))


def jitter_entropy(
    base_entropy: float,
    entropy_series: pd.Series,
    rng: np.random.Generator,
) -> float:
    """
    勒索样本一般表现为高熵写入。
    扩增时只在真实采集熵值范围内扰动，不生成真实样本中不存在的 8.0。
    """
    high_entropy = entropy_series[entropy_series > 7.5]

    if base_entropy <= 0:
        if len(high_entropy) > 0:
            base_entropy = float(rng.choice(high_entropy.to_numpy()))
        else:
            base_entropy = float(entropy_series.median())

    value = rng.normal(loc=base_entropy, scale=0.012)

    if len(high_entropy) > 0:
        low = max(7.50, float(high_entropy.quantile(0.03)))
    else:
        low = max(0.0, float(entropy_series.quantile(0.03)))

    # 关键修改：上限不超过真实采集样本最大熵值
    high = min(float(entropy_series.max()), 7.9999)

    value = min(max(value, low), high)

    return round(float(value), 4)


def augment_samples(
    real_df: pd.DataFrame,
    target: int,
    seed: int,
    jitter_strength: float,
) -> pd.DataFrame:
    if len(real_df) >= target:
        return real_df.sample(n=target, random_state=seed).reset_index(drop=True)

    rng = np.random.default_rng(seed)
    need = target - len(real_df)

    synthetic_rows = []

    for _ in range(need):
        base = real_df.sample(
            n=1,
            replace=True,
            random_state=int(rng.integers(0, 2**31 - 1)),
        ).iloc[0]

        write_count = jitter_count(
            int(base["write_count"]),
            real_df["write_count"],
            rng,
            jitter_strength,
        )
        rename_count = jitter_count(
            int(base["rename_count"]),
            real_df["rename_count"],
            rng,
            jitter_strength,
        )
        delete_count = jitter_count(
            int(base["delete_count"]),
            real_df["delete_count"],
            rng,
            jitter_strength,
        )
        setinfo_count = jitter_count(
            int(base["setinfo_count"]),
            real_df["setinfo_count"],
            rng,
            jitter_strength,
        )

        # 保留勒索行为的弱相关性：
        # 高写入窗口通常伴随一定重命名或删除。
        if write_count > 0 and rename_count == 0 and rng.random() < 0.35:
            rename_count = max(1, int(round(write_count * rng.uniform(0.03, 0.18))))

        if write_count > 10 and delete_count == 0 and rng.random() < 0.25:
            delete_count = max(1, int(round(write_count * rng.uniform(0.02, 0.12))))

        entropy = jitter_entropy(float(base["entropy"]), real_df["entropy"], rng)
        entropy_risk = 1 if entropy > 7.5 else 0
        if write_count == 0 and rename_count == 0 and entropy == 0.0:
            delete_count = min(delete_count, 20)

        synthetic_rows.append(
            {
                "write_count": write_count,
                "rename_count": rename_count,
                "delete_count": delete_count,
                "setinfo_count": setinfo_count,
                "entropy": entropy,
                "entropy_risk": entropy_risk,
                "label": 1,
            }
        )

    synthetic_df = pd.DataFrame(synthetic_rows, columns=FEATURE_COLUMNS)

    final_df = pd.concat([real_df, synthetic_df], ignore_index=True)

    # 打乱，避免前 627 条全是真实样本，后 373 条全是扩增样本
    final_df = final_df.sample(frac=1, random_state=seed).reset_index(drop=True)

    for col in COUNT_COLUMNS:
        final_df[col] = final_df[col].round().astype(int)

    final_df["entropy"] = final_df["entropy"].round(4)
    final_df["entropy_risk"] = (final_df["entropy"] > 7.5).astype(int)
    final_df["label"] = 1

    return final_df


def write_report(report_path: Path, real_df: pd.DataFrame, final_df: pd.DataFrame):
    synthetic_count = len(final_df) - len(real_df)

    lines = []
    lines.append("Ransomware Sample Augmentation Report")
    lines.append("=" * 45)
    lines.append(f"real_effective_samples = {len(real_df)}")
    lines.append(f"synthetic_augmented_samples = {synthetic_count}")
    lines.append(f"final_samples = {len(final_df)}")
    lines.append(f"duplicate_rows = {int(final_df.duplicated().sum())}")
    lines.append("")
    lines.append("[Real Samples Describe]")
    lines.append(real_df[FEATURE_COLUMNS].describe().round(4).to_string())
    lines.append("")
    lines.append("[Final Samples Describe]")
    lines.append(final_df[FEATURE_COLUMNS].describe().round(4).to_string())
    lines.append("")
    lines.append("说明：")
    lines.append("1. 扩增样本基于真实采集勒索样本的经验分布生成。")
    lines.append("2. 扩增方式为 bootstrap 抽样 + 小幅扰动。")
    lines.append("3. 论文中不应将扩增样本描述为完全真实采集样本。")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default=str(DEFAULT_INPUT))
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT))
    parser.add_argument("--report", type=str, default=str(DEFAULT_REPORT))
    parser.add_argument("--target", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--jitter-strength", type=float, default=0.20)
    parser.add_argument(
        "--replace-original",
        action="store_true",
        help="备份原始 ransomware_samples.csv 后，用最终扩增结果替换它",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    report_path = Path(args.report)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    real_df = load_and_clean(input_path)

    final_df = augment_samples(
        real_df=real_df,
        target=args.target,
        seed=args.seed,
        jitter_strength=args.jitter_strength,
    )

    final_df.to_csv(output_path, index=False, encoding="utf-8-sig")
    write_report(report_path, real_df, final_df)

    print("[+] 勒索样本扩增完成")
    print(f"[+] 有效真实样本数量：{len(real_df)}")
    print(f"[+] 扩增生成样本数量：{len(final_df) - len(real_df)}")
    print(f"[+] 最终样本数量：{len(final_df)}")
    print(f"[+] 输出文件：{output_path}")
    print(f"[+] 报告文件：{report_path}")

    print("\n[+] 最终数据概览：")
    print(final_df.describe().round(4))

    if args.replace_original:
        backup_path = input_path.with_name(input_path.stem + "_backup_before_augment.csv")
        shutil.copy2(input_path, backup_path)
        shutil.copy2(output_path, input_path)
        print(f"\n[+] 已备份原始文件：{backup_path}")
        print(f"[+] 已用扩增结果替换原始文件：{input_path}")


if __name__ == "__main__":
    main()
