# train_ransomware_model_strict_eval.py
# 严格评估版随机森林训练脚本
#
# 数据路径：
# data/human_normal_samples.csv          真实人工正常样本
# data/normal_samples_final.csv          最终正常样本，供随机划分基线和部署模型使用
# data/ransomware_samples.csv            真实采集/模拟执行得到的勒索样本，未扩增
# data/ransomware_samples_final.csv      扩增后的最终勒索样本，供随机划分基线和部署模型使用
#
# 输出：
# logs/strict_eval/strict_eval_report.txt
# logs/strict_eval/strict_eval_report.json
# logs/strict_eval/*.png
# models/rf_ransomware_model_strict_eval.joblib
# 可选：models/rf_ransomware_model.joblib

import argparse
import json
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


BASE_DIR = Path(r"C:\Users\root\Desktop\Ransomware_Guard")

DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
REPORT_DIR = BASE_DIR / "logs" / "strict_eval"

NORMAL_REAL_PATH = DATA_DIR / "human_normal_samples.csv"
NORMAL_FINAL_PATH = DATA_DIR / "normal_samples_final.csv"

RANSOM_REAL_PATH = DATA_DIR / "ransomware_samples.csv"
RANSOM_FINAL_PATH = DATA_DIR / "ransomware_samples_final.csv"

STRICT_MODEL_PATH = MODEL_DIR / "rf_ransomware_model_strict_eval.joblib"
SYSTEM_MODEL_PATH = MODEL_DIR / "rf_ransomware_model.joblib"

FEATURES_FULL = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
    "entropy",
    "entropy_risk",
]

FEATURES_NO_ENTROPY_RISK = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
    "entropy",
]

FEATURES_OPERATION_ONLY = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
]

LABEL_COL = "label"
ALL_COLUMNS = FEATURES_FULL + [LABEL_COL]

COUNT_COLUMNS = [
    "write_count",
    "rename_count",
    "delete_count",
    "setinfo_count",
]


def ensure_dirs():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)


def read_csv_required(path: Path, name: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"{name} 不存在：{path}")
    return pd.read_csv(path, encoding="utf-8-sig")


def clean_dataset(df: pd.DataFrame, expected_label: int, name: str) -> pd.DataFrame:
    missing = [c for c in ALL_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{name} 缺少必要列：{missing}")

    df = df[ALL_COLUMNS].copy()

    for col in ALL_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    before = len(df)
    df = df.dropna().copy()
    df = df[df[LABEL_COL] == expected_label].copy()

    for col in COUNT_COLUMNS:
        df = df[df[col] >= 0].copy()
        df[col] = df[col].round().astype(int)

    df = df[(df["entropy"] >= 0.0) & (df["entropy"] <= 8.0)].copy()
    df["entropy"] = df["entropy"].round(4)
    df["entropy_risk"] = (df["entropy"] > 7.5).astype(int)
    df[LABEL_COL] = int(expected_label)

    # 删除完全空窗口：没有任何有效行为，不应作为正常或勒索训练样本。
    empty_window = (
        (df["write_count"] == 0)
        & (df["rename_count"] == 0)
        & (df["delete_count"] == 0)
        & (df["setinfo_count"] == 0)
        & (df["entropy"] == 0.0)
        & (df["entropy_risk"] == 0)
    )
    df = df[~empty_window].copy()

    # 对勒索数据额外删除极端纯删除窗口。
    # 这种窗口通常来自恢复/清理过程，而不是加密行为本身。
    if expected_label == 1:
        extreme_delete_only = (
            (df["write_count"] == 0)
            & (df["rename_count"] == 0)
            & (df["setinfo_count"] == 0)
            & (df["entropy"] == 0.0)
            & (df["entropy_risk"] == 0)
            & (df["delete_count"] > 20)
        )
        df = df[~extreme_delete_only].copy()

    df = df.drop_duplicates().reset_index(drop=True)

    if len(df) == 0:
        raise ValueError(f"{name} 清洗后没有有效样本。原始行数={before}")

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
    if base_value <= 0:
        nonzero = series[series > 0]

        if len(nonzero) == 0:
            return 0

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
    label: int,
) -> float:
    if label == 1:
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

        # 不允许扩增出真实样本中没有的 8.0 极端熵值
        high = min(float(entropy_series.max()), 7.9999)

        value = min(max(value, low), high)
        return round(float(value), 4)

    # 正常样本按正常分布扰动，不强行推向高熵。
    if base_entropy < 0:
        base_entropy = float(entropy_series.median())

    value = rng.normal(loc=base_entropy, scale=0.08)
    low = max(0.0, float(entropy_series.quantile(0.03)))
    high = min(8.0, float(entropy_series.quantile(0.97)))

    value = min(max(value, low), high)
    return round(float(value), 4)


def augment_from_training_split(
    train_real_df: pd.DataFrame,
    target: int,
    label: int,
    seed: int,
    jitter_strength: float,
) -> pd.DataFrame:
    """
    严格评估用扩增函数。

    关键点：
    只从训练划分内部扩增，不从测试划分扩增。
    这样可以避免“扩增样本和测试样本高度相似”的泄漏问题。
    """
    if len(train_real_df) >= target:
        return train_real_df.sample(n=target, random_state=seed).reset_index(drop=True)

    rng = np.random.default_rng(seed)
    need = target - len(train_real_df)

    synthetic_rows = []

    for _ in range(need):
        base = train_real_df.sample(
            n=1,
            replace=True,
            random_state=int(rng.integers(0, 2**31 - 1)),
        ).iloc[0]

        write_count = jitter_count(
            int(base["write_count"]),
            train_real_df["write_count"],
            rng,
            jitter_strength,
        )
        rename_count = jitter_count(
            int(base["rename_count"]),
            train_real_df["rename_count"],
            rng,
            jitter_strength,
        )
        delete_count = jitter_count(
            int(base["delete_count"]),
            train_real_df["delete_count"],
            rng,
            jitter_strength,
        )
        setinfo_count = jitter_count(
            int(base["setinfo_count"]),
            train_real_df["setinfo_count"],
            rng,
            jitter_strength,
        )
        entropy = jitter_entropy(
            float(base["entropy"]),
            train_real_df["entropy"],
            rng,
            label,
        )

        if label == 1:
            # 保留勒索行为的弱相关性：
            # 高写入窗口通常伴随一定重命名或删除。
            if write_count > 0 and rename_count == 0 and rng.random() < 0.35:
                rename_count = max(
                    1,
                    int(round(write_count * rng.uniform(0.03, 0.18))),
                )

            if write_count > 10 and delete_count == 0 and rng.random() < 0.25:
                delete_count = max(
                    1,
                    int(round(write_count * rng.uniform(0.02, 0.12))),
                )

            # 避免生成极端纯删除窗口。
            if (
                write_count == 0
                and rename_count == 0
                and setinfo_count == 0
                and entropy == 0.0
            ):
                delete_count = min(delete_count, 20)

        entropy_risk = 1 if entropy > 7.5 else 0

        synthetic_rows.append(
            {
                "write_count": write_count,
                "rename_count": rename_count,
                "delete_count": delete_count,
                "setinfo_count": setinfo_count,
                "entropy": entropy,
                "entropy_risk": entropy_risk,
                "label": label,
            }
        )

    synthetic_df = pd.DataFrame(synthetic_rows, columns=ALL_COLUMNS)

    final_df = pd.concat([train_real_df, synthetic_df], ignore_index=True)
    final_df = final_df.sample(frac=1, random_state=seed).reset_index(drop=True)

    for col in COUNT_COLUMNS:
        final_df[col] = final_df[col].round().astype(int)

    final_df["entropy"] = final_df["entropy"].round(4)
    final_df["entropy_risk"] = (final_df["entropy"] > 7.5).astype(int)
    final_df["label"] = int(label)

    return final_df


def build_random_split_dataset(normal_final: pd.DataFrame, ransom_final: pd.DataFrame) -> pd.DataFrame:
    """
    基线评估：
    直接使用 normal_samples_final 和 ransomware_samples_final 随机切分。

    注意：
    这个结果可能偏乐观，只作为 baseline，不作为论文主要严谨结果。
    """
    df = pd.concat([normal_final, ransom_final], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def build_strict_holdout_dataset(
    normal_real: pd.DataFrame,
    ransom_real: pd.DataFrame,
    test_size: float,
    train_per_class: int,
    seed: int,
    jitter_strength: float,
):
    """
    严格评估：
    1. human_normal_samples.csv 先划分 train/test
    2. ransomware_samples.csv 先划分 train/test
    3. 只对 train 部分扩增
    4. test 部分保持真实采集样本，不使用扩增样本
    """
    normal_train_real, normal_test_real = train_test_split(
        normal_real,
        test_size=test_size,
        random_state=seed,
        shuffle=True,
    )

    ransom_train_real, ransom_test_real = train_test_split(
        ransom_real,
        test_size=test_size,
        random_state=seed,
        shuffle=True,
    )

    normal_train_aug = augment_from_training_split(
        train_real_df=normal_train_real,
        target=train_per_class,
        label=0,
        seed=seed + 101,
        jitter_strength=jitter_strength,
    )

    ransom_train_aug = augment_from_training_split(
        train_real_df=ransom_train_real,
        target=train_per_class,
        label=1,
        seed=seed + 202,
        jitter_strength=jitter_strength,
    )

    train_df = pd.concat([normal_train_aug, ransom_train_aug], ignore_index=True)
    train_df = train_df.sample(frac=1, random_state=seed).reset_index(drop=True)

    test_df = pd.concat([normal_test_real, ransom_test_real], ignore_index=True)
    test_df = test_df.sample(frac=1, random_state=seed).reset_index(drop=True)

    return train_df, test_df, normal_test_real, ransom_test_real


def train_rf(X_train: pd.DataFrame, y_train: pd.Series, seed: int):
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def plot_confusion_matrix(cm: np.ndarray, title: str, out_path: Path, show: bool):
    fig, ax = plt.subplots(figsize=(6, 5))

    image = ax.imshow(cm)

    ax.set_title(title)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Ransom"])
    ax.set_yticklabels(["Normal", "Ransom"])

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center",
            )

    fig.colorbar(image, ax=ax)
    fig.tight_layout()
    fig.savefig(out_path, dpi=160)

    if show:
        plt.show()

    plt.close(fig)


def plot_feature_importance(model, feature_names, title: str, out_path: Path, show: bool):
    if not hasattr(model, "feature_importances_"):
        return

    importance = pd.Series(
        model.feature_importances_,
        index=feature_names,
    ).sort_values(ascending=True)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh(importance.index, importance.values)
    ax.set_title(title)
    ax.set_xlabel("Importance")

    fig.tight_layout()
    fig.savefig(out_path, dpi=160)

    if show:
        plt.show()

    plt.close(fig)


def evaluate_model(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    feature_names,
    title: str,
    seed: int,
    show: bool,
):
    X_train = train_df[feature_names]
    y_train = train_df[LABEL_COL]

    X_test = test_df[feature_names]
    y_test = test_df[LABEL_COL]

    model = train_rf(X_train, y_train, seed)

    y_pred = model.predict(X_test)

    try:
        y_score = model.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, y_score)
    except Exception:
        auc = None

    accuracy = accuracy_score(y_test, y_pred)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test,
        y_pred,
        average="binary",
        zero_division=0,
    )

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    cls_report = classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Ransom"],
        zero_division=0,
    )

    safe_title = (
        title.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace(":", "")
    )

    cm_path = REPORT_DIR / f"confusion_matrix_{safe_title}.png"
    fi_path = REPORT_DIR / f"feature_importance_{safe_title}.png"

    plot_confusion_matrix(
        cm=cm,
        title=f"Confusion Matrix - {title}",
        out_path=cm_path,
        show=show,
    )

    plot_feature_importance(
        model=model,
        feature_names=feature_names,
        title=f"Feature Importance - {title}",
        out_path=fi_path,
        show=show,
    )

    result = {
        "title": title,
        "features": list(feature_names),
        "accuracy": float(accuracy),
        "precision_ransom": float(precision),
        "recall_ransom": float(recall),
        "f1_ransom": float(f1),
        "roc_auc": None if auc is None else float(auc),
        "confusion_matrix": cm.tolist(),
        "classification_report": cls_report,
        "confusion_matrix_png": str(cm_path),
        "feature_importance_png": str(fi_path),
    }

    return model, result


def dataset_summary(name: str, df: pd.DataFrame) -> dict:
    return {
        "name": name,
        "rows": int(len(df)),
        "label_counts": {
            str(k): int(v)
            for k, v in df[LABEL_COL].value_counts().to_dict().items()
        },
        "duplicates": int(df.duplicated().sum()),
        "entropy_risk_rate": float(df["entropy_risk"].mean()) if len(df) else 0.0,
        "describe": df[ALL_COLUMNS].describe().round(4).to_dict(),
    }


def write_text_report(report_path: Path, summaries: list, results: list, notes: list):
    lines = []

    lines.append("Strict Ransomware Model Evaluation Report")
    lines.append("=" * 70)
    lines.append("")

    lines.append("[Notes]")
    for note in notes:
        lines.append(f"- {note}")
    lines.append("")

    lines.append("[Dataset Summary]")
    for summary in summaries:
        lines.append("")
        lines.append(f"## {summary['name']}")
        lines.append(f"rows = {summary['rows']}")
        lines.append(f"label_counts = {summary['label_counts']}")
        lines.append(f"duplicates = {summary['duplicates']}")
        lines.append(f"entropy_risk_rate = {summary['entropy_risk_rate']:.4f}")

    lines.append("")
    lines.append("[Evaluation Results]")

    for result in results:
        lines.append("")
        lines.append(f"## {result['title']}")
        lines.append(f"features = {result['features']}")
        lines.append(f"accuracy = {result['accuracy']:.6f}")
        lines.append(f"precision_ransom = {result['precision_ransom']:.6f}")
        lines.append(f"recall_ransom = {result['recall_ransom']:.6f}")
        lines.append(f"f1_ransom = {result['f1_ransom']:.6f}")
        lines.append(f"roc_auc = {result['roc_auc']}")
        lines.append(f"confusion_matrix = {result['confusion_matrix']}")
        lines.append("classification_report:")
        lines.append(result["classification_report"])
        lines.append(f"confusion_matrix_png = {result['confusion_matrix_png']}")
        lines.append(f"feature_importance_png = {result['feature_importance_png']}")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def save_json(path: Path, obj):
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def print_result(result: dict):
    print("")
    print(f"[{result['title']}]")
    print(f"Accuracy           : {result['accuracy']:.6f}")
    print(f"Precision(Ransom)  : {result['precision_ransom']:.6f}")
    print(f"Recall(Ransom)     : {result['recall_ransom']:.6f}")
    print(f"F1(Ransom)         : {result['f1_ransom']:.6f}")
    print(f"ROC-AUC            : {result['roc_auc']}")
    print(f"Confusion Matrix   : {result['confusion_matrix']}")
    print("")
    print(result["classification_report"])


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--test-size",
        type=float,
        default=0.30,
        help="真实样本严格测试集比例，默认 0.30",
    )

    parser.add_argument(
        "--train-per-class",
        type=int,
        default=1000,
        help="严格评估中每一类训练样本扩增后的数量，默认 1000",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="随机种子",
    )

    parser.add_argument(
        "--jitter-strength",
        type=float,
        default=0.20,
        help="训练集扩增扰动强度，建议 0.15~0.25",
    )

    parser.add_argument(
        "--show",
        action="store_true",
        help="显示 matplotlib 图窗；不加则只保存图片",
    )

    parser.add_argument(
        "--save-system-model",
        action="store_true",
        help="额外使用 normal_samples_final + ransomware_samples_final 训练并保存系统部署模型 rf_ransomware_model.joblib",
    )

    args = parser.parse_args()

    ensure_dirs()

    print("[+] 读取并清洗数据...")

    normal_real = clean_dataset(
        read_csv_required(NORMAL_REAL_PATH, "human_normal_samples.csv"),
        expected_label=0,
        name="human_normal_samples.csv",
    )

    normal_final = clean_dataset(
        read_csv_required(NORMAL_FINAL_PATH, "normal_samples_final.csv"),
        expected_label=0,
        name="normal_samples_final.csv",
    )

    ransom_real = clean_dataset(
        read_csv_required(RANSOM_REAL_PATH, "ransomware_samples.csv"),
        expected_label=1,
        name="ransomware_samples.csv",
    )

    ransom_final = clean_dataset(
        read_csv_required(RANSOM_FINAL_PATH, "ransomware_samples_final.csv"),
        expected_label=1,
        name="ransomware_samples_final.csv",
    )

    print(f"[+] human_normal_samples 有效样本数      : {len(normal_real)}")
    print(f"[+] normal_samples_final 有效样本数     : {len(normal_final)}")
    print(f"[+] ransomware_samples 有效样本数       : {len(ransom_real)}")
    print(f"[+] ransomware_samples_final 有效样本数 : {len(ransom_final)}")

    if len(normal_real) < 50:
        print("[!] 警告：真实人工正常样本偏少，严格测试结果的 normal support 可能较小。")

    if len(ransom_real) < 100:
        print("[!] 警告：真实勒索样本偏少，严格评估可信度会下降。")

    # ============================================================
    # 1. 随机切分基线：final normal + final ransomware
    # ============================================================
    random_df = build_random_split_dataset(normal_final, ransom_final)

    random_train, random_test = train_test_split(
        random_df,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=random_df[LABEL_COL],
        shuffle=True,
    )

    # ============================================================
    # 2. 严格真实样本 holdout：
    #    先切分真实样本，再只对训练部分扩增
    # ============================================================
    strict_train, strict_test, normal_test_real, ransom_test_real = build_strict_holdout_dataset(
        normal_real=normal_real,
        ransom_real=ransom_real,
        test_size=args.test_size,
        train_per_class=args.train_per_class,
        seed=args.seed,
        jitter_strength=args.jitter_strength,
    )

    print(f"[+] random_train 样本数 : {len(random_train)}")
    print(f"[+] random_test 样本数  : {len(random_test)}")
    print(f"[+] strict_train 样本数 : {len(strict_train)}")
    print(f"[+] strict_test 样本数  : {len(strict_test)}")
    print(f"[+] strict_test normal  : {len(normal_test_real)}")
    print(f"[+] strict_test ransom  : {len(ransom_test_real)}")

    results = []

    # ============================================================
    # 3. 评估 A：随机切分基线
    # ============================================================
    _, random_baseline_result = evaluate_model(
        train_df=random_train,
        test_df=random_test,
        feature_names=FEATURES_FULL,
        title="Random Split Baseline Full Features",
        seed=args.seed,
        show=args.show,
    )
    results.append(random_baseline_result)

    # ============================================================
    # 4. 评估 B：严格 holdout，全特征
    # ============================================================
    strict_model, strict_full_result = evaluate_model(
        train_df=strict_train,
        test_df=strict_test,
        feature_names=FEATURES_FULL,
        title="Strict Holdout Full Features",
        seed=args.seed,
        show=args.show,
    )
    results.append(strict_full_result)

    # ============================================================
    # 5. 评估 C：严格 holdout，去掉 entropy_risk
    # ============================================================
    _, strict_no_entropy_risk_result = evaluate_model(
        train_df=strict_train,
        test_df=strict_test,
        feature_names=FEATURES_NO_ENTROPY_RISK,
        title="Strict Holdout Without Entropy Risk",
        seed=args.seed,
        show=args.show,
    )
    results.append(strict_no_entropy_risk_result)

    # ============================================================
    # 6. 评估 D：严格 holdout，只用操作类特征
    # ============================================================
    _, strict_operation_only_result = evaluate_model(
        train_df=strict_train,
        test_df=strict_test,
        feature_names=FEATURES_OPERATION_ONLY,
        title="Strict Holdout Operation Only",
        seed=args.seed,
        show=args.show,
    )
    results.append(strict_operation_only_result)

    # 保存严格评估模型。
    # 注意：这个模型没有直接使用 strict_test。
    joblib.dump(strict_model, STRICT_MODEL_PATH)

    notes = [
        "Random Split Baseline 使用 normal_samples_final.csv 与 ransomware_samples_final.csv 随机划分，可能偏乐观，只作为基础对照。",
        "Strict Holdout 使用 human_normal_samples.csv 与 ransomware_samples.csv 先划分真实训练/真实测试，再只对训练部分扩增。",
        "Strict Holdout 的测试集不包含扩增样本，因此比随机切分更适合作为论文主要评估依据。",
        "Without Entropy Risk 是消融实验，用于验证模型是否过度依赖 entropy_risk 阈值特征。",
        "Operation Only 是进一步消融实验，用于观察只依赖文件操作频度时模型仍能达到的效果。",
        "如果 Strict Holdout 仍然达到 1.0，不应人为修改结果；应在论文中解释受控实验环境、特征强区分度和样本来源限制。",
    ]

    summaries = [
        dataset_summary("human_normal_samples_clean", normal_real),
        dataset_summary("normal_samples_final_clean", normal_final),
        dataset_summary("ransomware_samples_clean", ransom_real),
        dataset_summary("ransomware_samples_final_clean", ransom_final),
        dataset_summary("random_train", random_train),
        dataset_summary("random_test", random_test),
        dataset_summary("strict_train_augmented_from_train_only", strict_train),
        dataset_summary("strict_test_real_only", strict_test),
        dataset_summary("strict_normal_test_real", normal_test_real),
        dataset_summary("strict_ransom_test_real", ransom_test_real),
    ]

    report_txt_path = REPORT_DIR / "strict_eval_report.txt"
    report_json_path = REPORT_DIR / "strict_eval_report.json"

    write_text_report(report_txt_path, summaries, results, notes)
    save_json(
        report_json_path,
        {
            "summaries": summaries,
            "results": results,
            "notes": notes,
        },
    )

    print("")
    print("=" * 70)
    print("Strict Evaluation Summary")
    print("=" * 70)

    for result in results:
        print_result(result)

    print("")
    print("[+] 严格评估模型已保存：")
    print(f"    {STRICT_MODEL_PATH}")

    print("[+] 文本报告已保存：")
    print(f"    {report_txt_path}")

    print("[+] JSON 报告已保存：")
    print(f"    {report_json_path}")

    print("[+] 图片已保存目录：")
    print(f"    {REPORT_DIR}")

    # ============================================================
    # 7. 可选：保存系统部署模型
    # ============================================================
    if args.save_system_model:
        system_train_df = pd.concat([normal_final, ransom_final], ignore_index=True)
        system_train_df = system_train_df.sample(frac=1, random_state=args.seed).reset_index(drop=True)

        system_model = train_rf(
            X_train=system_train_df[FEATURES_FULL],
            y_train=system_train_df[LABEL_COL],
            seed=args.seed,
        )

        joblib.dump(system_model, SYSTEM_MODEL_PATH)

        print("[+] 系统部署模型已保存：")
        print(f"    {SYSTEM_MODEL_PATH}")


if __name__ == "__main__":
    main()
