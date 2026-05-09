# -*- coding: utf-8 -*-

import warnings
import joblib
import psutil
from concurrent.futures import ThreadPoolExecutor

try:
    import pandas as pd
except ImportError:
    pd = None


class RansomwareEngine:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)

        self.entropy_threshold = 7.9
        self.malicious_prob_threshold = 0.85

        # 专用查杀线程池，避免阻塞主监听线程
        self.kill_executor = ThreadPoolExecutor(max_workers=3)

        # 如果模型训练时带有 DataFrame 列名，则 sklearn 会保存 feature_names_in_
        self.model_feature_names = getattr(self.model, "feature_names_in_", None)

    def prepare_features(self, features):
        """
        将特征输入转换为模型期望的格式。

        解决：
        UserWarning: X does not have valid feature names,
        but RandomForestClassifier was fitted with feature names

        如果模型有 feature_names_in_，并且 pandas 可用，则构造 DataFrame。
        否则保持原始 numpy array。
        """
        if self.model_feature_names is not None and pd is not None:
            try:
                return pd.DataFrame(features, columns=list(self.model_feature_names))
            except Exception:
                return features

        return features

    def predict_malicious_probability(self, features):
        """
        统一预测入口。
        """
        prepared_features = self.prepare_features(features)

        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="X does not have valid feature names.*"
            )
            return self.model.predict_proba(prepared_features)[0][1]

    def judge_and_protect(self, pid, features, current_op, current_entropy):
        """
        双轨判定：
        1. 随机森林模型
        2. Watchdog 规则兜底
        """
        prob = self.predict_malicious_probability(features)

        write_count = features[0][0]
        rename_count = features[0][1]

        is_watchdog_triggered = (
            current_entropy > self.entropy_threshold
            and (
                rename_count > 0
                or write_count >= 10
            )
        )

        if prob > self.malicious_prob_threshold or is_watchdog_triggered:
            reason = "Watchdog兜底" if is_watchdog_triggered else f"检测置信度 {prob:.2f}"

            self.kill_executor.submit(
                self._async_execute_block,
                pid,
                reason
            )

            return True

        return False

    def _async_execute_block(self, pid, reason):
        """
        后台异步执行挂起与查杀。
        """
        try:
            p = psutil.Process(pid)

            p.suspend()
            p.kill()

            print(f"[🔥 异步阻断成功] PID: {pid} 已被终止。触发机制: {reason}")

        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            print(f"[!] 权限不足，无法阻断 PID: {pid}")
        except Exception:
            pass
