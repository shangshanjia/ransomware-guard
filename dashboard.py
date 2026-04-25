# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd
import time
import os
import psutil
import json
from datetime import datetime

# --- 页面配置 ---
st.set_page_config(page_title="Ransomware Guard 态势感知中心", page_icon="🛡️", layout="wide")

st.title("🛡️ 基于行为语义的勒索病毒主动阻断系统")
st.markdown("状态: **运行中** 🟢 | 核心架构: **双轨决策引擎 + 策略热加载**")

# 文件路径定义
LOG_FILE = "logs/alerts.csv"
CONFIG_FILE = "config.json"

def load_real_logs():
    if os.path.exists(LOG_FILE):
        try:
            return pd.read_csv(LOG_FILE, names=["时间", "恶意进程", "PID", "触发机制", "高危目标", "状态"])
        except:
            return pd.DataFrame()
    return pd.DataFrame()

# --- 侧边栏：策略配置 (桥接逻辑) ---
st.sidebar.header("⚙️ 监控策略中心")
st.sidebar.subheader("资产布防路径配置")

# 读取当前生效的配置
current_paths = []
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            current_paths = json.load(f).get("watch_dirs", [])
    except: pass

# 侧边栏输入框
user_home = os.environ.get('USERPROFILE', 'C:\\Users')
initial_val = "\n".join(current_paths) if current_paths else f"{user_home}\n{os.path.abspath('./test_data')}"
watch_dirs_input = st.sidebar.text_area("监控路径 (每行一个):", value=initial_val, height=150)

if st.sidebar.button("🚀 下发策略至底层引擎"):
    # 解析并写入 JSON 文件
    new_dirs = [d.strip() for d in watch_dirs_input.split('\n') if d.strip()]
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"watch_dirs": new_dirs}, f, ensure_ascii=False, indent=4)
    st.sidebar.success(f"✅ 成功！{len(new_dirs)} 个路径已同步至后端。")
    st.toast("底层引擎已触发热重载线程...")

# --- 顶部实时数据指标 (真实数据) ---
df_alerts = load_real_logs()
intercept_count = len(df_alerts)

col1, col2, col3 = st.columns(3)
real_cpu = psutil.cpu_percent(interval=None)
real_mem = psutil.virtual_memory().percent

col1.metric("实时系统负载 (CPU)", f"{real_cpu}%")
col2.metric("内存占用率 (RAM)", f"{real_mem}%")
col3.metric("已拦截威胁总数", f"{intercept_count}", "🚨 安全阻断", delta_color="inverse")

st.divider()

# --- 资源性能曲线 (对齐论文) ---
st.subheader("📊 系统资源损耗监控 (Real-time Performance)")

if 'cpu_history' not in st.session_state:
    st.session_state.cpu_history = [psutil.cpu_percent()] * 30

st.session_state.cpu_history.pop(0)
st.session_state.cpu_history.append(real_cpu)

chart_df = pd.DataFrame(st.session_state.cpu_history, columns=["CPU 占用率 (%)"])
st.line_chart(chart_df, height=220)

# --- 拦截审计流水 ---
st.subheader("🚨 实时威胁拦截审计 (Audit Logs)")
if not df_alerts.empty:
    st.dataframe(df_alerts.iloc[::-1], use_container_width=True)
else:
    st.success("目前系统稳态运行，未检测到高危加密行为。")

st.caption(f"数据最后更新: {datetime.now().strftime('%H:%M:%S')} | 自动轮询中...")

# 自动刷新
time.sleep(3)
st.rerun()
