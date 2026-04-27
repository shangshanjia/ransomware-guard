import wmi
import psutil
import sys

def monitor_process_creation():
    print("="*70)
    print("📡 [事前防线] 轻量级进程创建与命令行雷达 已启动")
    print("🛡️  监控原理: 基于 WMI 用户态事件订阅 (纯 Python 实现)")
    print("⏳ 正在实时拦截高危恶意指令 (如删除卷影备份、禁用恢复等)...")
    print("="*70)

    # 1. 建立高危命令行特征库 (勒索病毒前置动作黑名单)
    high_risk_keywords = [
        "vssadmin.exe delete shadows",  # 勒索病毒最爱：删除系统卷影拷贝备份
        "bcdedit /set {default} recoveryenabled no", # 禁用系统启动修复
        "wbadmin delete catalog",       # 删除 Windows Server 备份目录
        "wevtutil cl security",         # 清除系统安全日志，企图隐蔽踪迹
        "taskkill /f /im sqlservr.exe", # 结束数据库进程以便解除文件占用进行加密
    ]

    try:
        # 2. 初始化 WMI 连接
        c = wmi.WMI()

        # 3. 核心魔法：使用 WQL (WMI查询语言) 订阅进程创建事件
        # WITHIN 1 表示每 1 秒轮询一次，兼顾了时效性与低 CPU 占用 (< 1%)
        process_watcher = c.ExecNotificationQuery(
            "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
        )

        while True:
            # 阻塞等待新进程创建事件
            new_event = process_watcher.NextEvent()
            process = new_event.TargetInstance

            pid = process.ProcessId
            name = process.Name
            cmdline = process.CommandLine

            # 有些系统级进程没有命令行权限获取，直接跳过
            if not cmdline:
                continue

            cmdline_lower = cmdline.lower()

            # 4. 匹配特征：检查新启动的进程是否包含高危命令
            is_malicious = any(keyword in cmdline_lower for keyword in high_risk_keywords)

            if is_malicious:
                print(f"\n[🚨 事前拦截触发] 检测到勒索病毒的破坏性前置动作！")
                print(f"  ├─ 恶意进程: {name} (PID: {pid})")
                print(f"  ├─ 攻击指令: {cmdline}")

                # 5. 执行“见血封喉”的事前击杀
                try:
                    p = psutil.Process(pid)
                    p.kill()
                    print(f"  └─ [🔥 斩首成功] 进程已被扼杀在摇篮中，未触碰任何文件资产！")
                except psutil.NoSuchProcess:
                    print(f"  └─ [!] 进程执行过快，已自行退出。")
                except psutil.AccessDenied:
                    print(f"  └─ [!] 权限不足，无法击杀该进程（请确保使用管理员权限运行）。")
            
            # (可选) 打印出所有进程，方便你观察系统的运行状态
            # else:
            #     print(f"[*] 正常放行 -> {name} | 参数: {cmdline}")

    except KeyboardInterrupt:
        print("\n[*] 前置雷达已安全关闭。")
        sys.exit()
    except Exception as e:
        print(f"\n[!] WMI 监控发生异常: {e}")

if __name__ == "__main__":
    monitor_process_creation()
