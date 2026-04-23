import os
import time

def simulate_normal_office_work(target_dir="./test_data"):
    print("[👨‍💻 正常用户模拟器] 正在模拟日常办公环境 (批量写入低熵值普通文本)...")
    os.makedirs(target_dir, exist_ok=True)
    
    # 模拟生成 30 个普通工作文档并批量重命名（为了突破 20 次的记录阈值）
    for i in range(1, 31):
        temp_file = os.path.join(target_dir, f"report_draft_{i}.docx")
        final_file = os.path.join(target_dir, f"日常工作报告_v{i}.txt")
        
        # 写入低熵值的普通中文字符
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("这是一份正常的日常办公文档，里面包含着普通的文本信息。" * 20)
            
        # 模拟软件在后台重命名文件
        os.rename(temp_file, final_file)
        
        # 正常软件的 I/O 速度会有微小的间隔
        time.sleep(0.02)

    print("[👨‍💻 正常用户模拟器] 批量办公操作完成！去看看 CSV 文件吧！")

if __name__ == "__main__":
    simulate_normal_office_work()