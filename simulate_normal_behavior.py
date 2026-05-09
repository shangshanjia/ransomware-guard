# simulate_normal_behavior.py
# 功能：
# 1. 自动创建正常样本工作目录
# 2. 自动生成随机大小的文档、图片、日志、CSV、压缩包等正常文件
# 3. 自动执行复制、修改、重命名、移动、删除、压缩、解压等正常办公行为
# 4. 配合 collect_normal_samples.py 采集 label=0 的正常行为样本
#
# 推荐流程：
# 第一次：python simulate_normal_behavior.py --init_only --force_rebuild
# 然后：python collect_normal_samples.py --target 1000 --window 3
# 最后：python simulate_normal_behavior.py --actions 12000 --sleep 0.10

import os
import csv
import time
import zipfile
import random
import shutil
import argparse
import string
from pathlib import Path


BASE_DIR = r"C:\Users\root\Desktop\Ransomware_Guard"
NORMAL_AREA = os.path.join(BASE_DIR, "sample_workspace", "normal_area")

DOCS_DIR = os.path.join(NORMAL_AREA, "docs")
IMAGES_DIR = os.path.join(NORMAL_AREA, "images")
ARCHIVES_DIR = os.path.join(NORMAL_AREA, "archives")
TEMP_DIR = os.path.join(NORMAL_AREA, "temp")


def ensure_dirs():
    """
    创建正常样本采集所需目录。
    docs/images/archives/temp 都是文件夹。
    """
    for d in [NORMAL_AREA, DOCS_DIR, IMAGES_DIR, ARCHIVES_DIR, TEMP_DIR]:
        os.makedirs(d, exist_ok=True)


def random_text(length=1024):
    """
    生成正常文本内容。
    """
    chars = (
        string.ascii_letters
        + string.digits
        + " ，。；：正常办公数据测试内容网络安全毕业设计文件行为采集"
    )
    return "".join(random.choice(chars) for _ in range(length))


def create_text_files(count=60):
    """
    创建 txt/log/csv 正常文本类文件。
    文件大小随机，避免所有样本过于一致。
    """
    for i in range(count):
        ext = random.choice([".txt", ".log", ".csv"])
        path = os.path.join(DOCS_DIR, f"normal_text_{i:03d}{ext}")

        if ext == ".csv":
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["id", "name", "value", "remark"])

                # CSV 行数随机
                for j in range(random.randint(30, 300)):
                    writer.writerow([
                        j,
                        f"user_{j}",
                        random.randint(1, 10000),
                        random_text(random.randint(10, 60))
                    ])
        else:
            with open(path, "w", encoding="utf-8") as f:
                # 2KB ~ 30KB
                f.write(random_text(random.randint(2 * 1024, 30 * 1024)))


def create_office_like_files(count=50):
    """
    创建伪办公文档文件。
    注意：这些文件用于触发正常文件系统行为，不要求能被 Office 正常打开。
    """
    exts = [".docx", ".xlsx", ".pptx", ".pdf"]

    for i in range(count):
        ext = random.choice(exts)
        path = os.path.join(DOCS_DIR, f"office_doc_{i:03d}{ext}")

        with open(path, "wb") as f:
            # 5KB ~ 200KB
            content = random_text(
                random.randint(5 * 1024, 200 * 1024)
            ).encode("utf-8", errors="ignore")
            f.write(content)


def create_fake_images(count=50):
    """
    创建测试图片类文件。

    修改点：
    不再全部使用 os.urandom()。
    30% 使用高熵随机内容，模拟真实图片、压缩类文件。
    70% 使用重复块内容，避免正常样本全部接近 entropy=8。
    """
    for i in range(count):
        ext = random.choice([".jpg", ".png", ".bmp"])
        path = os.path.join(IMAGES_DIR, f"image_{i:03d}{ext}")

        with open(path, "wb") as f:
            if ext == ".png":
                f.write(b"\x89PNG\r\n\x1a\n")
            elif ext == ".jpg":
                f.write(b"\xff\xd8\xff\xe0")
            elif ext == ".bmp":
                f.write(b"BM")

            # 20KB ~ 800KB
            size = random.randint(20 * 1024, 800 * 1024)

            # 30% 高熵，70% 中低熵
            if random.random() < 0.3:
                f.write(os.urandom(size))
            else:
                pattern = random.choice([
                    b"\x00\x11\x22\x33",
                    b"\xff\xd8\xff\xe0",
                    b"normal_image_data_",
                    b"\x89PNG\r\n\x1a\n",
                    b"RGBRGBRGBRGB",
                ])
                repeated = pattern * (size // len(pattern) + 1)
                f.write(repeated[:size])


def create_zip_archives(count=10):
    """
    创建正常压缩包。

    修改点：
    arcname 使用相对路径，避免 zipfile 出现 Duplicate name 警告。
    """
    files = list(Path(DOCS_DIR).glob("*")) + list(Path(IMAGES_DIR).glob("*"))

    if not files:
        return

    for i in range(count):
        zip_path = os.path.join(ARCHIVES_DIR, f"archive_{i:03d}.zip")

        selected = random.sample(
            files,
            k=min(len(files), random.randint(5, 20))
        )

        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for file in selected:
                    try:
                        arcname = str(file.relative_to(NORMAL_AREA))
                        zf.write(file, arcname=arcname)
                    except Exception:
                        pass
        except Exception:
            pass


def clear_workspace():
    """
    强制重建时，清理旧的 normal_area。
    注意：这里只清理 sample_workspace/normal_area，不影响项目代码。
    """
    if os.path.exists(NORMAL_AREA):
        shutil.rmtree(NORMAL_AREA, ignore_errors=True)

    ensure_dirs()


def prepare_initial_files(force_rebuild=False):
    """
    首次运行时准备基础正常文件。
    如果目录已有足够文件，则默认跳过初始化。
    """
    if force_rebuild:
        print("[!] force_rebuild 已启用，正在清理并重建 normal_area")
        clear_workspace()
    else:
        ensure_dirs()

    existing_files = list(Path(NORMAL_AREA).rglob("*.*"))

    if len(existing_files) >= 120 and not force_rebuild:
        print(f"[+] 已存在 {len(existing_files)} 个测试文件，跳过初始化")
        return

    print("[+] 正在初始化正常测试文件...")

    create_text_files(60)
    create_office_like_files(50)
    create_fake_images(50)
    create_zip_archives(10)

    total_files = len(list(Path(NORMAL_AREA).rglob("*.*")))
    print(f"[+] 初始化完成，当前正常测试文件数量：{total_files}")


def list_all_files():
    """
    获取 normal_area 下所有文件。
    """
    return [p for p in Path(NORMAL_AREA).rglob("*") if p.is_file()]


def safe_copy_file():
    """
    正常行为：复制文件到 temp 目录。
    """
    files = list_all_files()
    if not files:
        return

    src = random.choice(files)
    dst = os.path.join(
        TEMP_DIR,
        f"copy_{int(time.time() * 1000)}_{src.name}"
    )

    try:
        shutil.copy2(src, dst)
    except Exception:
        pass


def safe_modify_text_file():
    """
    正常行为：追加修改 txt/log/csv 文件。
    """
    candidates = (
        list(Path(DOCS_DIR).glob("*.txt"))
        + list(Path(DOCS_DIR).glob("*.log"))
        + list(Path(DOCS_DIR).glob("*.csv"))
    )

    if not candidates:
        return

    path = random.choice(candidates)

    try:
        with open(path, "a", encoding="utf-8", errors="ignore") as f:
            f.write("\n" + random_text(random.randint(100, 1000)))
    except Exception:
        pass


def safe_rename_file():
    """
    正常行为：重命名 temp 中的文件。
    """
    files = list(Path(TEMP_DIR).glob("*.*"))

    if not files:
        safe_copy_file()
        files = list(Path(TEMP_DIR).glob("*.*"))

    if not files:
        return

    src = random.choice(files)
    new_name = f"renamed_{random.randint(1000, 9999)}_{src.name}"
    dst = src.with_name(new_name)

    try:
        os.rename(src, dst)
    except Exception:
        pass


def safe_delete_temp_file():
    """
    正常行为：删除 temp 中的临时文件。
    只删除 temp，不删除 docs/images/archives 中的基础文件。
    """
    files = list(Path(TEMP_DIR).glob("*.*"))

    if len(files) < 10:
        return

    target = random.choice(files)

    try:
        os.remove(target)
    except Exception:
        pass


def safe_create_zip():
    """
    正常行为：从若干文件创建压缩包。

    修改点：
    arcname 使用相对路径，避免压缩包内部文件重名。
    """
    files = list_all_files()

    if len(files) < 5:
        return

    zip_path = os.path.join(
        ARCHIVES_DIR,
        f"normal_pack_{int(time.time() * 1000)}.zip"
    )

    selected = random.sample(
        files,
        k=min(len(files), random.randint(3, 15))
    )

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            used_names = set()

            for file in selected:
                try:
                    arcname = str(file.relative_to(NORMAL_AREA))

                    # 防止极端情况下仍然重名
                    if arcname in used_names:
                        arcname = f"{random.randint(1000, 9999)}_{arcname}"

                    used_names.add(arcname)
                    zf.write(file, arcname=arcname)
                except Exception:
                    pass
    except Exception:
        pass


def safe_extract_zip():
    """
    正常行为：解压压缩包到 temp。
    """
    zips = list(Path(ARCHIVES_DIR).glob("*.zip"))

    if not zips:
        return

    zip_path = random.choice(zips)
    extract_dir = os.path.join(
        TEMP_DIR,
        f"extract_{random.randint(1000, 9999)}"
    )

    os.makedirs(extract_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
    except Exception:
        pass


def safe_move_file():
    """
    正常行为：移动 temp 文件到 docs。
    """
    files = list(Path(TEMP_DIR).glob("*.*"))

    if not files:
        safe_copy_file()
        files = list(Path(TEMP_DIR).glob("*.*"))

    if not files:
        return

    src = random.choice(files)
    dst = os.path.join(
        DOCS_DIR,
        f"moved_{random.randint(1000, 9999)}_{src.name}"
    )

    try:
        shutil.move(str(src), dst)
    except Exception:
        pass


def safe_create_new_text_file():
    """
    正常行为：新建一个普通文本文件。
    """
    path = os.path.join(
        DOCS_DIR,
        f"new_note_{int(time.time() * 1000)}.txt"
    )

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(random_text(random.randint(1 * 1024, 10 * 1024)))
    except Exception:
        pass


def safe_cleanup_temp_folder():
    """
    正常行为：偶尔清理 temp 中过多的临时文件，避免目录无限膨胀。
    """
    files = list(Path(TEMP_DIR).rglob("*"))
    file_items = [p for p in files if p.is_file()]

    if len(file_items) < 100:
        return

    selected = random.sample(
        file_items,
        k=min(len(file_items), random.randint(10, 30))
    )

    for p in selected:
        try:
            os.remove(p)
        except Exception:
            pass


def simulate_one_action():
    """
    随机选择一个正常办公行为。

    修改点：
    降低压缩和解压权重，增加复制、文本修改、新建文本的比例。
    这样正常样本不会过度集中在高熵 zip 或图片操作上。
    """
    weighted_actions = [
        safe_copy_file,
        safe_copy_file,
        safe_copy_file,
        safe_copy_file,

        safe_modify_text_file,
        safe_modify_text_file,
        safe_modify_text_file,

        safe_create_new_text_file,
        safe_create_new_text_file,

        safe_rename_file,
        safe_delete_temp_file,

        safe_move_file,

        # 压缩和解压保留，但权重较低
        safe_create_zip,
        safe_extract_zip,

        safe_cleanup_temp_folder,
    ]

    action = random.choice(weighted_actions)
    action()


def main():
    parser = argparse.ArgumentParser(description="正常行为自动模拟脚本")

    parser.add_argument(
        "--actions",
        type=int,
        default=3500,
        help="执行正常操作次数，默认3500"
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=0.15,
        help="每次操作间隔秒数，默认0.15秒"
    )

    parser.add_argument(
        "--force_rebuild",
        action="store_true",
        help="强制清理并重新初始化 normal_area"
    )

    parser.add_argument(
        "--init_only",
        action="store_true",
        help="只初始化正常测试文件，不执行后续正常行为"
    )

    args = parser.parse_args()

    prepare_initial_files(force_rebuild=args.force_rebuild)

    if args.init_only:
        print("[+] 仅初始化文件，不执行正常行为模拟")
        print(f"[+] 初始化目录：{NORMAL_AREA}")
        return

    print("[+] 开始模拟正常办公文件行为")
    print(f"[+] 操作目录：{NORMAL_AREA}")
    print(f"[+] 操作次数：{args.actions}")
    print(f"[+] 操作间隔：{args.sleep} 秒")
    print("[+] 请确保 collect_normal_samples.py 正在另一个窗口运行")

    start = time.time()

    for i in range(args.actions):
        simulate_one_action()

        if (i + 1) % 100 == 0:
            elapsed = time.time() - start
            print(
                f"[NORMAL-BEHAVIOR] 已执行 {i + 1}/{args.actions} 次操作，"
                f"耗时 {elapsed:.1f} 秒"
            )

        time.sleep(args.sleep)

    total_time = time.time() - start
    print(f"[+] 正常行为模拟完成，总耗时 {total_time:.1f} 秒")


if __name__ == "__main__":
    main()
