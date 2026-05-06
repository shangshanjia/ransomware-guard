# simulate_ransomware_behavior.py
# 安全稳定版勒索式文件行为模拟器
# 只操作 sample_workspace/ransom_sim_area/work_area 内的测试副本文件
# 不操作 template_files，不操作系统目录，不联网，不驻留，不提权

import argparse
import os
import random
import shutil
import time
from pathlib import Path


BASE_DIR = Path(r"C:\Users\root\Desktop\Ransomware_Guard")

RANSOM_AREA = BASE_DIR / "sample_workspace" / "ransom_sim_area"
TEMPLATE_DIR = RANSOM_AREA / "template_files"
WORK_AREA = RANSOM_AREA / "work_area"
ENCRYPTED_DIR = RANSOM_AREA / "encrypted"

RANSOM_EXTS = [".locked", ".encrypted", ".wncry", ".conti"]


def ensure_safe_path(path: Path) -> Path:
    """
    安全保护：所有操作必须限制在 ransom_sim_area 内。
    """
    resolved = path.resolve()
    root = RANSOM_AREA.resolve()

    if root not in [resolved, *resolved.parents]:
        raise RuntimeError(f"拒绝操作非测试目录路径：{resolved}")

    return resolved


def ensure_dirs():
    RANSOM_AREA.mkdir(parents=True, exist_ok=True)
    TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
    WORK_AREA.mkdir(parents=True, exist_ok=True)
    ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)


def create_default_templates(count=120):
    """
    如果 template_files 为空，自动生成一批普通测试模板文件。
    这些文件只是普通 txt/csv/log/bin 测试文件。
    """
    existing = [p for p in TEMPLATE_DIR.rglob("*") if p.is_file()]
    if existing:
        return

    print("[!] template_files 为空，正在自动生成普通测试模板文件...")

    subdirs = ["docs", "csv", "logs", "misc"]
    for sub in subdirs:
        (TEMPLATE_DIR / sub).mkdir(parents=True, exist_ok=True)

    for i in range(count):
        file_type = random.choice(subdirs)

        if file_type == "docs":
            path = TEMPLATE_DIR / file_type / f"document_{i:04d}.txt"
            content = ("这是用于文件行为模拟的普通测试文档。\n" * random.randint(20, 100))
            path.write_text(content, encoding="utf-8")

        elif file_type == "csv":
            path = TEMPLATE_DIR / file_type / f"table_{i:04d}.csv"
            lines = ["id,value,status"]
            for j in range(random.randint(10, 40)):
                lines.append(f"{j},{random.randint(1, 1000)},normal")
            path.write_text("\n".join(lines), encoding="utf-8")

        elif file_type == "logs":
            path = TEMPLATE_DIR / file_type / f"app_{i:04d}.log"
            lines = []
            for j in range(random.randint(20, 80)):
                lines.append(f"2026-05-06 10:{j % 60:02d}:00 INFO operation={random.randint(1000,9999)}")
            path.write_text("\n".join(lines), encoding="utf-8")

        else:
            path = TEMPLATE_DIR / file_type / f"blob_{i:04d}.bin"
            path.write_bytes(os.urandom(random.randint(1024, 8192)))


def clear_dir(target_dir: Path):
    """
    清空指定目录。
    只允许清理 ransom_sim_area 下的 work_area 和 encrypted。
    """
    ensure_safe_path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    for item in target_dir.iterdir():
        ensure_safe_path(item)
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        except Exception as e:
            print(f"[!] 清理失败：{item} -> {e}")


def restore_initial_files():
    """
    从 template_files 恢复一份干净的工作副本到 work_area。
    模拟器只攻击 work_area 里的副本，不攻击 template_files。
    """
    ensure_dirs()
    create_default_templates()

    clear_dir(WORK_AREA)
    clear_dir(ENCRYPTED_DIR)

    copied = 0

    for src in TEMPLATE_DIR.rglob("*"):
        if not src.is_file():
            continue

        rel = src.relative_to(TEMPLATE_DIR)
        dst = WORK_AREA / rel

        dst.parent.mkdir(parents=True, exist_ok=True)

        try:
            shutil.copy2(src, dst)
            copied += 1
        except Exception as e:
            print(f"[!] 恢复模板失败：{src} -> {e}")

    print(f"[+] 已恢复测试文件副本：{copied} 个")
    return copied


def list_candidate_files():
    """
    只从 work_area 中选择候选文件。
    不选择 template_files，不选择 encrypted。
    """
    WORK_AREA.mkdir(parents=True, exist_ok=True)
    return [p for p in WORK_AREA.rglob("*") if p.is_file()]


def overwrite_file(path: Path):
    """
    使用随机字节覆盖测试副本文件，用于制造高熵写入特征。
    """
    try:
        ensure_safe_path(path)
        size = random.randint(8 * 1024, 128 * 1024)

        with open(path, "wb") as f:
            f.write(os.urandom(size))

        return True
    except Exception:
        return False


def rename_file(path: Path):
    """
    模拟勒索式扩展名变化。
    形式：report.docx -> report.docx.locked
    """
    try:
        ensure_safe_path(path)

        lower_name = path.name.lower()
        if any(lower_name.endswith(ext) for ext in RANSOM_EXTS):
            return None

        ext = random.choice(RANSOM_EXTS)
        new_path = path.with_name(path.name + ext)

        path.rename(new_path)
        return new_path
    except Exception:
        return None


def delete_file(path: Path):
    """
    删除测试副本文件。
    只允许删除 work_area 内文件。
    """
    try:
        ensure_safe_path(path)

        if WORK_AREA.resolve() not in [path.resolve(), *path.resolve().parents]:
            return False

        path.unlink()
        return True
    except Exception:
        return False


def move_to_encrypted(path: Path):
    """
    将测试副本移动到 encrypted 目录。
    """
    try:
        ensure_safe_path(path)
        ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)

        dst = ENCRYPTED_DIR / path.name
        if dst.exists():
            dst = ENCRYPTED_DIR / f"{path.stem}_{random.randint(1000, 9999)}{path.suffix}"

        shutil.move(str(path), str(dst))
        return dst
    except Exception:
        return None


def simulate_one_round(batch_min, batch_max):
    """
    执行一轮小批量行为。
    降低批量规模，避免几秒内耗尽全部文件。
    """
    files = list_candidate_files()

    stats = {
        "write": 0,
        "rename": 0,
        "delete": 0,
        "move": 0,
        "mode": "none"
    }

    if not files:
        return stats

    mode = random.choices(
        ["overwrite", "rename", "delete", "move", "mixed"],
        weights=[4, 3, 1, 1, 2],
        k=1
    )[0]

    stats["mode"] = mode

    batch_size = min(len(files), random.randint(batch_min, batch_max))
    selected = random.sample(files, batch_size)

    if mode == "overwrite":
        for f in selected:
            if overwrite_file(f):
                stats["write"] += 1

    elif mode == "rename":
        for f in selected:
            new_path = rename_file(f)
            if new_path is not None:
                stats["rename"] += 1

    elif mode == "delete":
        for f in selected:
            if delete_file(f):
                stats["delete"] += 1

    elif mode == "move":
        for f in selected:
            if move_to_encrypted(f) is not None:
                stats["move"] += 1

    else:
        for f in selected:
            current = f

            if overwrite_file(current):
                stats["write"] += 1

            new_path = rename_file(current)
            if new_path is not None:
                stats["rename"] += 1
                current = new_path

            r = random.random()

            if r < 0.15:
                if delete_file(current):
                    stats["delete"] += 1
            elif r < 0.30:
                if move_to_encrypted(current) is not None:
                    stats["move"] += 1

    return stats


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--actions", type=int, default=2500, help="模拟轮数")
    parser.add_argument("--sleep", type=float, default=0.15, help="每轮之间的基础休眠秒数")
    parser.add_argument("--batch-min", type=int, default=2, help="每轮最少处理文件数")
    parser.add_argument("--batch-max", type=int, default=8, help="每轮最多处理文件数")
    parser.add_argument("--restore-every", type=int, default=120, help="每多少轮自动恢复一次初始文件")
    parser.add_argument("--min-files", type=int, default=25, help="候选文件低于该数量时自动恢复")
    parser.add_argument("--no-initial-restore", action="store_true", help="启动时不恢复文件")

    args = parser.parse_args()

    ensure_dirs()

    if not args.no_initial_restore:
        restore_initial_files()

    print("[+] 开始稳定版勒索式文件行为模拟")
    print(f"[+] 工作目录：{WORK_AREA}")
    print(f"[+] 模板目录：{TEMPLATE_DIR}")
    print(f"[+] 参数：actions={args.actions}, sleep={args.sleep}, batch={args.batch_min}-{args.batch_max}")

    total = {
        "write": 0,
        "rename": 0,
        "delete": 0,
        "move": 0
    }

    for i in range(1, args.actions + 1):
        remain_files = len(list_candidate_files())

        if remain_files < args.min_files:
            print(f"[*] 候选文件不足 {args.min_files}，自动恢复初始文件")
            restore_initial_files()

        if args.restore_every > 0 and i > 1 and i % args.restore_every == 0:
            print(f"[*] 达到恢复周期 {args.restore_every}，自动恢复初始文件")
            restore_initial_files()

        stats = simulate_one_round(args.batch_min, args.batch_max)

        for key in total:
            total[key] += stats.get(key, 0)

        if i % 50 == 0:
            remain = len(list_candidate_files())
            print(
                f"[RANSOM_SIM] {i}/{args.actions} | "
                f"remain={remain} | "
                f"write={total['write']} "
                f"rename={total['rename']} "
                f"delete={total['delete']} "
                f"move={total['move']}"
            )

        time.sleep(random.uniform(args.sleep * 0.7, args.sleep * 1.4))

    print("[+] 模拟完成")
    print(f"[+] 总操作统计：{total}")


if __name__ == "__main__":
    main()
