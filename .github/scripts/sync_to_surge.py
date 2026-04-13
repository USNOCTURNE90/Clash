import os
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta

RULE_PREFIXES = (
    "DOMAIN,",
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "IP-CIDR,",
    "IP-CIDR6,",
    "IP-ASN,",
    "PROCESS-NAME,",
)


def bj_tz():
    return timezone(timedelta(hours=8))


def now_str():
    return datetime.now(bj_tz()).strftime("%Y-%m-%d %H:%M:%S (北京时间)")


def normalize(line):
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    if line in {"rules:", "payload:"}:
        return None

    if line.startswith("- "):
        line = line[2:].strip()

    if line.startswith(RULE_PREFIXES):
        return line

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
        return f"IP-CIDR,{line}/32"

    if "." in line:
        return f"DOMAIN-SUFFIX,{line}"

    return line


repo = Path("surge_repo")
if repo.exists():
    shutil.rmtree(repo)

subprocess.run([
    "git", "clone",
    f"https://x-access-token:{os.environ['GITHUB_TOKEN']}@github.com/{os.environ['TARGET_REPO']}.git",
    "surge_repo"
], check=True)

subprocess.run([
    "git", "-C", "surge_repo", "checkout", os.environ["TARGET_BRANCH"]
], check=True)


changed = False

for p in Path(".").iterdir():
    if (
        not p.is_file()
        or p.name.startswith(".")
        or p.suffix in {".py", ".yml", ".yaml", ".json", ".md"}
    ):
        continue

    lines = []

    for raw in p.read_text(encoding="utf-8").splitlines():
        n = normalize(raw)
        if n:
            lines.append(n)

    output = (
        f"# 最后更新时间: {now_str()}\n"
        "# 从Clash自动同步\n"
        f"# 原始文件: {p.name}\n"
        + "\n".join(lines)
        + "\n"
    )

    target = repo / p.name

    if not target.exists() or target.read_text(encoding="utf-8") != output:
        target.write_text(output, encoding="utf-8")
        changed = True


if changed:
    subprocess.run(["git", "-C", "surge_repo", "config", "user.name", "github-actions[bot]"], check=True)
    subprocess.run(["git", "-C", "surge_repo", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], check=True)
    subprocess.run(["git", "-C", "surge_repo", "add", "."], check=True)
    subprocess.run(["git", "-C", "surge_repo", "commit", "-m", f"[AUTO_SYNC] 从Clash自动同步规则集 - {now_str()}"], check=True)
    subprocess.run(["git", "-C", "surge_repo", "push"], check=True)