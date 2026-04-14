import ipaddress
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

RULE_PREFIXES = (
    "DOMAIN,",
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "IP-CIDR,",
    "IP-CIDR6,",
    "IP-ASN,",
    "PROCESS-NAME,",
)

EXCLUDED_SUFFIXES = {".py", ".yml", ".yaml", ".json", ".md"}


def bj_tz():
    return timezone(timedelta(hours=8))


def now_str():
    return datetime.now(bj_tz()).strftime("%Y-%m-%d %H:%M:%S (北京时间)")


def should_ignore_header(line: str) -> bool:
    prefixes = (
        "# 最后更新时间:",
        "# 从Surge自动同步",
        "# 从Surge自动标准化",
        "# 从Clash自动同步",
        "# 从Clash自动标准化",
        "# 原始文件:",
    )
    return line.startswith(prefixes)


def normalize(line: str):
    line = line.strip()

    if not line:
        return None

    if line.startswith("#"):
        return None

    if line in {"rules:", "payload:"}:
        return None

    if line.startswith("- "):
        line = line[2:].strip()

    if " #" in line:
        line = line.split(" #", 1)[0].strip()

    if not line:
        return None

    if line.startswith(RULE_PREFIXES):
        return line

    m = re.fullmatch(
        r"([^,/]+)(?:/(\d{1,2}))?(?:,(no-resolve))?",
        line,
        re.IGNORECASE,
    )
    if m:
        raw_ip = m.group(1)
        mask = m.group(2)
        extra = f",{m.group(3)}" if m.group(3) else ""
        try:
            ipaddress.IPv4Address(raw_ip)
            return f"IP-CIDR,{raw_ip}/{mask or '32'}{extra}"
        except ValueError:
            pass

    if "." in line:
        return f"DOMAIN-SUFFIX,{line}"

    return f"PROCESS-NAME,{line}"


def parse_rules_from_file(path: Path):
    rules = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        if raw.startswith("#"):
            if should_ignore_header(raw):
                continue
            continue
        n = normalize(raw)
        if n:
            rules.append(n)
    return rules


repo = Path("surge_repo")
if repo.exists():
    shutil.rmtree(repo)

subprocess.run(
    [
        "git",
        "clone",
        f"https://x-access-token:{os.environ['GITHUB_TOKEN']}@github.com/{os.environ['TARGET_REPO']}.git",
        "surge_repo",
    ],
    check=True,
)
subprocess.run(
    ["git", "-C", "surge_repo", "checkout", os.environ["TARGET_BRANCH"]],
    check=True,
)

changed_local = False
changed_remote = False

for p in Path(".").iterdir():
    if (
        not p.is_file()
        or p.name.startswith(".")
        or p.suffix in EXCLUDED_SUFFIXES
    ):
        continue

    rules = parse_rules_from_file(p)

    local_output = (
        f"# 最后更新时间: {now_str()}\n"
        "# 从Clash自动标准化\n"
        f"# 原始文件: {p.name}\n"
        "rules:\n"
        + "\n".join(f"  - {rule}" for rule in rules)
        + "\n"
    )

    old_local = p.read_text(encoding="utf-8")
    if old_local != local_output:
        p.write_text