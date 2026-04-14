import ipaddress
import json
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
STATE_DIR = Path(".github/sync_state")
PENDING_FILE = STATE_DIR / "pending_deletions.json"


def bj_tz():
    return timezone(timedelta(hours=8))


def now_dt():
    return datetime.now(bj_tz())


def now_str():
    return now_dt().strftime("%Y-%m-%d %H:%M:%S (北京时间)")


def now_iso():
    return now_dt().isoformat()


def run(cmd, cwd=None):
    subprocess.run(cmd, check=True, cwd=cwd)


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


def ensure_state():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not PENDING_FILE.exists():
        PENDING_FILE.write_text("[]\n", encoding="utf-8")


def load_pending():
    ensure_state()
    try:
        return json.loads(PENDING_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_pending(items):
    ensure_state()
    PENDING_FILE.write_text(
        json.dumps(items, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def record_deletions(current_names, repo_name):
    pending = load_pending()
    existing_names = set()

    for p in Path(".").iterdir():
        if (
            p.is_file()
            and not p.name.startswith(".")
            and p.suffix not in EXCLUDED_SUFFIXES
        ):
            existing_names.add(p.name)

    for item in pending:
        if item.get("repo") == repo_name:
            current_names.add(item.get("filename"))

    # 读取目标仓库现有文件，用于登记删除任务
    return pending, existing_names


def fix_current_repo_remote():
    token = os.environ["GITHUB_TOKEN"]
    run(
        [
            "git",
            "remote",
            "set-url",
            "origin",
            f"https://x-access-token:{token}@github.com/USNOCTURNE90/Clash.git",
        ]
    )


repo = Path("surge_repo")
if repo.exists():
    shutil.rmtree(repo)

run(
    [
        "git",
        "clone",
        f"https://x-access-token:{os.environ['GITHUB_TOKEN']}@github.com/{os.environ['TARGET_REPO']}.git",
        "surge_repo",
    ]
)
run(["git", "-C", "surge_repo", "checkout", os.environ["TARGET_BRANCH"]])

changed_local = False
changed_remote = False

source_names = set()

for p in Path(".").iterdir():
    if (
        not p.is_file()
        or p.name.startswith(".")
        or p.suffix in EXCLUDED_SUFFIXES
    ):
        continue

    source_names.add(p.name)
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
        p.write_text(local_output, encoding="utf-8")
        changed_local = True

    remote_output = (
        f"# 最后更新时间: {now_str()}\n"
        "# 从Clash自动同步\n"
        f"# 原始文件: {p.name}\n"
        + "\n".join(rules)
        + "\n"
    )

    target = repo / p.name
    old_remote = target.read_text(encoding="utf-8") if target.exists() else None

    if old_remote != remote_output:
        target.write_text(remote_output, encoding="utf-8")
        changed_remote = True

# 记录整文件删除任务（只登记，不立即删对端）
ensure_state()
pending = load_pending()

target_existing = set()
for rp in repo.iterdir():
    if (
        rp.is_file()
        and not rp.name.startswith(".")
        and rp.suffix not in EXCLUDED_SUFFIXES
    ):
        target_existing.add(rp.name)

for name in sorted(target_existing - source_names):
    already = any(
        x.get("repo") == "Clash"
        and x.get("target_repo") == "Surge"
        and x.get("filename") == name
        for x in pending
    )
    if not already:
        pending.append(
            {
                "repo": "Clash",
                "target_repo": "Surge",
                "filename": name,
                "requested_at": now_iso(),
            }
        )
        changed_local = True

save_pending(pending)

if changed_local:
    run(["git", "config", "user.name", "github-actions[bot]"])
    run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"])
    fix_current_repo_remote()
    run(["git", "add", "."])
    status = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if status.returncode != 0:
        run(["git", "commit", "-m", f"[AUTO_SYNC] 本地格式化 Clash 规则集 - {now_str()}"])
        run(["git", "push"])

if changed_remote:
    run(["git", "-C", "surge_repo", "config", "user.name", "github-actions[bot]"])
    run(["git", "-C", "surge_repo", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"])
    run(
        [
            "git",
            "-C",
            "surge_repo",
            "remote",
            "set-url",
            "origin",
            f"https://x-access-token:{os.environ['GITHUB_TOKEN']}@github.com/{os.environ['TARGET_REPO']}.git",
        ]
    )
    run(["git", "-C", "surge_repo", "add", "."])
    status = subprocess.run(["git", "-C", "surge_repo", "diff", "--cached", "--quiet"])
    if status.returncode != 0:
        run(["git", "-C", "surge_repo", "commit", "-m", f"[AUTO_SYNC] 从Clash自动同步规则集 - {now_str()}"])
        run(["git", "-C", "surge_repo", "push"])