import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta

BJ_TZ = timezone(timedelta(hours=8))
STATE_FILE = ".sync_state.json"
SYNC_MARK = "# 双向同步生成（标准输出）"

SURGE_SKIP = {".git", ".github", "README.md", "LICENSE", ".DS_Store", STATE_FILE, "peer_repo"}
CLASH_SKIP = {".git", ".github", "README.md", "LICENSE", ".DS_Store", STATE_FILE, "peer_repo"}

SURGE_ALLOWED_SUFFIXES = {"", ".list", ".txt", ".rules", ".rule", ".conf"}
CLASH_ALLOWED_SUFFIXES = {".yaml", ".yml"}

SUPPORTED_RULE_PREFIXES = (
    "DOMAIN,",
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "DOMAIN-WILDCARD,",
    "IP-CIDR,",
    "IP-CIDR6,",
    "IP-ASN,",
    "PROCESS-NAME,",
    "DST-PORT,",
    "SRC-IP,",
    "SRC-IP-CIDR,",
    "SRC-PORT,",
    "URL-REGEX,",
    "USER-AGENT,",
)


def now_str() -> str:
    return datetime.now(BJ_TZ).strftime("%Y-%m-%d %H:%M:%S (北京时间)")


def run(cmd, cwd=None, check=True, capture_output=False, text=True):
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        capture_output=capture_output,
        text=text,
    )


def is_ipv4(s: str) -> bool:
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", s):
        return False
    parts = s.split(".")
    return all(0 <= int(x) <= 255 for x in parts)


def is_ipv4_cidr(s: str) -> bool:
    m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)/(\d{1,2})", s)
    if not m:
        return False
    ip, mask = m.groups()
    if not is_ipv4(ip):
        return False
    return 0 <= int(mask) <= 32


def is_ipv6_or_cidr(s: str) -> bool:
    return ":" in s


def looks_like_plain_domain(s: str) -> bool:
    s = s.strip()
    if " " in s or "," in s or "/" in s:
        return False
    if s.startswith("http://") or s.startswith("https://"):
        return False
    t = s[2:] if s.startswith("*.") else s
    if t.endswith("."):
        t = t[:-1]
    if "." not in t:
        return False
    return re.fullmatch(r"[A-Za-z0-9.-]+", t) is not None


def looks_like_bare_process_name(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    if " " in s or "," in s or "/" in s or ":" in s:
        return False
    if "." in s:
        return False
    return re.fullmatch(r"[A-Za-z0-9_+\-]+", s) is not None


def normalize_rule(line: str):
    raw = line.strip()

    if not raw:
        return None
    if raw.startswith("#") or raw.startswith("//") or raw.startswith(";"):
        return None

    if " #" in raw:
        raw = raw.split(" #", 1)[0].strip()

    if raw.startswith("- "):
        raw = raw[2:].strip()

    if raw in ("payload:", "rules:"):
        return None

    # 已知规则类型，直接保留
    if raw.startswith(SUPPORTED_RULE_PREFIXES):
        return raw

    # IP
    if is_ipv4(raw):
        return f"IP-CIDR,{raw}/32"

    if is_ipv4_cidr(raw):
        return f"IP-CIDR,{raw}"

    if is_ipv6_or_cidr(raw):
        if "/" in raw:
            return f"IP-CIDR6,{raw}"
        return f"IP-CIDR6,{raw}/128"

    # 域名
    if looks_like_plain_domain(raw):
        if raw.startswith("*."):
            return f"DOMAIN-WILDCARD,{raw}"
        return f"DOMAIN-SUFFIX,{raw}"

    # 裸进程名，例如 Alipay / WeChat / Telegram
    if looks_like_bare_process_name(raw):
        return f"PROCESS-NAME,{raw}"

    # 其他无法识别的内容，不要删，原样保留
    return raw


def dedupe_keep_order(items):
    seen = set()
    out = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def parse_surge_repo(base: Path):
    files = {}
    for p in sorted(base.iterdir(), key=lambda x: x.name.lower()):
        if p.name in SURGE_SKIP or not p.is_file():
            continue
        if p.suffix.lower() not in SURGE_ALLOWED_SUFFIXES:
            continue

        rules = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            r = normalize_rule(line)
            if r:
                rules.append(r)

        rules = dedupe_keep_order(rules)
        if rules:
            files[p.stem] = rules
    return files


def parse_clash_repo(base: Path):
    files = {}
    for p in sorted(base.iterdir(), key=lambda x: x.name.lower()):
        if p.name in CLASH_SKIP or not p.is_file():
            continue
        if p.suffix.lower() not in CLASH_ALLOWED_SUFFIXES:
            continue

        rules = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            r = normalize_rule(line)
            if r:
                rules.append(r)

        rules = dedupe_keep_order(rules)
        if rules:
            files[p.stem] = rules
    return files


def load_state(base: Path):
    f = base / STATE_FILE
    if not f.exists():
        return {"files": {}, "updated_at": None}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {"files": {}, "updated_at": None}


def save_state(base: Path, state: dict):
    text = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    f = base / STATE_FILE
    old = f.read_text(encoding="utf-8") if f.exists() else None
    if old != text:
        f.write_text(text, encoding="utf-8")
        return True
    return False


def merge_by_source_priority(source_name: str, local_files: dict, remote_files: dict, local_state: dict, remote_state: dict):
    merged = {}

    all_names = set()
    all_names.update(local_state.get("files", {}).keys())
    all_names.update(remote_state.get("files", {}).keys())
    all_names.update(local_files.keys())
    all_names.update(remote_files.keys())

    for name in sorted(all_names):
        if name in local_files:
            merged[name] = dedupe_keep_order(local_files[name])
        elif name in remote_files:
            merged[name] = dedupe_keep_order(remote_files[name])
        elif name in local_state.get("files", {}):
            merged[name] = dedupe_keep_order(local_state["files"][name])
        elif name in remote_state.get("files", {}):
            merged[name] = dedupe_keep_order(remote_state["files"][name])

    return {
        "files": merged,
        "updated_at": now_str(),
        "updated_from": source_name,
    }


def render_surge_file(name: str, rules: list[str]) -> str:
    lines = [
        SYNC_MARK,
        f"# 规则集: {name}",
        *rules,
        "",
    ]
    return "\n".join(lines)


def render_clash_file(name: str, rules: list[str]) -> str:
    lines = [
        SYNC_MARK,
        f"# 规则集: {name}",
        "payload:",
        *[f"  - {r}" for r in rules],
        "",
    ]
    return "\n".join(lines)


def write_surge_repo(base: Path, files: dict):
    changed = False
    expected = set()

    for name, rules in sorted(files.items()):
        expected.add(name)
        target = base / name
        content = render_surge_file(name, rules)
        old = target.read_text(encoding="utf-8") if target.exists() else None
        if old != content:
            target.write_text(content, encoding="utf-8")
            changed = True

    for p in base.iterdir():
        if not p.is_file():
            continue
        if p.name in SURGE_SKIP:
            continue
        if p.suffix.lower() not in SURGE_ALLOWED_SUFFIXES:
            continue
        if p.stem not in expected:
            text = p.read_text(encoding="utf-8", errors="ignore")
            if SYNC_MARK in text:
                p.unlink()
                changed = True

    return changed


def write_clash_repo(base: Path, files: dict):
    changed = False
    expected = set()

    for name, rules in sorted(files.items()):
        filename = f"{name}.yaml"
        expected.add(filename)
        target = base / filename
        content = render_clash_file(name, rules)
        old = target.read_text(encoding="utf-8") if target.exists() else None
        if old != content:
            target.write_text(content, encoding="utf-8")
            changed = True

    for p in base.iterdir():
        if not p.is_file():
            continue
        if p.name in CLASH_SKIP:
            continue
        if p.suffix.lower() not in CLASH_ALLOWED_SUFFIXES:
            continue
        if p.name not in expected:
            text = p.read_text(encoding="utf-8", errors="ignore")
            if SYNC_MARK in text:
                p.unlink()
                changed = True

    return changed


def add_local_repo_files(repo_path: Path):
    state_file = repo_path / STATE_FILE
    if state_file.exists():
        run(["git", "add", "--", STATE_FILE], cwd=repo_path)

    for p in sorted(repo_path.iterdir(), key=lambda x: x.name.lower()):
        if not p.is_file():
            continue
        if p.name in SURGE_SKIP or p.name in CLASH_SKIP:
            continue

        suffix = p.suffix.lower()
        if suffix in SURGE_ALLOWED_SUFFIXES or suffix in CLASH_ALLOWED_SUFFIXES or suffix == "":
            run(["git", "add", "--", p.name], cwd=repo_path)

    run(["git", "add", "-u"], cwd=repo_path)


def commit_if_needed(repo_path: Path, message: str):
    run(["git", "config", "user.name", "github-actions[bot]"], cwd=repo_path)
    run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], cwd=repo_path)

    stash_result = run(
        ["git", "stash", "push", "-u", "-m", "autosync-temp-stash"],
        cwd=repo_path,
        check=False,
        capture_output=True,
    )

    had_stash = "No local changes to save" not in (stash_result.stdout or "")

    run(["git", "pull", "--rebase"], cwd=repo_path)

    if had_stash:
        pop_result = run(
            ["git", "stash", "pop"],
            cwd=repo_path,
            check=False,
            capture_output=True,
        )
        if pop_result.returncode != 0:
            raise RuntimeError(
                "git stash pop failed:\n"
                + (pop_result.stdout or "")
                + "\n"
                + (pop_result.stderr or "")
            )

    if repo_path.resolve() == Path(".").resolve():
        add_local_repo_files(repo_path)
    else:
        run(["git", "add", "-A"], cwd=repo_path)

    status = run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=repo_path,
        check=False,
        capture_output=True,
    )
    if status.returncode == 0:
        return False

    run(["git", "commit", "-m", message], cwd=repo_path)
    run(["git", "push"], cwd=repo_path)
    return True


def clone_repo(repo_full_name: str, branch: str, folder: str, token: str):
    path = Path(folder)
    if path.exists():
        shutil.rmtree(path)

    run([
        "git",
        "clone",
        f"https://x-access-token:{token}@github.com/{repo_full_name}.git",
        folder,
    ])
    run(["git", "checkout", branch], cwd=path)
    return path


def main():
    current_repo = os.environ["CURRENT_REPO"]
    target_repo = os.environ["TARGET_REPO"]
    target_branch = os.environ["TARGET_BRANCH"]
    source_type = os.environ["SOURCE_TYPE"]
    github_token = os.environ["GITHUB_TOKEN"]

    local = Path(".")
    remote = clone_repo(target_repo, target_branch, "peer_repo", github_token)

    local_state = load_state(local)
    remote_state = load_state(remote)

    if source_type == "surge":
        local_files = parse_surge_repo(local)
        remote_files = parse_clash_repo(remote)
    else:
        local_files = parse_clash_repo(local)
        remote_files = parse_surge_repo(remote)

    merged_state = merge_by_source_priority(
        source_name=current_repo,
        local_files=local_files,
        remote_files=remote_files,
        local_state=local_state,
        remote_state=remote_state,
    )

    local_changed = False
    remote_changed = False

    if source_type == "surge":
        local_changed |= write_surge_repo(local, merged_state["files"])
        remote_changed |= write_clash_repo(remote, merged_state["files"])
    else:
        local_changed |= write_clash_repo(local, merged_state["files"])
        remote_changed |= write_surge_repo(remote, merged_state["files"])

    local_changed |= save_state(local, merged_state)
    remote_changed |= save_state(remote, merged_state)

    if local_changed:
        commit_if_needed(local, f"[AUTO_SYNC] Normalize {current_repo} {now_str()}")

    if remote_changed:
        commit_if_needed(remote, f"[AUTO_SYNC] Sync from {current_repo} {now_str()}")


if __name__ == "__main__":
    main()
