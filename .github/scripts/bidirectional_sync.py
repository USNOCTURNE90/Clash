import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta

BJ_TZ = timezone(timedelta(hours=8))

STATE_FILE = ".sync_state.json"

SURGE_SKIP = {".git", ".github", "README.md", "LICENSE", ".DS_Store", STATE_FILE}
CLASH_SKIP = {".git", ".github", "README.md", "LICENSE", ".DS_Store", STATE_FILE}

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

def now_str():
    return datetime.now(BJ_TZ).strftime("%Y-%m-%d %H:%M:%S (北京时间)")

def run(cmd, cwd=None):
    subprocess.run(cmd, cwd=cwd, check=True)

def git_output(cmd, cwd=None):
    return subprocess.check_output(cmd, cwd=cwd, text=True).strip()

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
    if s.startswith("*."):
        s = s[2:]
    if s.endswith("."):
        s = s[:-1]
    if "." not in s:
        return False
    return re.fullmatch(r"[A-Za-z0-9.-]+", s) is not None

def normalize_rule(line: str):
    raw = line.strip()
    if not raw or raw.startswith("#") or raw.startswith("//") or raw.startswith(";"):
        return None

    if " #" in raw:
        raw = raw.split(" #", 1)[0].strip()

    if raw.startswith("- "):
        raw = raw[2:].strip()

    if raw in ("payload:", "rules:"):
        return None

    if raw.startswith(SUPPORTED_RULE_PREFIXES):
        return raw

    if is_ipv4(raw):
        return f"IP-CIDR,{raw}/32"

    if is_ipv4_cidr(raw):
        return f"IP-CIDR,{raw}"

    if is_ipv6_or_cidr(raw):
        if "/" in raw:
            return f"IP-CIDR6,{raw}"
        return f"IP-CIDR6,{raw}/128"

    if looks_like_plain_domain(raw):
        if raw.startswith("*."):
            return f"DOMAIN-WILDCARD,{raw}"
        return f"DOMAIN-SUFFIX,{raw}"

    return None

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
        return {"files": {}}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {"files": {}}

def save_state(base: Path, state: dict):
    text = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    old = None
    f = base / STATE_FILE
    if f.exists():
        old = f.read_text(encoding="utf-8")
    if old != text:
        f.write_text(text, encoding="utf-8")
        return True
    return False

def merge_states(base_state: dict, incoming: dict):
    merged = dict(base_state.get("files", {}))
    for name, rules in incoming.items():
        merged[name] = dedupe_keep_order(rules)
    return {"files": merged}

def render_surge_file(name: str, rules: list[str]) -> str:
    lines = [
        f"# 最后更新时间: {now_str()}",
        "# 双向同步生成（标准输出）",
        f"# 规则集: {name}",
        *rules,
        "",
    ]
    return "\n".join(lines)

def render_clash_file(name: str, rules: list[str]) -> str:
    lines = [
        f"# 最后更新时间: {now_str()}",
        "# 双向同步生成（标准输出）",
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
            if "# 双向同步生成（标准输出）" in text:
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
            if "# 双向同步生成（标准输出）" in text:
                p.unlink()
                changed = True

    return changed

def commit_if_needed(repo_path: Path, message: str):
    run(["git", "config", "user.name", "github-actions[bot]"], cwd=repo_path)
    run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], cwd=repo_path)
    run(["git", "add", "."], cwd=repo_path)

    status = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo_path)
    if status.returncode == 0:
        return False

    run(["git", "commit", "-m", message], cwd=repo_path)
    run(["git", "pull", "--rebase"], cwd=repo_path)
    run(["git", "push"], cwd=repo_path)
    return True

def clone_repo(url_repo: str, branch: str, folder: str, token: str):
    path = Path(folder)
    if path.exists():
        shutil.rmtree(path)
    run([
        "git",
        "clone",
        f"https://x-access-token:{token}@github.com/{url_repo}.git",
        folder,
    ])
    run(["git", "checkout", branch], cwd=path)
    return path

def main():
    current_repo = os.environ["CURRENT_REPO"]
    current_branch = os.environ["CURRENT_BRANCH"]
    target_repo = os.environ["TARGET_REPO"]
    target_branch = os.environ["TARGET_BRANCH"]
    github_token = os.environ["GITHUB_TOKEN"]
    source_type = os.environ["SOURCE_TYPE"]  # surge or clash

    remote = clone_repo(target_repo, target_branch, "peer_repo", github_token)
    local = Path(".")

    local_state = load_state(local)
    remote_state = load_state(remote)

    if source_type == "surge":
        incoming_local = parse_surge_repo(local)
        incoming_remote = parse_clash_repo(remote)
    else:
        incoming_local = parse_clash_repo(local)
        incoming_remote = parse_surge_repo(remote)

    merged = merge_states(remote_state, incoming_remote)
    merged = merge_states(merged, local_state.get("files", {}))
    merged = merge_states(merged, incoming_local)

    local_changed = False
    remote_changed = False

    if source_type == "surge":
        local_changed |= write_surge_repo(local, merged["files"])
        remote_changed |= write_clash_repo(remote, merged["files"])
    else:
        local_changed |= write_clash_repo(local, merged["files"])
        remote_changed |= write_surge_repo(remote, merged["files"])

    local_changed |= save_state(local, merged)
    remote_changed |= save_state(remote, merged)

    if local_changed:
        commit_if_needed(local, f"[AUTO_SYNC] Normalize {current_repo} {now_str()}")

    if remote_changed:
        commit_if_needed(remote, f"[AUTO_SYNC] Sync from {current_repo} {now_str()}")

if __name__ == "__main__":
    main()
