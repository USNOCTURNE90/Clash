#!/usr/bin/env python3

import ipaddress
import os
import shutil
import subprocess
import tempfile
import traceback
from datetime import datetime, timedelta
from pathlib import Path

KNOWN_PREFIXES = (
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "DOMAIN,",
    "IP-CIDR,",
    "IP-ASN,",
    "PROCESS-NAME,",
)
TIMESTAMP_PREFIX = "# 最后更新时间:"


def get_china_time():
    utc_now = datetime.utcnow()
    china_time = utc_now + timedelta(hours=8)
    return china_time.strftime("%Y-%m-%d %H:%M:%S")


def normalize_rule_line(line, is_surge):
    line = line.strip()
    if not line or line.startswith("#"):
        return line

    if line.startswith("  - "):
        line = line[4:]
    elif line.startswith("- "):
        line = line[2:]

    if any(line.startswith(prefix) for prefix in KNOWN_PREFIXES):
        return line if is_surge else f"- {line}"

    try:
        network = ipaddress.ip_network(line, strict=False)
        if isinstance(network, ipaddress.IPv4Network):
            normalized = f"IP-CIDR,{network.with_prefixlen}"
            return normalized if is_surge else f"- {normalized}"
        return line if is_surge else f"- {line}"
    except ValueError:
        pass

    try:
        address = ipaddress.ip_address(line)
        if isinstance(address, ipaddress.IPv4Address):
            normalized = f"IP-CIDR,{address}/32"
            return normalized if is_surge else f"- {normalized}"
        return line if is_surge else f"- {line}"
    except ValueError:
        pass

    if "." in line and "," not in line and " " not in line:
        normalized = f"DOMAIN-SUFFIX,{line}"
        return normalized if is_surge else f"- {normalized}"

    if "." not in line and "," not in line and " " not in line:
        normalized = f"PROCESS-NAME,{line}"
        return normalized if is_surge else f"- {normalized}"

    return line if is_surge else f"- {line}"


def should_exclude(path):
    if path.is_dir() or path.name.startswith("."):
        return True

    excluded_names = {".gitignore", "LICENSE", "sync_to_surge.py"}
    excluded_suffixes = {".yml", ".yaml", ".py", ".md"}
    if path.name in excluded_names:
        return True
    if path.name.startswith("README"):
        return True
    if path.suffix in excluded_suffixes:
        return True
    return False


def strip_timestamp(lines):
    return [line for line in lines if not line.startswith(TIMESTAMP_PREFIX)]


def is_top_level_key(line):
    stripped = line.strip()
    return bool(stripped) and not line.startswith((" ", "\t", "#", "-")) and stripped.endswith(":")


def normalize_clash_yaml(content):
    current_time = get_china_time()
    content_lines = content.splitlines()
    updated_lines = []
    rules_section = False

    for line in content_lines:
        stripped = line.strip()
        if line.startswith(TIMESTAMP_PREFIX):
            continue

        if stripped in ("payload:", "rules:"):
            rules_section = True
            updated_lines.append(line)
            continue

        if rules_section and is_top_level_key(line):
            rules_section = False

        if rules_section and stripped and not stripped.startswith("#"):
            if stripped.startswith(("  - ", "- ")):
                rule_part = stripped[4:] if stripped.startswith("  - ") else stripped[2:]
            else:
                rule_part = stripped

            if any(rule_part.startswith(prefix) for prefix in KNOWN_PREFIXES):
                updated_lines.append(f"  - {rule_part}")
            else:
                updated_lines.append(f"  {normalize_rule_line(rule_part, is_surge=False)}")
            continue

        updated_lines.append(line)

    updated_lines = [f"# 最后更新时间: {current_time} (北京时间)", *updated_lines]
    if strip_timestamp(updated_lines) == strip_timestamp(content_lines):
        return None
    return updated_lines


def normalize_plain_rules(content):
    current_time = get_china_time()
    content_lines = content.splitlines()
    updated_lines = []

    for line in content_lines:
        if line.startswith(TIMESTAMP_PREFIX):
            continue
        if line.strip() and not line.startswith("#"):
            updated_lines.append(normalize_rule_line(line, is_surge=True))
        else:
            updated_lines.append(line)

    updated_lines = [f"# 最后更新时间: {current_time} (北京时间)", *updated_lines]
    if strip_timestamp(updated_lines) == strip_timestamp(content_lines):
        return None
    return updated_lines


def convert_to_surge_content(file_name, content):
    is_clash_format = "payload:" in content or "rules:" in content
    surge_rules = []
    comment_lines = []
    rules_section = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("payload:", "rules:"):
            rules_section = True
            continue

        if rules_section and is_top_level_key(line):
            rules_section = False

        if line.startswith("#"):
            if not line.startswith(TIMESTAMP_PREFIX):
                comment_lines.append(line)
            continue

        if rules_section and stripped:
            candidate = stripped[4:] if stripped.startswith("  - ") else stripped[2:] if stripped.startswith("- ") else stripped
            surge_rules.append(normalize_rule_line(candidate, is_surge=True))
            continue

        if not is_clash_format and stripped:
            surge_rules.append(normalize_rule_line(stripped, is_surge=True))

    current_time = get_china_time()
    output_lines = [
        f"# 最后更新时间: {current_time} (北京时间)",
        "# 从Clash自动同步" if is_clash_format else "# 规则自动格式化",
        f"# 原始文件: {file_name}",
    ]

    for comment in comment_lines:
        if comment not in output_lines and "自动同步" not in comment and "规则自动格式化" not in comment and "原始文件" not in comment:
            output_lines.append(comment)

    output_lines.extend(surge_rules)
    return "\n".join(output_lines)


print(f"Current directory: {os.getcwd()}")
print(f"Directory contents: {os.listdir('.')}")

surge_root = None

try:
    root_dir = Path(".")
    rule_files = []

    for file_path in root_dir.glob("*"):
        if should_exclude(file_path):
            print(f"Skipping excluded file: {file_path}")
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
            if any(marker in content for marker in ("payload:", "rules:", "DOMAIN", "IP-CIDR", ".")):
                rule_files.append(file_path)
                print(f"Found rule file: {file_path.name}")
        except Exception as exc:
            print(f"Error reading {file_path.name}: {exc}")

    if not rule_files:
        print("No rule files found!")
        print(f"All files: {[f.name for f in root_dir.glob('*') if not should_exclude(f)]}")
        raise SystemExit(1)

    local_changed_files = []
    for clash_file in rule_files:
        content = clash_file.read_text(encoding="utf-8")
        if "payload:" in content or "rules:" in content:
            updated_lines = normalize_clash_yaml(content)
        else:
            updated_lines = normalize_plain_rules(content)

        if updated_lines is None:
            continue

        clash_file.write_text("\n".join(updated_lines), encoding="utf-8")
        local_changed_files.append(clash_file.name)
        print(f"Updated local file: {clash_file.name}")

    if local_changed_files:
        subprocess.run(["git", "add", "--", *local_changed_files], check=True)
        local_result = subprocess.run(
            ["git", "status", "--porcelain", "--", *local_changed_files],
            capture_output=True,
            text=True,
            check=True,
        )

        if local_result.stdout.strip():
            print("Changes found in local repo, committing...")
            local_commit_message = f"[AUTO_FORMAT] 自动格式化规则集 - {get_china_time()} (北京时间)"
            subprocess.run(["git", "commit", "-m", local_commit_message], check=True)
            print("Pushing changes to local repo...")
            subprocess.run(["git", "push"], check=True)
            print("Successfully updated local repo")
    else:
        print("No substantive local rule changes detected")

    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not github_token:
        raise RuntimeError("GITHUB_TOKEN is required for syncing to Surge")

    surge_root = Path(tempfile.mkdtemp(prefix="surge-sync-"))
    surge_repo_url = f"https://x-access-token:{github_token}@github.com/USNOCTURNE90/Surge.git"
    subprocess.run(["git", "clone", surge_repo_url, str(surge_root)], check=True)

    surge_changed_files = []
    for clash_file in rule_files:
        content = clash_file.read_text(encoding="utf-8")
        surge_file = surge_root / clash_file.name
        updated_content = convert_to_surge_content(clash_file.name, content)
        existing_content = surge_file.read_text(encoding="utf-8") if surge_file.exists() else ""

        if strip_timestamp(updated_content.splitlines()) == strip_timestamp(existing_content.splitlines()):
            continue

        surge_file.write_text(updated_content, encoding="utf-8")
        surge_changed_files.append(clash_file.name)
        print(f"Synced rule file to Surge: {clash_file.name}")

    if not surge_changed_files:
        print("No substantive changes to commit in Surge repo")
        raise SystemExit(0)

    subprocess.run(["git", "-C", str(surge_root), "add", "--", *surge_changed_files], check=True)
    result = subprocess.run(
        ["git", "-C", str(surge_root), "status", "--porcelain", "--", *surge_changed_files],
        capture_output=True,
        text=True,
        check=True,
    )

    if not result.stdout.strip():
        print("No changes to commit in Surge repo")
        raise SystemExit(0)

    print("Changes found in Surge repo, committing...")
    commit_message = f"[AUTO_SYNC] 从Clash自动同步规则集 - {get_china_time()} (北京时间)"
    subprocess.run(["git", "-C", str(surge_root), "commit", "-m", commit_message], check=True)

    print("Pushing changes to Surge repo...")
    subprocess.run(["git", "-C", str(surge_root), "push"], check=True)
    print("Successfully synced rules to Surge repo")

except Exception as exc:
    print(f"Error: {exc}")
    traceback.print_exc()
    raise SystemExit(1)

finally:
    if surge_root and surge_root.exists():
        shutil.rmtree(surge_root, ignore_errors=True)
